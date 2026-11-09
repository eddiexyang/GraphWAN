package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

const (
	// Ended sessions are remembered so a late chain cannot start one again.
	sessionTombstone = 10 * time.Minute
	// replayPort carries the egress's replay requests between the Agents'
	// overlay addresses; the ingress takes them before its TUN.
	replayPort        = 0x4757
	replayRequestSize = 16 + 4 // session ID, failed generation
)

type sessionKey struct {
	network, source model.ID
	conn            streamproxy.SessionID
}

// sessions tracks this Agent's part of resumable TCP sessions. Only the ends
// hold a session; a relay only remembers its chain's request, to check its
// next hop against the routes.
type sessions struct {
	mu       sync.Mutex
	ingress  map[sessionKey]*ingressSession
	relays   map[*relayChain]struct{}
	egress   map[sessionKey]*egressSession
	ended    map[sessionKey]time.Time
	purged   time.Time
	wake     chan struct{}
	counters streamproxy.Counters
	resets   uint64 // relay chains reset for a route change, under mu
	exits    uint64 // connections reset because their gateway changed, under mu
}

type ingressSession struct {
	request streamproxy.Request
	end     *streamproxy.End
	next    model.ID // the current chain's first hop, under sessions.mu
}

type relayChain struct {
	request  streamproxy.Request
	upstream model.ID
	next     model.ID
	up, down streamproxy.Hop
}

type egressSession struct {
	ready chan struct{}
	end   *streamproxy.End // nil when the server could not be reached
}

func (s *sessions) init() {
	s.ingress = map[sessionKey]*ingressSession{}
	s.relays = map[*relayChain]struct{}{}
	s.egress = map[sessionKey]*egressSession{}
	s.ended = map[sessionKey]time.Time{}
	s.wake = make(chan struct{}, 1)
}

// routesChanged schedules a check of every chain against the routes.
func (r *DataPlane) routesChanged() {
	select {
	case r.sessions.wake <- struct{}{}:
	default:
	}
}

// rerouteLoop checks chains on each route change and every second, which
// also catches an Edge that lost its streams.
func (r *DataPlane) rerouteLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.sessions.wake:
		case <-ticker.C:
		}
		r.rerouteSessions()
	}
}

// rerouteSessions moves every chain whose next hop changed: the ingress
// rebuilds its own, a relay resets its part so the ingress rebuilds. A
// connection whose destination now leaves the network at another Node is
// reset.
func (r *DataPlane) rerouteSessions() {
	state := r.state.Load()
	if state == nil {
		return
	}
	r.sessions.mu.Lock()
	var moved, ended []*ingressSession
	for key, s := range r.sessions.ingress {
		// A connection's state is at its egress. When traffic to its
		// destination leaves at another Node now, the connection ends there
		// with a reset; it never continues on another egress.
		if exit, err := state.router.TCPExit(s.request.Network, s.request.From, s.request.To); err == nil && exit != s.request.Destination {
			ended = append(ended, s)
			delete(r.sessions.ingress, key)
			r.sessions.exits++
			continue
		}
		next, local, err := state.router.TCPRoute(s.request, "")
		if err != nil || local || next != s.next || !state.mesh.ResumeAvailable(s.request.Network, next) {
			moved = append(moved, s)
		}
	}
	var reset []*relayChain
	for c := range r.sessions.relays {
		next, local, err := state.router.TCPRoute(c.request, c.upstream)
		if err != nil || local || next != c.next || !state.mesh.ResumeAvailable(c.request.Network, next) {
			reset = append(reset, c)
			delete(r.sessions.relays, c)
			r.sessions.resets++
		}
	}
	r.sessions.mu.Unlock()
	for _, s := range ended {
		s.end.Abort()
	}
	for _, s := range moved {
		s.end.Reroute()
	}
	for _, c := range reset {
		c.up.Abort()
		c.down.Abort()
	}
}

// startSession opens an access connection as a session when its first hop
// carries sessions. It returns nil for a plain stream or packets.
func (r *DataPlane) startSession(ctx context.Context, request streamproxy.Request) (streamproxy.Conn, error) {
	state := r.state.Load()
	if state == nil {
		return nil, net.ErrClosed
	}
	next, local, err := state.router.TCPRoute(request, "")
	if err != nil || local || !state.mesh.ResumeAvailable(request.Network, next) {
		return nil, nil
	}
	// An egress that lost its end-to-end sessions, as by a restart, refuses
	// the first chain; the connection waits for a new session once.
	var entry *ingressSession
	var key sessionKey
	var end *streamproxy.End
	for attempt := 0; ; attempt++ {
		entry, key, end, err = r.startIngress(ctx, request)
		if !errors.Is(err, streamproxy.ErrNoKey) || attempt > 0 {
			break
		}
	}
	if errors.Is(err, streamproxy.ErrLegacy) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry.end = end
	r.sessions.mu.Lock()
	r.sessions.ingress[key] = entry
	r.sessions.mu.Unlock()
	go func() {
		<-end.Done()
		r.sessions.mu.Lock()
		delete(r.sessions.ingress, key)
		r.sessions.mu.Unlock()
	}()
	return end, nil
}

// startIngress opens a session's first chain, sealed end to end when the
// egress has an Agent key.
func (r *DataPlane) startIngress(ctx context.Context, request streamproxy.Request) (*ingressSession, sessionKey, *streamproxy.End, error) {
	sealed, channel, ok, err := r.e2eChannel(ctx, request.Network, request.Destination)
	if err != nil {
		return nil, sessionKey{}, nil, fmt.Errorf("%w: end-to-end session: %w", streamproxy.ErrNoRoute, err)
	}
	var records *streamproxy.Records
	if ok {
		request.E2E, request.Channel = sealed.id, channel
		if state := r.state.Load(); state != nil {
			request.Sealer = state.selfID(request.Network)
		}
		records = streamproxy.NewRecords(sealed.session, channel)
	}
	request.Conn = streamproxy.NewSessionID()
	key := sessionKey{request.Network, request.Source, request.Conn}
	entry := &ingressSession{request: request}
	end, err := streamproxy.StartIngress(ctx, func(ctx context.Context, gen uint32, down, up uint64) (streamproxy.Hop, uint64, error) {
		chain := request
		chain.Gen, chain.Down, chain.Up, chain.At = gen, down, up, gen > 0
		// The attempt's first hop is the session's: a route away from it
		// reroutes the session, which cancels the attempt.
		if state := r.state.Load(); state != nil {
			if next, _, err := state.router.TCPRoute(chain, ""); err == nil {
				r.sessions.mu.Lock()
				entry.next = next
				r.sessions.mu.Unlock()
			}
		}
		hop, next, at, err := r.openChain(ctx, chain, "")
		if err == nil {
			r.sessions.mu.Lock()
			entry.next = next
			r.sessions.mu.Unlock()
		}
		return hop, at, err
	}, &r.sessions.counters, records)
	if errors.Is(err, streamproxy.ErrNoKey) && ok {
		r.dropE2E(request.Network, request.Destination, sealed)
	}
	return entry, key, end, err
}

// openChain opens the next hop of a chain along the current routes and waits
// for the chain to reach the egress. Toward an Agent without sessions, or an
// Edge whose Link carries only packets, it fails with ErrLegacy: with no TCP
// over TCP, the chain cannot continue. An Edge without a Link yet is retried.
// openChain opens the next hop of a chain and returns it with the offset from
// which it carries the downstream bytes: the egress's answer to At, or Down.
func (r *DataPlane) openChain(ctx context.Context, request streamproxy.Request, upstream model.ID) (streamproxy.Hop, model.ID, uint64, error) {
	state := r.state.Load()
	if state == nil {
		return nil, "", 0, net.ErrClosed
	}
	next, local, err := state.router.TCPRoute(request, upstream)
	if err != nil {
		return nil, "", 0, err
	}
	if local {
		return nil, "", 0, errors.New("TCP session egress is this Agent")
	}
	waitStreams(ctx, state, request.Network, next)
	if !state.mesh.ResumeAvailable(request.Network, next) {
		if state.mesh.StreamsAvailable(request.Network, next) || state.mesh.PacketsOnly(request.Network, next) {
			return nil, "", 0, streamproxy.ErrLegacy
		}
		return nil, "", 0, errNoCarriage
	}
	s, err := state.mesh.OpenStream(ctx, request.Network, next)
	if err != nil {
		return nil, "", 0, err
	}
	hop, ok := s.(streamproxy.Hop)
	if !ok {
		s.Close()
		return nil, "", 0, streamproxy.ErrLegacy
	}
	request.Hops--
	from := request.Down
	err = streamproxy.During(ctx, hop, func() error {
		if err := streamproxy.WriteRequest(hop, request); err != nil {
			return err
		}
		var response [9]byte
		if _, err := io.ReadFull(hop, response[:1]); err != nil {
			return err
		}
		if response[0] == streamproxy.StatusOKAt && request.At {
			if _, err := io.ReadFull(hop, response[1:]); err != nil {
				return err
			}
			from = binary.BigEndian.Uint64(response[1:])
			if from < request.Down {
				return errors.New("egress resumes before its delivered offset")
			}
			return nil
		}
		return streamproxy.ResponseError(response[0])
	})
	if err != nil {
		hop.Abort()
		return nil, "", 0, err
	}
	return hop, next, from, nil
}

// chainAnswer is a chain's success response: with the egress's offset when
// the request asked for it.
func chainAnswer(request streamproxy.Request, from uint64) []byte {
	if !request.At {
		return []byte{streamproxy.StatusOK}
	}
	answer := make([]byte, 9)
	answer[0] = streamproxy.StatusOKAt
	binary.BigEndian.PutUint64(answer[1:], from)
	return answer
}

var errNoCarriage = errors.New("the TCP session's next Edge has no Link")

// noRoute reports a path that is missing for now: no route, or no Link on
// the next Edge.
func noRoute(err error) bool {
	return errors.Is(err, streamproxy.ErrNoRoute) || errors.Is(err, forwarding.ErrUnreachable) || errors.Is(err, errNoCarriage)
}

func chainStatus(err error) byte {
	switch {
	case noRoute(err):
		return streamproxy.StatusNoRoute
	case errors.Is(err, streamproxy.ErrLegacy):
		return streamproxy.StatusLegacy
	case errors.Is(err, streamproxy.ErrUnknownSession):
		return streamproxy.StatusUnknown
	case errors.Is(err, streamproxy.ErrNoKey):
		return streamproxy.StatusNoKey
	default:
		return streamproxy.StatusRefused
	}
}

// refuse answers a chain's request with a failure status. The stream closes
// with a reset once this returns, which would discard the unsent status, so
// it ends its write half and waits for the opener to close the stream.
func refuse(ctx context.Context, s streamproxy.Conn, status byte) {
	streamproxy.During(ctx, s, func() error {
		if _, err := s.Write([]byte{status}); err != nil {
			return err
		}
		if err := s.CloseWrite(); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, s)
		return err
	})
}

// acceptChain serves a chain from remote: it relays it toward the egress, or
// is the egress. It returns when the chain ends.
func (r *DataPlane) acceptChain(parent, ctx context.Context, network, remote model.ID, s streamproxy.Conn, request streamproxy.Request) {
	hop, ok := s.(streamproxy.Hop)
	state := r.state.Load()
	if !ok || state == nil {
		refuse(ctx, s, streamproxy.StatusRefused)
		return
	}
	_, local, err := state.router.TCPRoute(request, remote)
	if err != nil {
		refuse(ctx, s, chainStatus(err))
		return
	}
	if local {
		r.acceptEgress(parent, ctx, network, remote, hop, request)
		return
	}
	down, next, from, err := r.openChain(ctx, request, remote)
	if err != nil {
		refuse(ctx, s, chainStatus(err))
		return
	}
	if err := streamproxy.During(ctx, hop, func() error {
		_, err := hop.Write(chainAnswer(request, from))
		return err
	}); err != nil {
		down.Abort()
		return
	}
	hop.Begin(request.Up)
	down.Begin(from)
	if request.E2E != (e2eID{}) {
		// The ends seal the session: this relay copies records.
		streamproxy.CarrySealed(hop)
		streamproxy.CarrySealed(down)
	}
	c := &relayChain{request: request, upstream: remote, next: next, up: hop, down: down}
	r.sessions.mu.Lock()
	r.sessions.relays[c] = struct{}{}
	r.sessions.mu.Unlock()
	streamproxy.RelayHops(parent, hop, down)
	r.sessions.mu.Lock()
	delete(r.sessions.relays, c)
	r.sessions.mu.Unlock()
}

func (r *DataPlane) acceptEgress(parent, ctx context.Context, network, remote model.ID, hop streamproxy.Hop, request streamproxy.Request) {
	key := sessionKey{network, request.Source, request.Conn}
	r.sessions.mu.Lock()
	now := time.Now()
	if now.Sub(r.sessions.purged) > sessionTombstone {
		r.sessions.purged = now
		for k, at := range r.sessions.ended {
			if now.Sub(at) > sessionTombstone {
				delete(r.sessions.ended, k)
			}
		}
	}
	entry := r.sessions.egress[key]
	_, ended := r.sessions.ended[key]
	create := entry == nil && !ended && request.Gen == 0 && request.Down == 0 && request.Up == 0
	if create {
		entry = &egressSession{ready: make(chan struct{})}
		r.sessions.egress[key] = entry
	}
	r.sessions.mu.Unlock()
	if entry == nil {
		refuse(ctx, hop, streamproxy.StatusUnknown)
		return
	}
	if !create {
		select {
		case <-entry.ready:
		case <-ctx.Done():
			return
		}
		if entry.end == nil || entry.end.Gen() >= request.Gen {
			refuse(ctx, hop, streamproxy.StatusUnknown)
			return
		}
		answer := func(from uint64) error {
			_, err := hop.Write(chainAnswer(request, from))
			return err
		}
		if err := entry.end.Accept(hop, request.Gen, request.Down, request.Up, request.At, answer); err != nil {
			hop.Abort()
			return
		}
		<-entry.end.Done()
		return
	}
	defer r.endEgress(key, entry)
	records, ok := r.egressRecords(network, request)
	if !ok {
		close(entry.ready)
		refuse(ctx, hop, streamproxy.StatusNoKey)
		return
	}
	plain := request
	plain.Conn, plain.Gen, plain.Down, plain.Up = streamproxy.SessionID{}, 0, 0, 0
	plain.Sealer, plain.E2E, plain.Channel = "", streamproxy.E2EID{}, 0
	conn, err := r.openTCP(ctx, plain, remote)
	if err != nil {
		close(entry.ready)
		refuse(ctx, hop, streamproxy.StatusRefused)
		return
	}
	if _, err := hop.Write([]byte{streamproxy.StatusOK}); err != nil {
		close(entry.ready)
		conn.Close()
		return
	}
	entry.end = streamproxy.NewEgress(r.ctx, hop, func(gen uint32) { r.askReplay(key, gen) }, &r.sessions.counters, records)
	close(entry.ready)
	streamproxy.Relay(parent, entry.end, conn)
	<-entry.end.Done()
}

// egressRecords returns what opens a new session's records: the ingress's
// end-to-end session it names. A session to this Node must name one, so no
// relay can have the egress send its bytes unsealed; one to a WireGuard leaf
// this Agent attaches, which has no Agent key, is sealed per hop only. The
// sealer is the Source, or for a WireGuard leaf the Agent it attaches, which
// the session authenticates but this Agent cannot tell from another: the
// leaf's address is as much the hops' word as it is without sealing.
func (r *DataPlane) egressRecords(network model.ID, request streamproxy.Request) (*streamproxy.Records, bool) {
	state := r.state.Load()
	if state == nil {
		return nil, false
	}
	if request.Destination != state.selfID(network) {
		return nil, request.E2E == (e2eID{})
	}
	if request.E2E == (e2eID{}) {
		return nil, false
	}
	if _, keyed := e2eKeys(state)[e2ePeer{network, request.Source}]; keyed && request.Sealer != request.Source {
		return nil, false
	}
	s := r.e2eAccepted(network, request.Sealer, request.E2E)
	if s == nil {
		return nil, false
	}
	return streamproxy.NewRecords(s.session, request.Channel), true
}

func (r *DataPlane) endEgress(key sessionKey, entry *egressSession) {
	r.sessions.mu.Lock()
	defer r.sessions.mu.Unlock()
	if r.sessions.egress[key] == entry {
		delete(r.sessions.egress, key)
	}
	r.sessions.ended[key] = time.Now()
}

// selfID returns this Agent's Node in a network.
func (s *runtimeState) selfID(network model.ID) model.ID {
	for _, n := range s.snapshot.Networks {
		if n.ID == network {
			return n.Self.ID
		}
	}
	return ""
}

// overlayAddress returns a node's address in a network.
func (s *runtimeState) overlayAddress(network, node model.ID) (netip.Addr, bool) {
	for _, n := range s.snapshot.Networks {
		if n.ID != network {
			continue
		}
		if n.Self.ID == node {
			return n.Self.Address, true
		}
		for _, d := range n.Directory {
			if d.NodeID == node {
				return d.Address, true
			}
		}
	}
	return netip.Addr{}, false
}

// askReplay sends the egress's replay request to the ingress along the
// current routes.
func (r *DataPlane) askReplay(key sessionKey, gen uint32) {
	state := r.state.Load()
	if state == nil {
		return
	}
	var self model.ID
	for _, n := range state.snapshot.Networks {
		if n.ID == key.network {
			self = n.Self.ID
		}
	}
	from, ok := state.overlayAddress(key.network, self)
	to, found := state.overlayAddress(key.network, key.source)
	if !ok || !found {
		return
	}
	payload := make([]byte, replayRequestSize)
	copy(payload, key.conn[:])
	binary.BigEndian.PutUint32(payload[16:], gen)
	if raw := packet.UDP(netip.AddrPortFrom(from, replayPort), netip.AddrPortFrom(to, replayPort), payload); raw != nil {
		state.router.FromTunnel(r.ctx, key.network, raw)
	}
}

// replayRequest takes a replay request for one of this Agent's own sessions.
// It reports whether the packet was one.
func (r *DataPlane) replayRequest(state *runtimeState, network model.ID, raw []byte) bool {
	source, destination, payload, ok := packet.UDPDatagram(raw)
	if !ok || destination.Port() != replayPort || source.Port() != replayPort {
		return false
	}
	self := state.selfAddress[network]
	if destination.Addr() != self {
		return false
	}
	if len(payload) == replayRequestSize {
		var conn streamproxy.SessionID
		copy(conn[:], payload)
		var source model.ID
		for _, n := range state.snapshot.Networks {
			if n.ID == network {
				source = n.Self.ID
			}
		}
		r.sessions.mu.Lock()
		entry := r.sessions.ingress[sessionKey{network, source, conn}]
		r.sessions.mu.Unlock()
		if entry != nil && entry.end != nil {
			entry.end.RequestReplay(binary.BigEndian.Uint32(payload[16:]))
		}
	}
	return true
}

// sessionCounters reports session event totals.
func (r *DataPlane) sessionCounters() map[string]uint64 {
	r.sessions.mu.Lock()
	resets, exits := r.sessions.resets, r.sessions.exits
	r.sessions.mu.Unlock()
	c := &r.sessions.counters
	return map[string]uint64{
		"session_hop_failures":    c.HopFailures.Load(),
		"session_rebuilds":        c.Rebuilds.Load(),
		"session_replay_requests": c.ReplayRequests.Load(),
		"session_route_resets":    resets,
		"session_exit_resets":     exits,
		"session_retained_bytes":  c.Retained(),
	}
}
