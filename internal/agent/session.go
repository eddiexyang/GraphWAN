package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/mesh"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

// Ended sessions are remembered so a late chain cannot start one again.
const sessionTombstone = 10 * time.Minute

type sessionKey struct {
	network, source model.ID
	conn            streamproxy.SessionID
}

// sessions tracks the resumable TCP on this Agent: connections it accepted as
// ingress, chains it relays and connections it serves as egress. A route
// change moves an ingress connection, and makes each relay whose next hop
// changed tell its ingress.
type sessions struct {
	mu      sync.Mutex
	ingress map[*ingressSession]struct{}
	relays  map[*relaySession]struct{}
	egress  map[sessionKey]*egressSession
	ended   map[sessionKey]time.Time
	purged  time.Time
	wake    chan struct{}
}

type ingressSession struct {
	request streamproxy.Request
	session *streamproxy.Ingress
}

type relaySession struct {
	request  streamproxy.Request
	ingress  model.ID // the hop toward the ingress
	next     model.ID
	down     streamproxy.Conn
	notified bool
	relay    *streamproxy.SessionRelay
}

type egressSession struct {
	ready   chan struct{}
	session *streamproxy.Egress // nil when the server could not be reached
}

func (s *sessions) init() {
	s.ingress = map[*ingressSession]struct{}{}
	s.relays = map[*relaySession]struct{}{}
	s.egress = map[sessionKey]*egressSession{}
	s.ended = map[sessionKey]time.Time{}
	s.wake = make(chan struct{}, 1)
}

// routesChanged schedules a check of every session against the routes.
func (r *DataPlane) routesChanged() {
	select {
	case r.sessions.wake <- struct{}{}:
	default:
	}
}

// rerouteLoop checks sessions on each route change and every second, which
// also catches an Edge that lost the kind of hop a chain uses.
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

// hopUsable reports whether a chain's hop to next still has its carriage: a
// stream needs the Edge's streams, a carrier its selected Link.
func hopUsable(state *runtimeState, network, next model.ID, hop streamproxy.Conn) bool {
	if mesh.IsCarrier(hop) {
		return state.mesh.CarrierAvailable(network, next)
	}
	return state.mesh.ResumeAvailable(network, next)
}

// hopAvailable reports whether a session can take a hop to next at all.
func hopAvailable(state *runtimeState, network, next model.ID) bool {
	return state.mesh.ResumeAvailable(network, next) || state.mesh.CarrierAvailable(network, next)
}

func (r *DataPlane) rerouteSessions() {
	state := r.state.Load()
	if state == nil {
		return
	}
	r.sessions.mu.Lock()
	ingress := make([]*ingressSession, 0, len(r.sessions.ingress))
	for s := range r.sessions.ingress {
		ingress = append(ingress, s)
	}
	relays := make([]*relaySession, 0, len(r.sessions.relays))
	for s := range r.sessions.relays {
		relays = append(relays, s)
	}
	r.sessions.mu.Unlock()
	for _, s := range ingress {
		current, hop, ok := s.session.Next()
		if !ok {
			continue // already moving
		}
		next, local, err := state.router.TCPRoute(s.request, "")
		if err != nil || local || next != current || !hopUsable(state, s.request.Network, next, hop) {
			s.session.Reroute()
		}
	}
	for _, s := range relays {
		next, local, err := state.router.TCPRoute(s.request, s.ingress)
		moved := err != nil || local || next != s.next || !hopUsable(state, s.request.Network, next, s.down)
		r.sessions.mu.Lock()
		notify := moved && !s.notified
		s.notified = s.notified || moved
		r.sessions.mu.Unlock()
		if notify {
			s.relay.Notify()
		}
	}
}

// startSession opens an access connection as a session when its first hop
// supports them. It returns nil when the connection is to use a plain stream.
func (r *DataPlane) startSession(ctx context.Context, request streamproxy.Request) (streamproxy.Remote, error) {
	state := r.state.Load()
	if state == nil {
		return nil, net.ErrClosed
	}
	next, local, err := state.router.TCPRoute(request, "")
	if err != nil || local || !hopAvailable(state, request.Network, next) {
		return nil, nil
	}
	request.Conn = streamproxy.NewSessionID()
	session, err := streamproxy.StartIngress(ctx, func(ctx context.Context, epoch uint32, up, down uint64) (streamproxy.Conn, model.ID, error) {
		chain := request
		chain.Epoch, chain.Up, chain.Down = epoch, up, down
		return r.openChain(ctx, chain, "")
	})
	if errors.Is(err, streamproxy.ErrLegacy) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry := &ingressSession{request: request, session: session}
	r.sessions.mu.Lock()
	r.sessions.ingress[entry] = struct{}{}
	r.sessions.mu.Unlock()
	release := sync.OnceFunc(func() {
		r.sessions.mu.Lock()
		delete(r.sessions.ingress, entry)
		r.sessions.mu.Unlock()
	})
	return &ingressRemote{Ingress: session, release: release}, nil
}

type ingressRemote struct {
	*streamproxy.Ingress
	release func()
}

func (s *ingressRemote) Serve(ctx context.Context, local streamproxy.Conn) error {
	defer s.release()
	return s.Ingress.Serve(ctx, local)
}

func (s *ingressRemote) Close() error {
	s.release()
	return s.Ingress.Close()
}

// openChain opens the next hop of a session's chain and waits for the chain to
// reach the egress.
func (r *DataPlane) openChain(ctx context.Context, request streamproxy.Request, ingress model.ID) (streamproxy.Conn, model.ID, error) {
	state := r.state.Load()
	if state == nil {
		return nil, "", net.ErrClosed
	}
	next, local, err := state.router.TCPRoute(request, ingress)
	if err != nil {
		return nil, "", err
	}
	if local {
		return nil, "", errors.New("TCP session egress is this Agent")
	}
	// A hop takes the Edge's streams when they carry sessions, else its
	// carrier; an Edge to an Agent with neither does not carry sessions.
	var s streamproxy.Conn
	switch {
	case state.mesh.ResumeAvailable(request.Network, next):
		s, err = state.mesh.OpenStream(ctx, request.Network, next)
	case state.mesh.CarrierAvailable(request.Network, next):
		s, err = state.mesh.OpenCarrier(ctx, request.Network, next)
	default:
		return nil, "", streamproxy.ErrLegacy
	}
	if err != nil {
		return nil, "", err
	}
	request.Hops--
	err = streamproxy.During(ctx, s, func() error {
		if err := streamproxy.WriteRequest(s, request); err != nil {
			return err
		}
		var response [1]byte
		if _, err := io.ReadFull(s, response[:]); err != nil {
			return err
		}
		return streamproxy.ResponseError(response[0])
	})
	if err != nil {
		s.Close()
		return nil, "", err
	}
	return s, next, nil
}

func chainStatus(err error) byte {
	switch {
	case errors.Is(err, streamproxy.ErrLegacy):
		return streamproxy.StatusLegacy
	case errors.Is(err, streamproxy.ErrUnknownSession):
		return streamproxy.StatusUnknown
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
	state := r.state.Load()
	if state == nil {
		return
	}
	_, local, err := state.router.TCPRoute(request, remote)
	if err != nil {
		refuse(ctx, s, streamproxy.StatusRefused)
		return
	}
	if local {
		r.acceptEgress(parent, ctx, network, remote, s, request)
		return
	}
	down, next, err := r.openChain(ctx, request, remote)
	if err != nil {
		refuse(ctx, s, chainStatus(err))
		return
	}
	if err := streamproxy.During(ctx, s, func() error {
		_, err := s.Write([]byte{streamproxy.StatusOK})
		return err
	}); err != nil {
		down.Close()
		return
	}
	relay := streamproxy.NewSessionRelay(s, down)
	entry := &relaySession{request: request, ingress: remote, next: next, down: down, relay: relay}
	r.sessions.mu.Lock()
	r.sessions.relays[entry] = struct{}{}
	r.sessions.mu.Unlock()
	defer func() {
		r.sessions.mu.Lock()
		delete(r.sessions.relays, entry)
		r.sessions.mu.Unlock()
	}()
	relay.Run(parent)
}

func (r *DataPlane) acceptEgress(parent, ctx context.Context, network, remote model.ID, s streamproxy.Conn, request streamproxy.Request) {
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
	create := entry == nil && !ended && request.Up == 0 && request.Down == 0
	if create {
		entry = &egressSession{ready: make(chan struct{})}
		r.sessions.egress[key] = entry
	}
	r.sessions.mu.Unlock()
	if entry == nil {
		refuse(ctx, s, streamproxy.StatusUnknown)
		return
	}
	if create {
		plain := request
		plain.Conn = streamproxy.SessionID{}
		conn, err := r.openTCP(ctx, plain, remote)
		if err == nil {
			entry.session = streamproxy.NewEgress(r.ctx, conn)
		}
		close(entry.ready)
		if err != nil {
			r.endEgress(key, entry)
			refuse(ctx, s, streamproxy.StatusRefused)
			return
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			entry.session.Run()
			r.endEgress(key, entry)
		}()
	} else {
		select {
		case <-entry.ready:
		case <-ctx.Done():
			return
		}
		if entry.session == nil {
			refuse(ctx, s, streamproxy.StatusUnknown)
			return
		}
	}
	if _, err := s.Write([]byte{streamproxy.StatusOK}); err != nil {
		return
	}
	released, ok := entry.session.Add(s, request)
	if !ok {
		return
	}
	select {
	case <-released:
	case <-parent.Done():
	}
}

func (r *DataPlane) endEgress(key sessionKey, entry *egressSession) {
	r.sessions.mu.Lock()
	defer r.sessions.mu.Unlock()
	if r.sessions.egress[key] == entry {
		delete(r.sessions.egress, key)
	}
	r.sessions.ended[key] = time.Now()
}

// countSessions adds the sessions whose next hop each Edge reaches to the
// Edge's active Link, by carriage.
func (r *DataPlane) countSessions(state *runtimeState, links []model.LinkStatus) {
	type hopKey struct {
		network, next model.ID
		carrier       bool
	}
	counts := map[hopKey]uint32{}
	r.sessions.mu.Lock()
	relays := make([]*relaySession, 0, len(r.sessions.relays))
	for s := range r.sessions.relays {
		relays = append(relays, s)
	}
	ingress := make([]*ingressSession, 0, len(r.sessions.ingress))
	for s := range r.sessions.ingress {
		ingress = append(ingress, s)
	}
	r.sessions.mu.Unlock()
	for _, s := range relays {
		counts[hopKey{s.request.Network, s.next, mesh.IsCarrier(s.down)}]++
	}
	for _, s := range ingress {
		if next, hop, ok := s.session.Next(); ok {
			counts[hopKey{s.request.Network, next, mesh.IsCarrier(hop)}]++
		}
	}
	if len(counts) == 0 {
		return
	}
	edges := map[[2]model.ID]model.ID{} // network, edge -> peer node
	for _, n := range state.snapshot.Networks {
		for _, p := range n.Peers {
			edges[[2]model.ID{n.ID, p.Edge.ID}] = p.Node.ID
		}
	}
	for i := range links {
		l := &links[i]
		if !l.Active {
			continue
		}
		peer := edges[[2]model.ID{l.NetworkID, l.EdgeID}]
		l.StreamSessions = counts[hopKey{l.NetworkID, peer, false}]
		l.CarrierSessions = counts[hopKey{l.NetworkID, peer, true}]
	}
}
