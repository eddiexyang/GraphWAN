package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

// The two ends of a TCP session seal its bytes with an end-to-end session
// between their Nodes, so relays carry them without opening them. Each Agent
// opens a session toward every Node in its directory with an Agent key ahead
// of use, as the initiator; the sessions it accepts as the responder serve
// the connections other Nodes bring. The handshake travels as UDP between the
// Nodes' overlay addresses on e2ePort, taken before the TUN like replay
// requests, and is retried until it completes: its messages are
// authenticated by the handshake itself.
const (
	e2ePort = 0x4758
	// Messages: [kind][session ID][Noise message].
	e2eHello   = 1 // initiator, Noise message 1
	e2eReply   = 2 // responder, message 2
	e2eFinish  = 3 // initiator, message 3
	e2eConfirm = 4 // responder: the session is in use
	e2eIDSize  = len(e2eID{})
	// An unanswered message is sent again after e2eRetry, doubling to
	// e2eRetryMax; a handshake that does not complete in e2eAttempt starts
	// over.
	e2eRetry    = 200 * time.Millisecond
	e2eRetryMax = 2 * time.Second
	e2eAttempt  = 10 * time.Second
	// A session is replaced this long before it may no longer seal new
	// channels; open channels keep it.
	e2eRenew = 10 * time.Minute
	// A responder keeps this many sessions per Node: the current one, and
	// the one connections opened just before it replaced it.
	e2eKept = 2
	// Responder handshakes in progress per Node.
	e2ePending = 8
)

type e2eID = streamproxy.E2EID

type e2ePeer struct{ network, node model.ID }

// e2eSession is an established end-to-end session; channel hands out its
// initiator's channels, of which 0 is reserved.
type e2eSession struct {
	id      e2eID
	session *secure.Session
	mu      sync.Mutex
	channel uint32
}

// nextChannel returns a channel no other connection used, or false once the
// session has none left.
func (s *e2eSession) nextChannel() (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.channel == ^uint32(0) {
		return 0, false
	}
	s.channel++
	return s.channel, true
}

// e2eOutgoing is this Agent's sessions toward one Node.
type e2eOutgoing struct {
	key     ed25519.PublicKey
	current *e2eSession
	ready   chan struct{} // closed once current is set; replaced when it is dropped
	// The handshake in progress.
	attempt   *secure.Handshake
	id        e2eID
	started   time.Time
	message   []byte // the last message sent, until answered
	retry     time.Time
	delay     time.Duration
	confirmed *secure.Session // after message 3, until confirmed
}

type e2eResponse struct {
	handshake *secure.Handshake
	reply     []byte
	started   time.Time
}

// e2eIncoming is the sessions one Node opened toward this Agent.
type e2eIncoming struct {
	key      ed25519.PublicKey
	pending  map[e2eID]*e2eResponse
	sessions []*e2eSession // oldest first
}

type e2eSessions struct {
	mu       sync.Mutex
	outgoing map[e2ePeer]*e2eOutgoing
	incoming map[e2ePeer]*e2eIncoming
	wake     chan struct{}
}

func (e *e2eSessions) init() {
	e.outgoing = map[e2ePeer]*e2eOutgoing{}
	e.incoming = map[e2ePeer]*e2eIncoming{}
	e.wake = make(chan struct{}, 1)
}

func (r *DataPlane) wakeE2E() {
	select {
	case r.e2e.wake <- struct{}{}:
	default:
	}
}

// e2eLoop keeps a session toward every keyed Node of the directory and
// resends handshake messages that are not answered.
func (r *DataPlane) e2eLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(e2eRetry / 4)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.e2e.wake:
		case <-ticker.C:
		}
		r.maintainE2E()
	}
}

// e2eKeys returns the Agent keys of the directory's other Nodes.
func e2eKeys(state *runtimeState) map[e2ePeer]ed25519.PublicKey {
	keys := map[e2ePeer]ed25519.PublicKey{}
	for _, n := range state.snapshot.Networks {
		for _, d := range n.Directory {
			if d.NodeID != n.Self.ID && len(d.PublicKey) == ed25519.PublicKeySize {
				keys[e2ePeer{n.ID, d.NodeID}] = d.PublicKey
			}
		}
	}
	return keys
}

func (r *DataPlane) maintainE2E() {
	state := r.state.Load()
	if state == nil {
		return
	}
	keys := e2eKeys(state)
	now := time.Now()
	type message struct {
		peer e2ePeer
		raw  []byte
	}
	var send []message
	e := &r.e2e
	e.mu.Lock()
	for peer, out := range e.outgoing {
		if key, ok := keys[peer]; !ok || !key.Equal(out.key) {
			delete(e.outgoing, peer)
		}
	}
	for peer, in := range e.incoming {
		if key, ok := keys[peer]; !ok || !key.Equal(in.key) {
			delete(e.incoming, peer)
			continue
		}
		for id, p := range in.pending {
			if now.Sub(p.started) > e2eAttempt {
				delete(in.pending, id)
			}
		}
	}
	for peer, key := range keys {
		out := e.outgoing[peer]
		if out == nil {
			out = &e2eOutgoing{key: key, ready: make(chan struct{})}
			e.outgoing[peer] = out
		}
		renew := out.current == nil || now.Sub(out.current.session.Created()) > secure.MaxSessionAge-e2eRenew
		if out.attempt == nil && renew || out.attempt != nil && now.Sub(out.started) > e2eAttempt {
			raw, ok := r.startE2ELocked(state, peer, out, now)
			if ok {
				send = append(send, message{peer, raw})
			}
			continue
		}
		if out.attempt != nil && !now.Before(out.retry) {
			out.retry, out.delay = now.Add(out.delay), min(2*out.delay, e2eRetryMax)
			send = append(send, message{peer, out.message})
		}
	}
	e.mu.Unlock()
	for _, m := range send {
		r.sendE2E(state, m.peer, m.raw)
	}
}

// startE2ELocked starts a handshake toward peer and returns its first message.
func (r *DataPlane) startE2ELocked(state *runtimeState, peer e2ePeer, out *e2eOutgoing, now time.Time) ([]byte, bool) {
	out.attempt, out.confirmed, out.message = nil, nil, nil
	config, ok := e2eConfig(state, peer, r.identity, out.key, true)
	if !ok {
		return nil, false
	}
	handshake, err := secure.NewEndToEndHandshake(config)
	if err != nil {
		return nil, false
	}
	message, _, err := handshake.Write()
	if err != nil {
		return nil, false
	}
	rand.Read(out.id[:])
	out.attempt, out.started = handshake, now
	out.message = e2eMessage(e2eHello, out.id, message)
	out.retry, out.delay = now.Add(e2eRetry), 2*e2eRetry
	return out.message, true
}

func e2eConfig(state *runtimeState, peer e2ePeer, identity ed25519.PrivateKey, key ed25519.PublicKey, initiator bool) (secure.E2EConfig, bool) {
	for _, n := range state.snapshot.Networks {
		if n.ID == peer.network {
			return secure.E2EConfig{Network: n.ID, Local: n.Self.ID, Peer: peer.node, Cipher: n.Cipher, Identity: identity, PeerIdentity: key, Initiator: initiator}, true
		}
	}
	return secure.E2EConfig{}, false
}

func e2eMessage(kind byte, id e2eID, noise []byte) []byte {
	raw := make([]byte, 0, 1+e2eIDSize+len(noise))
	raw = append(raw, kind)
	raw = append(raw, id[:]...)
	return append(raw, noise...)
}

// sendE2E sends a handshake message to peer's overlay address along the
// current routes.
func (r *DataPlane) sendE2E(state *runtimeState, peer e2ePeer, raw []byte) {
	from, ok := state.selfAddress[peer.network]
	to, found := state.overlayAddress(peer.network, peer.node)
	if !ok || !found {
		return
	}
	if udp := packet.UDP(netip.AddrPortFrom(from, e2ePort), netip.AddrPortFrom(to, e2ePort), raw); udp != nil {
		state.router.FromTunnel(r.ctx, peer.network, udp)
	}
}

// e2eRequest takes a handshake message addressed to this Agent. It reports
// whether the packet was one.
func (r *DataPlane) e2eRequest(state *runtimeState, network model.ID, raw []byte) bool {
	source, destination, payload, ok := packet.UDPDatagram(raw)
	if !ok || destination.Port() != e2ePort || source.Port() != e2ePort {
		return false
	}
	if destination.Addr() != state.selfAddress[network] || len(payload) < 1+e2eIDSize {
		return true
	}
	var peer e2ePeer
	var key ed25519.PublicKey
	for _, n := range state.snapshot.Networks {
		if n.ID != network {
			continue
		}
		for _, d := range n.Directory {
			if d.Address == source.Addr() && d.NodeID != n.Self.ID && len(d.PublicKey) == ed25519.PublicKeySize {
				peer, key = e2ePeer{network, d.NodeID}, d.PublicKey
			}
		}
	}
	if key == nil {
		return true
	}
	kind, noise := payload[0], payload[1+e2eIDSize:]
	var id e2eID
	copy(id[:], payload[1:])
	var reply []byte
	switch kind {
	case e2eHello, e2eFinish:
		reply = r.respondE2E(state, peer, key, kind, id, noise)
	case e2eReply, e2eConfirm:
		reply = r.answerE2E(peer, kind, id, noise)
	}
	if reply != nil {
		r.sendE2E(state, peer, reply)
	}
	return true
}

// respondE2E is the responder's side of a handshake from peer.
func (r *DataPlane) respondE2E(state *runtimeState, peer e2ePeer, key ed25519.PublicKey, kind byte, id e2eID, noise []byte) []byte {
	e := &r.e2e
	e.mu.Lock()
	defer e.mu.Unlock()
	in := e.incoming[peer]
	if in == nil || !key.Equal(in.key) {
		in = &e2eIncoming{key: key, pending: map[e2eID]*e2eResponse{}}
		e.incoming[peer] = in
	}
	for _, s := range in.sessions {
		if s.id == id {
			// Message 3 again: the confirmation was lost.
			if kind == e2eFinish {
				return e2eMessage(e2eConfirm, id, nil)
			}
			return nil
		}
	}
	p := in.pending[id]
	switch {
	case kind == e2eHello && p != nil:
		return p.reply
	case kind == e2eHello:
		if len(in.pending) >= e2ePending {
			// Anyone can start a handshake; the oldest gives way.
			var oldest e2eID
			for pid, q := range in.pending {
				if in.pending[oldest] == nil || q.started.Before(in.pending[oldest].started) {
					oldest = pid
				}
			}
			delete(in.pending, oldest)
		}
		config, ok := e2eConfig(state, peer, r.identity, key, false)
		if !ok {
			return nil
		}
		handshake, err := secure.NewEndToEndHandshake(config)
		if err != nil {
			return nil
		}
		if _, err := handshake.Read(noise); err != nil {
			return nil
		}
		message, _, err := handshake.Write()
		if err != nil {
			return nil
		}
		p = &e2eResponse{handshake: handshake, reply: e2eMessage(e2eReply, id, message), started: time.Now()}
		in.pending[id] = p
		return p.reply
	case p != nil:
		session, err := p.handshake.Read(noise)
		delete(in.pending, id)
		if err != nil || session == nil {
			return nil
		}
		in.sessions = append(in.sessions, &e2eSession{id: id, session: session})
		if len(in.sessions) > e2eKept {
			in.sessions = in.sessions[len(in.sessions)-e2eKept:]
		}
		return e2eMessage(e2eConfirm, id, nil)
	}
	return nil
}

// answerE2E is the initiator's side of a handshake toward peer.
func (r *DataPlane) answerE2E(peer e2ePeer, kind byte, id e2eID, noise []byte) []byte {
	e := &r.e2e
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.outgoing[peer]
	if out == nil || out.attempt == nil || out.id != id {
		return nil
	}
	switch {
	case kind == e2eReply && out.confirmed == nil:
		if _, err := out.attempt.Read(noise); err != nil {
			// Not from peer, or broken: the attempt starts over when it expires.
			return nil
		}
		message, session, err := out.attempt.Write()
		if err != nil || session == nil {
			out.started = time.Time{} // start over
			return nil
		}
		now := time.Now()
		out.confirmed = session
		out.message = e2eMessage(e2eFinish, id, message)
		out.retry, out.delay = now.Add(e2eRetry), 2*e2eRetry
		return out.message
	case kind == e2eConfirm && out.confirmed != nil:
		out.current = &e2eSession{id: id, session: out.confirmed}
		out.attempt, out.confirmed, out.message = nil, nil, nil
		close(out.ready)
		out.ready = make(chan struct{})
	}
	return nil
}

// e2eChannel returns this Agent's session toward a Node and a fresh channel of
// it, waiting for the session until ctx ends. It reports false when the Node
// has no Agent key: its connections are sealed per hop only.
func (r *DataPlane) e2eChannel(ctx context.Context, network, node model.ID) (*e2eSession, uint32, bool, error) {
	peer := e2ePeer{network, node}
	for {
		state := r.state.Load()
		if state == nil {
			return nil, 0, false, context.Canceled
		}
		if _, ok := e2eKeys(state)[peer]; !ok {
			return nil, 0, false, nil
		}
		e := &r.e2e
		e.mu.Lock()
		out := e.outgoing[peer]
		var ready chan struct{}
		if out != nil {
			if s := out.current; s != nil {
				e.mu.Unlock()
				if channel, ok := s.nextChannel(); ok {
					return s, channel, true, nil
				}
				r.dropE2E(network, node, s)
				continue
			}
			ready = out.ready
		}
		e.mu.Unlock()
		if ready == nil {
			r.wakeE2E()
			ready = make(chan struct{})
		}
		select {
		case <-ready:
		case <-time.After(e2eRetry):
		case <-ctx.Done():
			return nil, 0, true, ctx.Err()
		}
	}
}

// dropE2E forgets a session the far end no longer has, so the next
// connection waits for a new one.
func (r *DataPlane) dropE2E(network, node model.ID, s *e2eSession) {
	e := &r.e2e
	e.mu.Lock()
	if out := e.outgoing[e2ePeer{network, node}]; out != nil && out.current == s {
		out.current = nil
	}
	e.mu.Unlock()
	r.wakeE2E()
}

// e2eAccepted returns the session a Node opened toward this Agent.
func (r *DataPlane) e2eAccepted(network, node model.ID, id e2eID) *e2eSession {
	e := &r.e2e
	e.mu.Lock()
	defer e.mu.Unlock()
	if in := e.incoming[e2ePeer{network, node}]; in != nil {
		for _, s := range in.sessions {
			if s.id == id {
				return s
			}
		}
	}
	return nil
}
