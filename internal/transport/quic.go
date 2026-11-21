package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"github.com/eddiexyang/graphnet/internal/sockets"
	quic "github.com/quic-go/quic-go"
)

const (
	quicProtocol = "graphnet.quic.v2"
	// quicIDSize is the length of every local connection ID, which starts
	// with quicIDPrefix; see quicIDs.
	quicIDSize   = 16
	quicIDPrefix = 'Q'
	// quicQueue bounds the datagrams waiting for QUIC's reader.
	quicQueue = 1024
	// A knock opens QUIC to its sender's address for quicKnockLife: kind,
	// 8-byte Unix time, 8 random bytes, then quicKnockMAC bytes of
	// HMAC-SHA256 keyed by the receiver's identity. Without one, a stranger's
	// Initial gets no answer.
	quicKnockKind  = 0x47
	quicKnockSize  = 1 + 8 + 8 + quicKnockMAC
	quicKnockMAC   = 16
	quicKnockLife  = time.Minute
	quicKnockSkew  = time.Minute
	quicKnockLimit = 4096
)

// QUIC carries a Link as one bidirectional stream of length-framed messages,
// as TCP does, over the UDP hub's sockets. Like a TCP Link it carries
// streams; unlike one it shares the port with native UDP and STUN.
type QUIC struct {
	*Stream
	conn             *quic.Conn
	releaseAdmission func()
}

// Authenticated is invoked by the configured Noise handshake, never by QUIC's
// TLS, which only pins the server.
func (q *QUIC) Authenticated() {
	if q.releaseAdmission != nil {
		q.releaseAdmission()
	}
}

// QUICHub dials and accepts QUIC Links on a UDP hub's sockets.
type QUICHub struct {
	udp       *UDP
	engines   map[*net.UDPConn]*quic.Transport
	sockets   map[*net.UDPConn]*quicSocket
	listeners []*quic.Listener
	slots     chan struct{}
	accepted  chan *QUIC
	wg        sync.WaitGroup
	cancel    context.CancelFunc
	ids       quicIDs
	// knockKey is the key of knocks toward this Agent; knocks holds when each
	// knocking address may start a connection until. The hub's lock guards it.
	knockKey [32]byte
	knocks   map[netip.AddrPort]time.Time
}

// quicKey derives one of an identity's QUIC keys.
func quicKey(secret []byte, label string) (key [32]byte) {
	derived, _ := hkdf.Key(sha256.New, secret, nil, label, len(key))
	copy(key[:], derived)
	return key
}

// admit reports a datagram for QUIC: one toward a connection ID this Agent
// made, or an Initial from an address that knocked. The hub's lock is held.
func (q *QUICHub) admit(raw []byte, remote netip.AddrPort, now time.Time) bool {
	if len(raw) < 1+quicIDSize || raw[0]&0x40 == 0 {
		return false
	}
	if raw[0]&0x80 == 0 {
		return q.ids.verify(raw[1 : 1+quicIDSize])
	}
	if len(raw) < 6 || binary.BigEndian.Uint32(raw[1:5]) != uint32(quic.Version1) {
		return false
	}
	if size := int(raw[5]); size == quicIDSize && len(raw) >= 6+size && q.ids.verify(raw[6:6+size]) {
		return true
	}
	initial := raw[0]&0x30 == 0
	return initial && now.Before(q.knocks[remote])
}

// knock records a valid knock from remote. The hub's lock is held.
func (q *QUICHub) knock(raw []byte, remote netip.AddrPort, now time.Time) {
	if len(raw) != quicKnockSize {
		return
	}
	sent := time.Unix(int64(binary.BigEndian.Uint64(raw[1:9])), 0)
	if sent.Before(now.Add(-quicKnockSkew)) || sent.After(now.Add(quicKnockSkew)) {
		return
	}
	mac := hmac.New(sha256.New, q.knockKey[:])
	mac.Write(raw[:quicKnockSize-quicKnockMAC])
	if subtle.ConstantTimeCompare(mac.Sum(nil)[:quicKnockMAC], raw[quicKnockSize-quicKnockMAC:]) != 1 {
		return
	}
	if len(q.knocks) >= quicKnockLimit {
		for address, until := range q.knocks {
			if now.After(until) {
				delete(q.knocks, address)
			}
		}
		if len(q.knocks) >= quicKnockLimit {
			return
		}
	}
	q.knocks[remote] = now.Add(quicKnockLife)
}

// knockFor returns a knock toward the Agent of identity.
func knockFor(identity ed25519.PublicKey) []byte {
	key := quicKey(identity, "GraphNet QUIC knock v1")
	raw := make([]byte, quicKnockSize)
	raw[0] = quicKnockKind
	binary.BigEndian.PutUint64(raw[1:9], uint64(time.Now().Unix()))
	rand.Read(raw[9:17])
	mac := hmac.New(sha256.New, key[:])
	mac.Write(raw[:quicKnockSize-quicKnockMAC])
	copy(raw[quicKnockSize-quicKnockMAC:], mac.Sum(nil))
	return raw
}

// EnableQUIC starts QUIC on the hub's sockets: datagrams that admit takes
// and no native peer claims go to it.
func (h *UDP) EnableQUIC(identity ed25519.PrivateKey) (*QUICHub, error) {
	tlsConfig, err := PeerServerTLS(identity)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = []string{quicProtocol}
	reset, err := hkdf.Key(sha256.New, identity.Seed(), nil, "GraphNet QUIC stateless reset v2", 32)
	if err != nil {
		return nil, err
	}
	var resetKey quic.StatelessResetKey
	copy(resetKey[:], reset)
	ctx, cancel := context.WithCancel(context.Background())
	q := &QUICHub{udp: h, engines: map[*net.UDPConn]*quic.Transport{}, sockets: map[*net.UDPConn]*quicSocket{}, slots: make(chan struct{}, 512), accepted: make(chan *QUIC), cancel: cancel, knocks: map[netip.AddrPort]time.Time{}}
	q.ids = quicIDs{key: quicKey(identity.Seed(), "GraphNet QUIC connection ID v1")}
	q.knockKey = quicKey(identity.Public().(ed25519.PublicKey), "GraphNet QUIC knock v1")
	for _, socket := range h.sockets {
		conn := &quicSocket{socket: socket, hub: h, incoming: make(chan udpPacketCopy, quicQueue), done: make(chan struct{})}
		engine := &quic.Transport{
			Conn:                             conn,
			ConnectionIDGenerator:            q.ids,
			StatelessResetKey:                &resetKey,
			DisableVersionNegotiationPackets: true,
			VerifySourceAddress:              func(net.Addr) bool { return true },
			ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
				release, err := q.reserve()
				if err != nil {
					return nil, err
				}
				context.AfterFunc(ctx, release)
				return context.WithValue(ctx, quicAdmissionKey{}, release), nil
			},
		}
		listener, err := engine.Listen(tlsConfig, quicConfig())
		if err != nil {
			cancel()
			q.close()
			return nil, err
		}
		q.engines[socket], q.sockets[socket] = engine, conn
		q.listeners = append(q.listeners, listener)
	}
	h.mu.Lock()
	h.quic = q
	h.mu.Unlock()
	for _, listener := range q.listeners {
		q.wg.Add(1)
		go func() {
			defer q.wg.Done()
			for {
				conn, err := listener.Accept(ctx)
				if err != nil {
					return
				}
				q.wg.Add(1)
				go func() {
					defer q.wg.Done()
					q.acceptStream(ctx, conn)
				}()
			}
		}()
	}
	return q, nil
}

type quicAdmissionKey struct{}

func (q *QUICHub) acceptStream(ctx context.Context, conn *quic.Conn) {
	accept, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := conn.AcceptStream(accept)
	if err != nil {
		conn.CloseWithError(1, "no stream")
		return
	}
	release, _ := conn.Context().Value(quicAdmissionKey{}).(func())
	link := &QUIC{Stream: NewStream(&quicConn{Stream: stream, conn: conn}), conn: conn, releaseAdmission: release}
	select {
	case q.accepted <- link:
	case <-ctx.Done():
		conn.CloseWithError(0, "listener closed")
	}
}

func quicConfig() *quic.Config {
	return &quic.Config{Versions: []quic.Version{quic.Version1},
		HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 15 * time.Second, KeepAlivePeriod: 5 * time.Second,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 512 << 10, MaxStreamReceiveWindow: 16 << 20,
		InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 24 << 20,
	}
}

// Admission bounds TLS/Noise handshakes, not the configured live Link set.
// Authentication and connection cancellation may race; each releases once.
func (q *QUICHub) reserve() (func(), error) {
	select {
	case <-q.udp.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case q.slots <- struct{}{}:
		return sync.OnceFunc(func() { <-q.slots }), nil
	default:
		return nil, errors.New("QUIC pending connection limit reached")
	}
}

// close stops QUIC; the hub's Close calls it.
func (q *QUICHub) close() {
	q.cancel()
	for _, socket := range q.sockets {
		socket.Close()
	}
	for _, engine := range q.engines {
		engine.Close()
	}
	q.wg.Wait()
}

func (q *QUICHub) Accept(ctx context.Context) (*QUIC, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-q.udp.done:
		return nil, net.ErrClosed
	case link := <-q.accepted:
		return link, nil
	}
}

// DialAt pins a DNS answer while retaining the endpoint TLS hostname.
func (q *QUICHub) DialAt(ctx context.Context, endpoint model.Endpoint, family int, identity ed25519.PublicKey, target netip.Addr) (*QUIC, error) {
	if err := endpoint.Validate(); err != nil {
		return nil, err
	}
	if endpoint.Transport != model.QUIC || family != 4 && family != 6 {
		return nil, errors.New("invalid QUIC candidate")
	}
	u, _ := url.Parse(endpoint.URL)
	if !target.IsValid() {
		target, _ = netip.ParseAddr(u.Hostname())
	}
	if _, err := EndpointDialAddress(endpoint, family, target); err != nil {
		return nil, err
	}
	addresses := []netip.Addr{target}
	var err error
	if !target.IsValid() {
		addresses, err = sockets.LookupNetIP(ctx, "ip"+strconv.Itoa(family), u.Hostname())
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("endpoint has no address for permitted family")
	}
	release, err := q.reserve()
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	port, _ := strconv.ParseUint(u.Port(), 10, 16)
	knock := knockFor(identity)
	tlsConfig := PeerClientTLS(u.Hostname(), identity, nil)
	tlsConfig.NextProtos = []string{quicProtocol}
	for i, address := range addresses {
		attempt := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			attempt, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-i))
		}
		socket := q.udp.socketFor(address)
		engine := q.engines[socket]
		stopKnocking := q.knockUntil(attempt, socket, netip.AddrPortFrom(address, uint16(port)), knock)
		conn, dialErr := engine.Dial(attempt, net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, uint16(port))), tlsConfig, quicConfig())
		stopKnocking()
		if dialErr == nil {
			var stream *quic.Stream
			if stream, dialErr = conn.OpenStreamSync(attempt); dialErr != nil {
				conn.CloseWithError(1, "no stream")
			} else {
				cancel()
				retained = true
				context.AfterFunc(conn.Context(), release)
				return &QUIC{Stream: NewStream(&quicConn{Stream: stream, conn: conn}), conn: conn, releaseAdmission: release}, nil
			}
		}
		cancel()
		err = dialErr
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, err
}

// knockUntil sends knock to remote now and again while a dial may still be
// waiting on a lost one; stop ends it.
func (q *QUICHub) knockUntil(ctx context.Context, socket *net.UDPConn, remote netip.AddrPort, knock []byte) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, wait := range []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond, 700 * time.Millisecond, 1500 * time.Millisecond} {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			q.udp.writeMu.Lock()
			socket.WriteToUDPAddrPort(knock, remote)
			q.udp.writeMu.Unlock()
		}
	}()
	return func() { cancel(); <-done }
}

// quicConn is a QUIC stream as a net.Conn; closing it closes the connection.
type quicConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (c *quicConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *quicConn) Close() error {
	c.Stream.CancelRead(0)
	c.Stream.Close()
	return c.conn.CloseWithError(0, "closed")
}

// udpPacketCopy is a datagram the hub passed to QUIC.
type udpPacketCopy struct {
	buffer *packetbuf.Buffer
	remote netip.AddrPort
}

// quicSocket is QUIC's view of a hub socket: it reads what the hub passes
// and writes to the socket directly.
type quicSocket struct {
	socket   *net.UDPConn
	hub      *UDP
	incoming chan udpPacketCopy
	done     chan struct{}
	once     sync.Once
	deadline sync.Mutex
	timer    *time.Timer
	expired  chan struct{}
	// changed is closed and replaced when the read deadline changes, so a
	// blocked read takes the new one.
	changed chan struct{}
}

// pass hands a datagram to QUIC, dropping it when QUIC's queue is full.
func (s *quicSocket) pass(raw []byte, remote netip.AddrPort) {
	buffer := packetbuf.Get(len(raw))
	copy(buffer.Data, raw)
	select {
	case s.incoming <- udpPacketCopy{buffer, remote}:
	default:
		buffer.Release()
	}
}

func (s *quicSocket) ReadFrom(raw []byte) (int, net.Addr, error) {
	for {
		s.deadline.Lock()
		if s.changed == nil {
			s.changed = make(chan struct{})
		}
		expired, changed := s.expired, s.changed
		s.deadline.Unlock()
		select {
		case p := <-s.incoming:
			n := copy(raw, p.buffer.Data)
			p.buffer.Release()
			return n, net.UDPAddrFromAddrPort(p.remote), nil
		case <-s.done:
			return 0, nil, net.ErrClosed
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
		}
	}
}

func (s *quicSocket) WriteTo(raw []byte, remote net.Addr) (int, error) {
	address, ok := remote.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid QUIC address")
	}
	s.hub.writeMu.Lock()
	defer s.hub.writeMu.Unlock()
	if err := s.socket.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return 0, err
	}
	defer s.socket.SetWriteDeadline(time.Time{})
	return s.socket.WriteToUDPAddrPort(raw, address.AddrPort())
}

func (s *quicSocket) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}
func (s *quicSocket) LocalAddr() net.Addr              { return s.socket.LocalAddr() }
func (s *quicSocket) SetDeadline(t time.Time) error    { return s.SetReadDeadline(t) }
func (s *quicSocket) SetWriteDeadline(time.Time) error { return nil }
func (s *quicSocket) SetReadBuffer(int) error          { return nil }
func (s *quicSocket) SetWriteBuffer(int) error         { return nil }
func (s *quicSocket) SetReadDeadline(t time.Time) error {
	s.deadline.Lock()
	defer s.deadline.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.expired = nil
	if !t.IsZero() {
		expired := make(chan struct{})
		s.expired = expired
		s.timer = time.AfterFunc(time.Until(t), func() { close(expired) })
	}
	if s.changed != nil {
		close(s.changed)
		s.changed = nil
	}
	return nil
}

// Every local connection ID is quicIDPrefix, 7 random bytes and a MAC of
// those 8 under a key of this Agent's identity, so the hub passes QUIC only
// datagrams toward IDs it made and a stranger's guess gets no answer.
type quicIDs struct{ key [32]byte }

const quicIDRandom = 8

func (ids quicIDs) ConnectionIDLen() int { return quicIDSize }
func (ids quicIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	var raw [quicIDSize]byte
	raw[0] = quicIDPrefix
	if _, err := rand.Read(raw[1:quicIDRandom]); err != nil {
		return quic.ConnectionID{}, err
	}
	copy(raw[quicIDRandom:], ids.mac(raw[:quicIDRandom]))
	return quic.ConnectionIDFromBytes(raw[:]), nil
}

func (ids quicIDs) mac(prefix []byte) []byte {
	mac := hmac.New(sha256.New, ids.key[:])
	mac.Write(prefix)
	return mac.Sum(nil)[:quicIDSize-quicIDRandom]
}

func (ids quicIDs) verify(id []byte) bool {
	return len(id) == quicIDSize && id[0] == quicIDPrefix && subtle.ConstantTimeCompare(ids.mac(id[:quicIDRandom]), id[quicIDRandom:]) == 1
}
