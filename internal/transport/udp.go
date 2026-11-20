package transport

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eddiexyang/graphnet/internal/packetbuf"
)

const (
	// udpTokenSize trails each GraphNet datagram: the sender's random token,
	// which with its address names one message connection.
	udpTokenSize = 4
	// A GraphNet datagram's first byte, its peer message kind, is at least
	// udpFirstKind, so STUN, whose first byte is 0 or 1, cannot be mistaken
	// for one.
	udpFirstKind = 0x40
	// udpReceiveBuffer absorbs receive bursts while readers hand batches on.
	udpReceiveBuffer = 7 << 20
	maxPendingUDP    = 512
	udpQueueSize     = 256
)

type udpKey struct {
	remote netip.AddrPort
	token  [udpTokenSize]byte
}

// UDP multiplexes independent message connections over one data socket per address
// family. The same socket is used for STUN and hole punching; a NAT mapping must
// never be discovered on a different socket than the one carrying peer traffic.
type UDP struct {
	sockets      []*net.UDPConn
	batchSockets map[*net.UDPConn]*udpBatchSocket
	mu           sync.Mutex
	writeMu      sync.Mutex
	peers        map[udpKey]*Datagram
	quic         *QUICHub
	pending      int // Only peers that have not passed the configured Noise handshake.
	accept       chan *Datagram
	done         chan struct{}
	closeOnce    sync.Once
	wg           sync.WaitGroup
	stunMu       sync.Mutex
	stunPending  map[[12]byte]*stunTransaction
}

type Datagram struct {
	replyControl  []byte
	batchSend     *udpBatchSend
	hub           *UDP
	key           udpKey
	incoming      *packetbuf.Queue
	done          chan struct{}
	closeOnce     sync.Once
	lastSeen      atomic.Int64
	authenticated atomic.Bool
}

// ListenUDP shares each address family's data socket between native UDP,
// and STUN. The sockets use the hooks of ctx.
func ListenUDP(ctx context.Context, address string) (*UDP, error) {
	sockets, err := listenUDPSockets(ctx, address)
	if err != nil {
		return nil, err
	}
	return newUDP(sockets)
}

// NewUDP takes ownership of socket, including cleanup if setup fails.
func NewUDP(socket *net.UDPConn) (*UDP, error) { return newUDP([]*net.UDPConn{socket}) }

func newUDP(sockets []*net.UDPConn) (*UDP, error) {
	for _, socket := range sockets {
		// BSD defaults may be smaller than one permitted GraphNet message.
		var err error
		switch runtime.GOOS {
		case "darwin", "dragonfly", "freebsd", "netbsd", "openbsd":
			err = socket.SetWriteBuffer(64 << 10)
		}
		if err == nil {
			err = enableUDPPacketInfo(socket)
		}
		if err != nil {
			for _, owned := range sockets {
				owned.Close()
			}
			return nil, err
		}
	}
	hub := &UDP{sockets: sockets, peers: map[udpKey]*Datagram{}, accept: make(chan *Datagram, 64), done: make(chan struct{})}
	hub.batchSockets = make(map[*net.UDPConn]*udpBatchSocket, len(sockets))
	for _, socket := range sockets {
		hub.batchSockets[socket] = newUDPBatchSocket(socket)
	}
	hub.wg.Add(1 + len(sockets))
	for _, socket := range sockets {
		go hub.readLoop(socket)
	}
	go hub.expireLoop()
	return hub, nil
}
func (h *UDP) LocalAddr() net.Addr { return h.sockets[0].LocalAddr() }
func (h *UDP) Close() error {
	h.stop()
	h.mu.Lock()
	q := h.quic
	h.mu.Unlock()
	if q != nil {
		q.close()
	}
	h.wg.Wait()
	return nil
}
func (h *UDP) stop() {
	h.closeOnce.Do(func() {
		close(h.done)
		for _, socket := range h.sockets {
			socket.Close()
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, peer := range h.peers {
			peer.closeOnce.Do(func() { close(peer.done); peer.incoming.Close() })
		}
		clear(h.peers)
		h.pending = 0
	})
}
func (h *UDP) newPeer(key udpKey, reply []byte) *Datagram {
	peer := &Datagram{replyControl: reply, hub: h, key: key, incoming: packetbuf.NewQueue(udpQueueSize), done: make(chan struct{})}
	peer.lastSeen.Store(time.Now().UnixNano())
	h.peers[key] = peer
	h.pending++
	return peer
}
func (h *UDP) Dial(remote netip.AddrPort) (*Datagram, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() {
		return nil, errors.New("invalid UDP peer address")
	}
	key := udpKey{remote: remote}
	for key.token == [udpTokenSize]byte{} {
		rand.Read(key.token[:])
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.done:
		return nil, net.ErrClosed
	default:
	}
	if h.pending >= maxPendingUDP {
		return nil, errors.New("UDP pending peer limit reached")
	}
	return h.newPeer(key, nil), nil
}
func (h *UDP) Accept(ctx context.Context) (*Datagram, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-h.done:
			return nil, net.ErrClosed
		case peer := <-h.accept:
			select {
			case <-peer.done:
				continue
			default:
				return peer, nil
			}
		}
	}
}

type udpPacket struct {
	raw, control []byte
	remote       netip.AddrPort
	flags        int
}

func (h *UDP) readLoop(socket *net.UDPConn) {
	defer h.wg.Done()
	defer h.stop()
	reader := newUDPPacketReader(socket)
	var packets [packetbuf.BatchSize]udpPacket
	for {
		n, err := reader.readBatch(packets[:])
		if udpReadTruncated(0, err) {
			continue
		}
		if err != nil {
			return
		}
		count := 0
		for _, p := range packets[:n] {
			if udpReadTruncated(p.flags, nil) || h.receiveSTUN(p.raw, p.remote) {
				continue
			}
			packets[count] = p
			count++
		}
		h.receivePackets(socket, packets[:count])
	}
}

// receivePackets publishes each consecutive run for a peer together, preserving
// socket/GRO batches through the decryption queue. The lock also serializes
// acceptance and close, so no storage can arrive after the last close drain.
func (h *UDP) receivePackets(socket *net.UDPConn, packets []udpPacket) {
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.done:
		return
	default:
	}
	now := time.Now()
	var pending [packetbuf.BatchSize]*packetbuf.Buffer
	var previous *Datagram
	count := 0
	flush := func() {
		if count > 0 {
			previous.incoming.Put(pending[:count])
			clear(pending[:count])
			count = 0
		}
	}
	defer flush()
	for _, p := range packets {
		raw, remote := p.raw, p.remote
		n := len(raw)
		if n <= udpTokenSize || n > MaxMessage+udpTokenSize || raw[0] < udpFirstKind {
			continue
		}
		key := udpKey{remote: netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()), token: [udpTokenSize]byte(raw[n-udpTokenSize:])}
		peer := h.peers[key]
		if peer == nil && h.quic != nil {
			if raw[0] == quicKnockKind && n == quicKnockSize {
				h.quic.knock(raw, key.remote, now)
				continue
			}
			if h.quic.admit(raw, key.remote, now) {
				h.quic.sockets[socket].pass(raw, remote)
				continue
			}
		}
		if key.token == [udpTokenSize]byte{} {
			continue
		}
		if peer == nil {
			if h.pending >= maxPendingUDP {
				continue
			}
			peer = h.newPeer(key, udpReplyControl(p.control, remote))
			select {
			case h.accept <- peer:
			default:
				delete(h.peers, key)
				h.pending--
				peer.closeOnce.Do(func() { close(peer.done); peer.incoming.Close() })
				continue
			}
		}
		if peer != previous || count == len(pending) {
			flush()
			previous = peer
		}
		payload := packetbuf.Get(n - udpTokenSize)
		copy(payload.Data, raw[:n-udpTokenSize])
		pending[count] = payload
		count++
	}
}

func (h *UDP) expireLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case now := <-ticker.C:
			h.mu.Lock()
			expired := []*Datagram{}
			for _, peer := range h.peers {
				limit := 10 * time.Second
				if peer.authenticated.Load() {
					limit = 2 * time.Minute
				}
				if now.Sub(time.Unix(0, peer.lastSeen.Load())) > limit {
					expired = append(expired, peer)
				}
			}
			h.mu.Unlock()
			for _, peer := range expired {
				peer.Close()
			}
		}
	}
}
func (d *Datagram) LocalAddr() net.Addr  { return d.hub.socketFor(d.key.remote.Addr()).LocalAddr() }
func (d *Datagram) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(d.key.remote) }

// Authenticated is called only after validating a peer handshake. Validated
// application packets call Alive; unauthenticated traffic cannot extend lifetime.
// Established configured Links must not exhaust pending handshake admission.
func (d *Datagram) Authenticated() {
	d.hub.mu.Lock()
	if d.hub.peers[d.key] == d && !d.authenticated.Swap(true) {
		d.hub.pending--
	}
	d.hub.mu.Unlock()
	d.Alive()
}
func (d *Datagram) Alive() { d.lastSeen.Store(time.Now().UnixNano()) }
func (d *Datagram) Close() error {
	d.hub.mu.Lock()
	defer d.hub.mu.Unlock()
	d.closeOnce.Do(func() {
		close(d.done)
		d.incoming.Close()
		if d.hub.peers[d.key] == d {
			delete(d.hub.peers, d.key)
			if !d.authenticated.Load() {
				d.hub.pending--
			}
		}
	})
	return nil
}
func (d *Datagram) Send(ctx context.Context, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxMessage || payload[0] < udpFirstKind {
		return errors.New("invalid UDP message size")
	}
	select {
	case <-d.done:
		return net.ErrClosed
	default:
	}
	raw := make([]byte, 0, len(payload)+udpTokenSize)
	raw = append(append(raw, payload...), d.key.token[:]...)
	return d.hub.writeDatagramControl(ctx, raw, d.key.remote, d.replyControl)
}

func (h *UDP) writeDatagram(ctx context.Context, raw []byte, remote netip.AddrPort) error {
	return h.writeDatagramControl(ctx, raw, remote, nil)
}

func (h *UDP) writeDatagramControl(ctx context.Context, raw []byte, remote netip.AddrPort, control []byte) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	socket := h.socketFor(remote.Addr())
	cleanup, err := deadline(ctx, socket.SetWriteDeadline)
	if err != nil {
		return err
	}
	defer cleanup()
	n, _, err := socket.WriteMsgUDPAddrPort(raw, control, remote)
	if err != nil {
		return ctxError(ctx, err)
	}
	if n != len(raw) {
		return errors.New("partial UDP datagram")
	}
	return nil
}
func (d *Datagram) receiveOwned(ctx context.Context) (*packetbuf.Buffer, error) {
	var out [1]*packetbuf.Buffer
	_, err := d.incoming.Read(ctx, out[:])
	return out[0], err
}
func (d *Datagram) Receive(ctx context.Context) ([]byte, error) {
	b, err := d.receiveOwned(ctx)
	if err != nil {
		return nil, err
	}
	defer b.Release()
	return append([]byte(nil), b.Data...), nil
}
func (d *Datagram) ReceiveBatch(ctx context.Context) ([][]byte, error) {
	batch, err := d.ReceiveOwnedBatch(ctx)
	if err != nil {
		return nil, err
	}
	defer packetbuf.ReleaseAll(batch)
	out := make([][]byte, len(batch))
	for i, b := range batch {
		out[i] = append([]byte(nil), b.Data...)
	}
	return out, nil
}
func (d *Datagram) ReceiveOwnedBatch(ctx context.Context) ([]*packetbuf.Buffer, error) {
	out := make([]*packetbuf.Buffer, packetbuf.BatchSize)
	n, err := d.incoming.Read(ctx, out)
	return out[:n], err
}

func (d *Datagram) Unreliable() bool { return true }

// A single externally supplied socket may support both families. With separate
// wildcard sockets, select the family before sending native or STUN data.
func (h *UDP) socketFor(remote netip.Addr) *net.UDPConn {
	for _, socket := range h.sockets {
		if socket.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap().Is4() == remote.Unmap().Is4() {
			return socket
		}
	}
	return h.sockets[0]
}
