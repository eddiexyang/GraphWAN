package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
	"github.com/eWloYW8/GraphWAN/internal/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type runtimeTCP struct {
	offload     bool
	engine      *streamproxy.Engine
	fingerprint string
	flows       tcpFlows
}

type flowKey struct{ client, server netip.AddrPort }
type flowState struct {
	established bool
	since       time.Time
}

// tcpFlows lists connections the local TCP stack owns. Their packets go to the
// stack in both directions; every other TCP packet is forwarded unchanged.
type tcpFlows struct {
	mu        sync.Mutex
	flows     map[flowKey]flowState
	lastPurge time.Time
}

// A captured SYN the stack never accepted (for example at its connection
// limit) leaves a pending entry; it expires so later packets are forwarded.
const pendingFlowLifetime = time.Minute

func (f *tcpFlows) add(client, server netip.AddrPort, established bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.flows == nil {
		f.flows = map[flowKey]flowState{}
	}
	if now.Sub(f.lastPurge) > pendingFlowLifetime {
		f.lastPurge = now
		for k, s := range f.flows {
			if !s.established && now.Sub(s.since) > pendingFlowLifetime {
				delete(f.flows, k)
			}
		}
	}
	key := flowKey{client, server}
	if s, ok := f.flows[key]; ok && s.established && !established {
		return
	}
	f.flows[key] = flowState{established, now}
}
func (f *tcpFlows) remove(client, server netip.AddrPort) {
	f.mu.Lock()
	delete(f.flows, flowKey{client, server})
	f.mu.Unlock()
}
func (f *tcpFlows) has(source, destination netip.AddrPort) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, key := range [2]flowKey{{source, destination}, {destination, source}} {
		if s, ok := f.flows[key]; ok && (s.established || time.Since(s.since) <= pendingFlowLifetime) {
			return true
		}
	}
	return false
}

// captureTCP chooses the carriage per Edge. A connection is terminated here
// only when the Edge toward its destination carries streams; otherwise its
// packets are forwarded as they are. next is empty when not yet routed.
func (r *DataPlane) captureTCP(state *runtimeState, network model.ID, raw []byte, next model.ID) bool {
	tcp := state.tcp[network]
	if tcp == nil {
		return false
	}
	source, destination, flags, ok := packet.TCPFlow(raw)
	if !ok {
		return false
	}
	if tcp.flows.has(source, destination) {
		return true
	}
	if flags&(packet.TCPSyn|packet.TCPAck|packet.TCPRst) != packet.TCPSyn {
		return false
	}
	if next == "" {
		hop, local, err := state.router.NextHop(network, destination.Addr())
		if err != nil || local {
			return false
		}
		next = hop
	}
	if !state.mesh.StreamsAvailable(network, next) {
		return false
	}
	tcp.flows.add(source, destination, false)
	return true
}

// interceptTCP takes transit TCP that should enter a stream on its next Edge.
func (r *DataPlane) interceptTCP(network model.ID, raw []byte, next model.ID) bool {
	state := r.state.Load()
	if state == nil || !r.captureTCP(state, network, raw, next) {
		return false
	}
	state.tcp[network].engine.Inject(raw)
	return true
}

// forwardTCP sends access TCP that stays a packet on its next Edge. Kernel GSO
// packets are split and partial checksums completed first.
func (r *DataPlane) forwardTCP(state *runtimeState, network model.ID, raw []byte, segmentSize int, whole bool) error {
	if whole {
		return state.router.FromTunnel(r.ctx, network, raw)
	}
	mss := 65535
	if segmentSize > 0 {
		if header, ok := packet.TCPHeaderLength(raw); ok && segmentSize > header {
			mss = segmentSize - header
		}
	}
	var segments [][]byte
	err := packet.SegmentTCP(raw, mss, func(segment []byte) error {
		segments = append(segments, segment)
		return nil
	})
	if err != nil {
		return err
	}
	for start := 0; start < len(segments); start += packetbuf.BatchSize {
		err = errors.Join(err, state.router.FromTunnelBatch(r.ctx, network, segments[start:min(start+packetbuf.BatchSize, len(segments))]))
	}
	return err
}

// Endpoint refreshes, MTU changes and live route changes preserve access TCP
// state. Changes to address ownership or access identities invalidate it.
func tcpFingerprint(cfg model.NetworkConfig) string {
	type accessPeer struct {
		Node model.ID
		Edge model.ID
		Key  []byte
	}
	var peers []accessPeer
	for _, p := range cfg.Peers {
		if p.Node.WireGuard != nil {
			peers = append(peers, accessPeer{p.Node.ID, p.Edge.ID, p.PublicKey})
		}
	}
	raw, _ := json.Marshal(struct {
		Self struct {
			ID      model.ID
			Address netip.Addr
			Subnets []model.AdvertisedSubnet
		}
		CIDR      netip.Prefix
		Cipher    model.CipherSuite
		Directory []model.Destination
		Access    []accessPeer
	}{struct {
		ID      model.ID
		Address netip.Addr
		Subnets []model.AdvertisedSubnet
	}{cfg.Self.ID, cfg.Self.Address, cfg.Self.AdvertisedSubnets}, cfg.CIDR, cfg.Cipher, cfg.Directory, peers})
	return string(raw)
}

func (r *DataPlane) newTCP(network model.ID, fingerprint string, mtu int, offload bool) (*runtimeTCP, error) {
	var engine *streamproxy.Engine
	var err error
	output := func(raw []byte) error {
		state := r.state.Load()
		if state == nil || state.tcp[network] == nil || state.tcp[network].engine != engine {
			return net.ErrClosed
		}
		return state.router.TCPOutput(r.ctx, network, raw)
	}
	open := func(ctx context.Context, from, to netip.AddrPort) (streamproxy.Conn, error) {
		state := r.state.Load()
		if state == nil || state.tcp[network] == nil || state.tcp[network].engine != engine {
			return nil, net.ErrClosed
		}
		request, err := state.router.TCPRequest(network, from, to)
		if err != nil {
			return nil, err
		}
		return r.openTCP(ctx, request, "")
	}
	batch := func(packets [][]byte) error {
		state := r.state.Load()
		if state == nil || state.tcp[network] == nil || state.tcp[network].engine != engine {
			return net.ErrClosed
		}
		return state.router.TCPOutputBatch(r.ctx, network, packets)
	}
	if offload {
		engine, err = streamproxy.NewOffloadEngine(r.ctx, mtu, output, open, func(p *stack.PacketBuffer) error {
			state := r.state.Load()
			if state == nil || state.tcp[network] == nil || state.tcp[network].engine != engine {
				return net.ErrClosed
			}
			var destination netip.Addr
			switch p.NetworkProtocolNumber {
			case ipv4.ProtocolNumber:
				destination = netip.AddrFrom4(header.IPv4(p.NetworkHeader().Slice()).DestinationAddress().As4())
			case ipv6.ProtocolNumber:
				destination = netip.AddrFrom16(header.IPv6(p.NetworkHeader().Slice()).DestinationAddress().As16())
			default:
				return forwarding.ErrDestination
			}
			if state.router.TCPOutputLocal(network, destination) != nil {
				// Toward another node over an Edge without streams: send
				// ordinary MTU-sized packets with complete checksums.
				view := p.ToView()
				defer view.Release()
				mss := 65535
				if p.GSOOptions.Type != stack.GSONone && p.GSOOptions.MSS > 0 {
					mss = int(p.GSOOptions.MSS)
				}
				return packet.SegmentTCP(view.AsSlice(), mss, func(segment []byte) error {
					return state.router.TCPOutput(r.ctx, network, segment)
				})
			}
			device := state.devices[network]
			if device == nil || device.failure.Load() != nil {
				return tunnel.ErrUnavailable
			}
			writer, ok := device.Device.(tunnel.TCPPacketWriter)
			if !ok {
				return tunnel.ErrUnavailable
			}
			err := writer.WriteTCPPacket(p)
			if errors.Is(err, tunnel.ErrUnavailable) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				r.failTunnel(network, device, err)
			}
			return err
		})
	} else {
		engine, err = streamproxy.NewEngine(r.ctx, mtu, output, open, batch)
	}
	if err != nil {
		return nil, err
	}
	tcp := &runtimeTCP{engine: engine, fingerprint: fingerprint, offload: offload}
	engine.SetFlowHook(func(from, to netip.AddrPort, open bool) {
		if open {
			tcp.flows.add(from, to, true)
		} else {
			tcp.flows.remove(from, to)
		}
	})
	return tcp, nil
}

func (r *DataPlane) accessPacket(state *runtimeState, ctx context.Context, network model.ID, raw []byte, wireguard bool) error {
	if packet.IsTCP(raw) && state.router.TCPIngress(network, raw, wireguard) == nil && r.captureTCP(state, network, raw, "") {
		state.tcp[network].engine.Inject(raw)
		return nil
	}
	if wireguard {
		return state.router.FromWireGuard(ctx, network, raw)
	}
	return state.router.FromTunnel(ctx, network, raw)
}

func (r *DataPlane) openTCP(ctx context.Context, request streamproxy.Request, ingress model.ID) (streamproxy.Conn, error) {
	state := r.state.Load()
	if state == nil {
		return nil, net.ErrClosed
	}
	next, local, err := state.router.TCPRoute(request, ingress)
	if err != nil {
		return nil, err
	}
	if local || !state.mesh.StreamsAvailable(request.Network, next) {
		// The connection leaves the stream here: either it is delivered on this
		// node, or its next Edge forwards packets. The local stack keeps the tuple.
		tcp := state.tcp[request.Network]
		if tcp == nil {
			return nil, net.ErrClosed
		}
		tcp.flows.add(request.From, request.To, true)
		conn, err := tcp.engine.Dial(ctx, request.From, request.To)
		if err != nil {
			tcp.flows.remove(request.From, request.To)
			return nil, err
		}
		return &flowConn{Conn: conn, done: sync.OnceFunc(func() { tcp.flows.remove(request.From, request.To) })}, nil
	}
	s, err := state.mesh.OpenStream(ctx, request.Network, next)
	if err != nil {
		return nil, err
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
		if response[0] != 0 {
			return errors.New("TCP stream target refused")
		}
		return nil
	})
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// flowConn releases its flow entry when the relay closes the connection.
type flowConn struct {
	streamproxy.Conn
	done func()
}

func (c *flowConn) Close() error {
	err := c.Conn.Close()
	c.done()
	return err
}
func (c *flowConn) Abort() {
	if conn, ok := c.Conn.(interface{ Abort() }); ok {
		conn.Abort()
	}
}

func (r *DataPlane) acceptTCP(parent context.Context, network, remote model.ID, s streamproxy.Conn) {
	ctx, cancel := context.WithTimeout(parent, streamproxy.ConnectTimeout)
	defer cancel()
	var target streamproxy.Conn
	err := streamproxy.During(ctx, s, func() error {
		request, err := streamproxy.ReadRequest(s)
		if err != nil {
			return err
		}
		if request.Network != network {
			return errors.New("stream network disagrees with authenticated channel")
		}
		target, err = r.openTCP(ctx, request, remote)
		if err != nil {
			s.Write([]byte{1})
			return err
		}
		_, err = s.Write([]byte{0})
		return err
	})
	if target != nil {
		defer target.Close()
	}
	if err != nil {
		return
	}
	streamproxy.Relay(parent, s, target)
}
