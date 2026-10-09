package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
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
	fragments   packet.FragmentClassifier
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
		engine, err = streamproxy.NewOffloadEngine(r.ctx, mtu, output, open, func(packet *stack.PacketBuffer) error {
			state := r.state.Load()
			if state == nil || state.tcp[network] == nil || state.tcp[network].engine != engine {
				return net.ErrClosed
			}
			var destination netip.Addr
			switch packet.NetworkProtocolNumber {
			case ipv4.ProtocolNumber:
				destination = netip.AddrFrom4(header.IPv4(packet.NetworkHeader().Slice()).DestinationAddress().As4())
			case ipv6.ProtocolNumber:
				destination = netip.AddrFrom16(header.IPv6(packet.NetworkHeader().Slice()).DestinationAddress().As16())
			default:
				return forwarding.ErrDestination
			}
			if err := state.router.TCPOutputLocal(network, destination); err != nil {
				return err
			}
			device := state.devices[network]
			if device == nil || device.failure.Load() != nil {
				return tunnel.ErrUnavailable
			}
			writer, ok := device.Device.(tunnel.TCPPacketWriter)
			if !ok {
				return tunnel.ErrUnavailable
			}
			err := writer.WriteTCPPacket(packet)
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
	return &runtimeTCP{engine: engine, fingerprint: fingerprint, offload: offload}, nil
}

func (r *DataPlane) accessPacket(state *runtimeState, ctx context.Context, network model.ID, raw []byte, wireguard bool) error {
	if packet.IsTCP(raw) || packet.HasExtensionFragment(raw) {
		if err := state.router.TCPIngress(network, raw, wireguard); err != nil {
			return err
		}
		tcp := state.tcp[network]
		if tcp == nil {
			return net.ErrClosed
		}
		isTCP, packets := tcp.fragments.Classify(raw)
		var result error
		for _, raw := range packets {
			if isTCP {
				tcp.engine.Inject(raw)
			} else if wireguard {
				result = errors.Join(result, state.router.FromWireGuard(ctx, network, raw))
			} else {
				result = errors.Join(result, state.router.FromTunnel(ctx, network, raw))
			}
		}
		return result
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
	if local {
		tcp := state.tcp[request.Network]
		if tcp == nil {
			return nil, net.ErrClosed
		}
		return tcp.engine.Dial(ctx, request.From, request.To)
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
