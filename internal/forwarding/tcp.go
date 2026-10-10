package forwarding

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

// TCPIngress validates local access packets before the userspace TCP stack sees
// them. WireGuard passes its already authenticated source through the same table.
func (r *Router) TCPIngress(networkID model.ID, raw []byte, wireguard bool) error {
	return r.tcpIngress(networkID, raw, len(raw), wireguard)
}

// TCPIngressGSO admits only native access TCP with validated kernel segmentation
// metadata. The MTU still bounds each resulting IP segment; ordinary access and
// WireGuard packets retain their full-packet MTU bound.
func (r *Router) TCPIngressGSO(networkID model.ID, raw []byte, segmentSize int) error {
	if segmentSize <= 0 || segmentSize > len(raw) || len(raw) > 65535 || !packet.IsTCP(raw) {
		return ErrMTU
	}
	return r.tcpIngress(networkID, raw, segmentSize, false)
}

func (r *Router) tcpIngress(networkID model.ID, raw []byte, segmentSize int, wireguard bool) error {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return ErrNetwork
	}
	if segmentSize > n.mtu {
		return ErrMTU
	}
	info, err := packet.InspectAddresses(raw)
	if err != nil {
		return err
	}
	source := n.owner(info.Source)
	if wireguard {
		if n.wireguard[info.Source] == nil {
			return ErrSource
		}
	} else if source == nil || source.id != n.self.ID {
		return ErrSource
	}
	if n.owner(info.Destination) == nil {
		return ErrDestination
	}
	return nil
}

func wireID(id model.ID) (out [16]byte) { hex.Decode(out[:], []byte(id)); return }

// NextHop returns the neighbor that carries traffic to destination, or local
// when this Agent delivers it (its own addresses and attached WireGuard leaves).
func (r *Router) NextHop(networkID model.ID, destination netip.Addr) (next model.ID, local bool, err error) {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return "", false, ErrNetwork
	}
	dest := n.owner(destination)
	if dest == nil {
		return "", false, ErrDestination
	}
	if dest.id == n.self.ID {
		return "", true, nil
	}
	next, ok := n.routes[dest.id]
	if !ok {
		return "", false, ErrUnreachable
	}
	if n.wireguard[dest.address] != nil && next == dest.id {
		return "", true, nil
	}
	return next, false, nil
}

func (r *Router) TCPRequest(networkID model.ID, from, to netip.AddrPort) (streamproxy.Request, error) {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return streamproxy.Request{}, ErrNetwork
	}
	// Access packets were admitted by TCPIngress and transit packets by the
	// peer path, so the source only needs an owner here.
	source, dest := n.owner(from.Addr()), n.owner(to.Addr())
	if source == nil {
		return streamproxy.Request{}, ErrSource
	}
	if dest == nil {
		return streamproxy.Request{}, ErrDestination
	}
	request := streamproxy.Request{Network: networkID, Source: source.id, Destination: dest.id, From: from, To: to, Hops: packet.DefaultHopLimit}
	return request, request.Validate()
}

// TCPRoute uses the same weighted/live table and address ownership as datagrams.
// A WireGuard leaf terminates at its attaching Agent, which emits local TCP to it.
func (r *Router) TCPRoute(request streamproxy.Request, ingress model.ID) (next model.ID, local bool, err error) {
	if err := request.Validate(); err != nil {
		return "", false, err
	}
	n := r.state.Load().networks[request.Network]
	if n == nil {
		return "", false, ErrNetwork
	}
	if ingress != "" && !n.peers[ingress] {
		return "", false, ErrPeer
	}
	source, dest := n.byNode[wireID(request.Source)], n.byNode[wireID(request.Destination)]
	if source == nil || n.owner(request.From.Addr()) != source || ingress != "" && source.id == n.self.ID {
		return "", false, ErrSource
	}
	if dest == nil || n.owner(request.To.Addr()) != dest {
		return "", false, ErrDestination
	}
	if dest.id == n.self.ID {
		return "", true, nil
	}
	next, ok := n.routes[dest.id]
	if !ok {
		return "", false, ErrUnreachable
	}
	if n.wireguard[dest.address] != nil && next == dest.id {
		return "", true, nil
	}
	if request.Hops <= 1 {
		return "", false, packet.ErrHopLimit
	}
	if next == ingress {
		return "", false, ErrUnreachable
	}
	return next, false, nil
}

// TCPOutput sends packets of the local TCP stack. Its connections keep the
// original tuple, so packets toward other nodes leave as transit packets of
// their source's owner, on Edges that do not carry streams.
func (r *Router) TCPOutput(ctx context.Context, networkID model.ID, raw []byte) error {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return ErrNetwork
	}
	info, err := packet.InspectAddresses(raw)
	if err != nil {
		return err
	}
	dest := n.owner(info.Destination)
	if dest == nil {
		return ErrDestination
	}
	if dest.id == n.self.ID {
		return r.deliver(ctx, networkID, raw)
	}
	if n.wireguard[info.Destination] != nil {
		frame, err := (packet.Packet{Header: packet.Header{Network: networkID, Source: n.self.ID, Destination: dest.id, HopLimit: packet.DefaultHopLimit}, Payload: raw}).MarshalBinary()
		if err != nil {
			return err
		}
		return r.send(ctx, networkID, dest.id, frame)
	}
	source := n.owner(info.Source)
	if source == nil {
		return ErrSource
	}
	if len(raw) > n.mtu {
		return ErrMTU
	}
	next, ok := n.routes[dest.id]
	if !ok {
		return ErrUnreachable
	}
	frame, err := (packet.Packet{Header: packet.Header{Network: networkID, Source: source.id, Destination: dest.id, HopLimit: packet.DefaultHopLimit}, Payload: raw}).MarshalBinary()
	if err != nil {
		return err
	}
	return r.send(ctx, networkID, next, frame)
}

// TCPOutputLocal applies the same destination ownership check for packet-buffer
// output, where flattening a host-GSO packet would discard its offload metadata.
func (r *Router) TCPOutputLocal(networkID model.ID, destination netip.Addr) error {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return ErrNetwork
	}
	dest := n.owner(destination)
	if dest == nil || dest.id != n.self.ID {
		return ErrDestination
	}
	return nil
}

// TCPOutputBatch preserves local access packet order and ownership checks while
// allowing the TUN adapter to coalesce consecutive TCP segments with GRO.
// WireGuard access keeps its existing per-packet send path.
func (r *Router) TCPOutputBatch(ctx context.Context, networkID model.ID, packets [][]byte) error {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return ErrNetwork
	}
	var local [packetbuf.BatchSize][]byte
	count := 0
	var result error
	flush := func() {
		if count == 0 {
			return
		}
		if r.deliverBatch != nil {
			result = errors.Join(result, r.deliverBatch(ctx, networkID, local[:count]))
		} else {
			for _, raw := range local[:count] {
				result = errors.Join(result, r.deliver(ctx, networkID, raw))
			}
		}
		clear(local[:count])
		count = 0
	}
	for _, raw := range packets {
		info, err := packet.InspectAddresses(raw)
		if err != nil {
			flush()
			result = errors.Join(result, err)
			continue
		}
		dest := n.owner(info.Destination)
		if dest == nil {
			flush()
			result = errors.Join(result, ErrDestination)
			continue
		}
		if dest.id == n.self.ID {
			local[count] = raw
			count++
			if count == len(local) {
				flush()
			}
			continue
		}
		flush()
		result = errors.Join(result, r.TCPOutput(ctx, networkID, raw))
	}
	flush()
	return result
}
