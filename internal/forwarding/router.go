// Package forwarding routes validated IP packets between TUN devices and peers.
package forwarding

import (
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
)

var (
	ErrNetwork     = errors.New("unknown virtual network")
	ErrSource      = errors.New("packet source is not admitted")
	ErrDestination = errors.New("packet destination is not admitted")
	ErrPeer        = errors.New("packet arrived from an unconfigured neighbor")
	ErrUnreachable = errors.New("no route to destination")
	ErrMTU         = errors.New("packet exceeds network MTU")
	// ErrSealed drops a packet that arrived sealed when it should not be, or
	// not sealed or failing to open when it should be.
	ErrSealed = errors.New("packet failed end-to-end authentication")
	// ErrTCPOverTCP drops a TCP packet whose next Edge sends on a TCP-backed
	// Link; its sender receives a reset.
	ErrTCPOverTCP = errors.New("TCP packet refused: its next Edge carries TCP only as streams")
)

// TCPIntercept may take a transit TCP packet before it is sent to next. It must
// copy raw if it keeps it, and return true only when it consumed the packet.
type TCPIntercept func(network model.ID, raw []byte, next model.ID) bool

// TCPCarrier reports whether the Edge to next sends on a TCP, WS, WSS or gRPC
// Link, which carries TCP only as streams.
type TCPCarrier func(network, next model.ID) bool

// EndToEnd seals the packets this Node sends to other Nodes and opens the
// packets they send it, between end-to-end sessions of the two Nodes: see
// packet.Trailer. Seal takes a non-TCP IP packet with packet.Trailer bytes of
// spare capacity and reports false, leaving it as it is, when the packet
// travels sealed per hop only. Open takes a packet for this Node, sealed or
// not, and returns the IP packet, or an error when it should have been
// sealed and was not, or was and fails to open.
type EndToEnd interface {
	Seal(network, destination model.ID, raw []byte) ([]byte, bool, error)
	Open(network, source model.ID, raw []byte, sealed bool) ([]byte, error)
}

type Send func(context.Context, model.ID, model.ID, []byte) error
type Deliver func(context.Context, model.ID, []byte) error

type BatchOptions struct {
	Send    func(context.Context, model.ID, model.ID, [][]byte) error
	Deliver func(context.Context, model.ID, [][]byte) error
	// SendOwned takes ownership of every buffer even on error; it must not
	// retain the caller's slice. It takes precedence over Send.
	SendOwned func(context.Context, model.ID, model.ID, []*packetbuf.Buffer) error
}

type node struct {
	id      model.ID
	address netip.Addr
	wire    [16]byte
}

type network struct {
	id            model.ID
	header        [packet.HeaderSize]byte
	self          model.Node
	mtu           int
	byAddress     map[netip.Addr]*node
	overlay       netip.Prefix
	subnets       map[netip.Prefix][]exit
	prefixLengths []int
	byNode        map[[16]byte]*node
	wireguard     map[netip.Addr]*node
	peers         map[model.ID]bool
	// routes lists each destination's next hops, lowest Node ID first.
	routes map[model.ID][]model.ID
	costs  map[model.ID]uint64
	ecmp   bool
}

// exit is one Node advertising a prefix.
type exit struct {
	node   *node
	metric uint32
}
type table struct {
	agentID  model.ID
	revision uint64
	networks map[model.ID]*network
	byWire   map[[16]byte]*network
}

// Router swaps immutable forwarding tables atomically. Send chooses the active
// Link of the requested Edge; that choice must never alter the graph edge weight.
// Callbacks must not retain packet buffers unless they copy them.
type Router struct {
	state          atomic.Pointer[table]
	send           Send
	deliver        Deliver
	deliverBatch   func(context.Context, model.ID, [][]byte) error
	sendBatch      func(context.Context, model.ID, model.ID, [][]byte) error
	sendOwnedBatch func(context.Context, model.ID, model.ID, []*packetbuf.Buffer) error
	tcpIntercept   atomic.Pointer[TCPIntercept]
	tcpCarrier     atomic.Pointer[TCPCarrier]
	e2e            atomic.Pointer[EndToEnd]
}

// SetEndToEnd installs or removes (nil) end-to-end sealing.
func (r *Router) SetEndToEnd(e2e EndToEnd) {
	if e2e == nil {
		r.e2e.Store(nil)
		return
	}
	r.e2e.Store(&e2e)
}

// SetTCPCarrier installs or removes (nil) the check that keeps TCP packets
// off TCP-backed Links.
func (r *Router) SetTCPCarrier(carrier TCPCarrier) {
	if carrier == nil {
		r.tcpCarrier.Store(nil)
		return
	}
	r.tcpCarrier.Store(&carrier)
}

func (r *Router) carriesTCP(network, next model.ID) bool {
	carrier := r.tcpCarrier.Load()
	return carrier != nil && (*carrier)(network, next)
}

// refuseTCP drops a TCP packet that would cross a TCP-backed Link and resets
// its sender, so the connection ends instead of running TCP over TCP: through
// the local TCP stack when it owns the connection, to the TUN when the sender
// is local (from is nil), or back toward the source Node from, unless that
// path also starts on a TCP-backed Link.
func (r *Router) refuseTCP(ctx context.Context, n *network, raw []byte, from, to *node) error {
	reset := packet.TCPReset(raw)
	if reset == nil {
		return ErrTCPOverTCP
	}
	if intercept := r.tcpIntercept.Load(); intercept != nil && (*intercept)(n.id, reset, "") {
		return ErrTCPOverTCP
	}
	if from == nil {
		return errors.Join(ErrTCPOverTCP, r.deliver(ctx, n.id, reset))
	}
	next, ok := n.next(from.id, func() uint64 { info, _ := packet.InspectIP(reset); return info.Flow })
	if !ok || r.carriesTCP(n.id, next) {
		return ErrTCPOverTCP
	}
	frame, err := (packet.Packet{Header: packet.Header{Network: n.id, Source: to.id, Destination: from.id, HopLimit: packet.DefaultHopLimit}, Payload: reset}).MarshalBinary()
	if err != nil {
		return errors.Join(ErrTCPOverTCP, err)
	}
	return errors.Join(ErrTCPOverTCP, r.send(ctx, n.id, next, frame))
}

// SetTCPIntercept installs or removes (nil) the transit TCP hook.
func (r *Router) SetTCPIntercept(intercept TCPIntercept) {
	if intercept == nil {
		r.tcpIntercept.Store(nil)
		return
	}
	r.tcpIntercept.Store(&intercept)
}

func New(snapshot model.Snapshot, send Send, deliver Deliver, batches ...BatchOptions) (*Router, error) {
	if send == nil || deliver == nil {
		return nil, errors.New("forwarding callbacks are required")
	}
	router := &Router{send: send, deliver: deliver}
	if len(batches) > 0 {
		router.deliverBatch = batches[0].Deliver
		router.sendBatch = batches[0].Send
		router.sendOwnedBatch = batches[0].SendOwned
	}
	if err := router.Configure(snapshot); err != nil {
		return nil, err
	}
	return router, nil
}
func (r *Router) Configure(snapshot model.Snapshot) error {
	if err := snapshot.Validate(snapshot.AgentID); err != nil {
		return err
	}
	previous := r.state.Load()
	if previous != nil && (previous.agentID != snapshot.AgentID || snapshot.Revision < previous.revision) {
		return errors.New("forwarding table identity change or revision rollback")
	}
	next := &table{agentID: snapshot.AgentID, revision: snapshot.Revision, networks: map[model.ID]*network{}, byWire: map[[16]byte]*network{}}
	for _, config := range snapshot.Networks {
		n := &network{id: config.ID, self: config.Self, mtu: config.MTU, byAddress: map[netip.Addr]*node{}, byNode: map[[16]byte]*node{}, peers: map[model.ID]bool{}, routes: map[model.ID][]model.ID{}, costs: map[model.ID]uint64{}, ecmp: config.EqualCostPaths == model.EqualCostECMP}
		// Snapshot validation above is the sole place where IDs need checking.
		header, err := (packet.Packet{Header: packet.Header{Network: config.ID, Source: config.Self.ID, Destination: config.Self.ID, HopLimit: packet.DefaultHopLimit, Epoch: snapshot.Revision}, Payload: []byte{0}}).MarshalBinary()
		if err != nil {
			return err
		}
		copy(n.header[:], header)
		next.byWire[[16]byte(header[8:24])] = n
		n.overlay = config.CIDR
		n.subnets = map[netip.Prefix][]exit{}
		lengths := map[int]bool{}
		for _, dest := range config.Directory {
			entry := &node{id: dest.NodeID, address: dest.Address}
			if _, err := hex.Decode(entry.wire[:], []byte(dest.NodeID)); err != nil {
				return err
			}
			n.byAddress[dest.Address] = entry
			n.byNode[entry.wire] = entry
			for _, subnet := range dest.AdvertisedSubnets {
				n.subnets[subnet.Prefix] = append(n.subnets[subnet.Prefix], exit{entry, subnet.Metric})
				lengths[subnet.Prefix.Bits()] = true
			}
		}
		for _, exits := range n.subnets {
			slices.SortFunc(exits, func(a, b exit) int { return cmp.Compare(a.node.id, b.node.id) })
		}
		for bits := range lengths {
			n.prefixLengths = append(n.prefixLengths, bits)
		}
		slices.Sort(n.prefixLengths)
		slices.Reverse(n.prefixLengths)
		n.wireguard = map[netip.Addr]*node{}
		for _, peer := range config.Peers {
			if peer.Node.WireGuard != nil {
				n.wireguard[peer.Node.Address] = n.byAddress[peer.Node.Address]
			}
			n.peers[peer.Node.ID] = true
		}
		for _, route := range config.Routes {
			n.routes[route.Destination] = append([]model.ID{route.NextHop}, route.Alternates...)
			n.costs[route.Destination] = route.Cost
		}
		next.networks[config.ID] = n
	}
	// Configuration application has one owner. CAS detects accidental competing
	// reconcilers instead of silently publishing an older table after a newer one.
	if !r.state.CompareAndSwap(previous, next) {
		return errors.New("concurrent forwarding table update")
	}
	return nil
}

func (r *Router) FromTunnel(ctx context.Context, networkID model.ID, raw []byte) error {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return ErrNetwork
	}
	buffer, nextHop, err := r.encapsulate(ctx, n, raw)
	if err != nil || buffer == nil {
		return err
	}
	defer buffer.Release()
	return r.send(ctx, networkID, nextHop, buffer.Data)
}

// FromTunnelBatch preserves immediately available TUN bursts across routing and
// enqueue. Only consecutive frames for the same next hop are grouped. Invalid
// packets are dropped independently, and callbacks borrow storage until return.
func (r *Router) FromTunnelBatch(ctx context.Context, networkID model.ID, packets [][]byte) error {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return ErrNetwork
	}
	var owners [packetbuf.BatchSize]*packetbuf.Buffer
	var frames [packetbuf.BatchSize][]byte
	var nextHop model.ID
	count := 0
	var result error
	flush := func() {
		if count == 0 {
			return
		}
		if r.sendOwnedBatch != nil {
			result = errors.Join(result, r.sendOwnedBatch(ctx, networkID, nextHop, owners[:count]))
		} else if r.sendBatch != nil {
			result = errors.Join(result, r.sendBatch(ctx, networkID, nextHop, frames[:count]))
		} else {
			for _, frame := range frames[:count] {
				result = errors.Join(result, r.send(ctx, networkID, nextHop, frame))
			}
		}
		if r.sendOwnedBatch == nil {
			packetbuf.ReleaseAll(owners[:count])
		}
		clear(owners[:count])
		clear(frames[:count])
		count = 0
	}
	for _, raw := range packets {
		buffer, hop, err := r.encapsulate(ctx, n, raw)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if buffer == nil {
			continue
		}
		if count == len(frames) || hop != nextHop {
			flush()
		}
		nextHop = hop
		owners[count], frames[count] = buffer, buffer.Data
		count++
	}
	flush()
	return result
}

func (r *Router) encapsulate(ctx context.Context, n *network, raw []byte) (*packetbuf.Buffer, model.ID, error) {
	return r.encapsulateSource(ctx, n, raw, nil)
}
func (r *Router) encapsulateSource(ctx context.Context, n *network, raw []byte, client *node) (*packetbuf.Buffer, model.ID, error) {
	if len(raw) > n.mtu {
		return nil, "", ErrMTU
	}
	info, err := packet.InspectIP(raw)
	if err != nil {
		return nil, "", err
	}
	if client != nil {
		if info.Source != client.address {
			return nil, "", ErrSource
		}
	} else if info.Source != n.self.Address && !n.admits(n.byAddress[n.self.Address], info.Source) {
		return nil, "", ErrSource
	}
	flow := func() uint64 { return info.Flow }
	destination := n.exit(info.Destination, flow)
	if destination == nil {
		return nil, "", ErrDestination
	}
	if destination.id == n.self.ID {
		return nil, "", r.deliver(ctx, n.id, raw)
	}
	nextHop, ok := n.next(destination.id, flow)
	if !ok {
		return nil, "", ErrUnreachable
	}
	if packet.IsTCP(raw) && r.carriesTCP(n.id, nextHop) {
		if client != nil {
			return nil, "", ErrTCPOverTCP
		}
		return nil, "", r.refuseTCP(ctx, n, raw, nil, nil)
	}
	if client != nil && packet.IPHopLimit(raw) <= 1 {
		return nil, "", r.timeExceeded(ctx, n, raw)
	}
	// Room for a Link's two-byte prefix of a sealed frame, and the trailer.
	buffer := packetbuf.GetHeadroom(packet.HeaderSize+len(raw)+packet.Trailer, 2)
	frame := buffer.Data[:packet.HeaderSize+len(raw)]
	copy(frame, n.header[:])
	if client != nil {
		copy(frame[24:40], client.wire[:])
	}
	copy(frame[40:56], destination.wire[:])
	binary.BigEndian.PutUint64(frame[64:72], info.Flow)
	copy(frame[packet.HeaderSize:], raw)
	if client != nil {
		packet.DecrementIPHopLimit(frame[packet.HeaderSize:])
	} else if e2e := r.e2e.Load(); e2e != nil && !packet.IsTCP(raw) {
		sealed, ok, err := (*e2e).Seal(n.id, destination.id, frame[packet.HeaderSize:])
		if err != nil {
			buffer.Release()
			return nil, "", err
		}
		if ok {
			frame = frame[:packet.HeaderSize+len(sealed)]
			packet.SetSealed(frame, true)
		}
	}
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(frame)-packet.HeaderSize))
	buffer.Data = frame
	return buffer, nextHop, nil
}

// FromPeer must receive the Node ID authenticated by the peer Channel, never an
// unauthenticated ID read from the packet itself. Transit Nodes are trusted hop
// forwarders; the IP/Node directory check is admission, not end-to-end signing.
func (r *Router) FromPeer(ctx context.Context, peerID model.ID, frame []byte) error {
	return r.fromPeer(ctx, peerID, frame, r.deliver, nil)
}

// FromPeerOwnedBatch takes ownership of every buffer. A transit frame is
// forwarded in its own buffer, its hop limits decremented in place; local
// packets are delivered in batches as FromPeerBatch does.
func (r *Router) FromPeerOwnedBatch(ctx context.Context, peerID model.ID, owners []*packetbuf.Buffer) error {
	var result error
	var deliverNetwork model.ID
	var packets [packetbuf.BatchSize][]byte
	delivered := 0
	flushDeliver := func() {
		if delivered == 0 {
			return
		}
		if r.deliverBatch != nil {
			result = errors.Join(result, r.deliverBatch(ctx, deliverNetwork, packets[:delivered]))
		} else {
			for _, raw := range packets[:delivered] {
				result = errors.Join(result, r.deliver(ctx, deliverNetwork, raw))
			}
		}
		clear(packets[:delivered])
		delivered = 0
	}
	deliver := func(_ context.Context, id model.ID, raw []byte) error {
		if id != deliverNetwork || delivered == len(packets) {
			flushDeliver()
		}
		deliverNetwork = id
		packets[delivered] = raw
		delivered++
		return nil
	}
	var sendNetwork, sendHop model.ID
	var sends [packetbuf.BatchSize]*packetbuf.Buffer
	sending := 0
	flushSend := func() {
		if sending == 0 {
			return
		}
		if r.sendOwnedBatch != nil {
			result = errors.Join(result, r.sendOwnedBatch(ctx, sendNetwork, sendHop, sends[:sending]))
		} else {
			for _, b := range sends[:sending] {
				result = errors.Join(result, r.send(ctx, sendNetwork, sendHop, b.Data))
				b.Release()
			}
		}
		clear(sends[:sending])
		sending = 0
	}
	current := 0
	forward := func(network, next model.ID) {
		if network != sendNetwork || next != sendHop || sending == len(sends) {
			flushSend()
		}
		sendNetwork, sendHop = network, next
		sends[sending], owners[current] = owners[current], nil
		sending++
	}
	for i, owner := range owners {
		current = i
		result = errors.Join(result, r.fromPeer(ctx, peerID, owner.Data, deliver, forward))
	}
	flushSend()
	flushDeliver()
	for i, owner := range owners {
		owner.Release()
		owners[i] = nil
	}
	return result
}

// FromPeerBatch validates every frame independently. Only admitted local
// packets are batched; transit retains the normal hop-limit and routing checks.
func (r *Router) FromPeerBatch(ctx context.Context, peerID model.ID, frames [][]byte) error {
	var networkID model.ID
	var packets [packetbuf.BatchSize][]byte
	count := 0
	var result error
	flush := func() {
		if count == 0 {
			return
		}
		if r.deliverBatch != nil {
			result = errors.Join(result, r.deliverBatch(ctx, networkID, packets[:count]))
		} else {
			for _, raw := range packets[:count] {
				result = errors.Join(result, r.deliver(ctx, networkID, raw))
			}
		}
		clear(packets[:count])
		count = 0
	}
	deliver := func(_ context.Context, id model.ID, raw []byte) error {
		if id != networkID || count == len(packets) {
			flush()
		}
		networkID = id
		packets[count] = raw
		count++
		return nil
	}
	for _, frame := range frames {
		result = errors.Join(result, r.fromPeer(ctx, peerID, frame, deliver, nil))
	}
	flush()
	return result
}

// fromPeer forwards a transit frame with forward when the caller owns frame:
// its hop limits are then decremented in place. Otherwise it sends a copy.
func (r *Router) fromPeer(ctx context.Context, peerID model.ID, frame []byte, deliver Deliver, forward func(network, next model.ID)) error {
	p, err := packet.ParseView(frame)
	if err != nil {
		return err
	}
	current := r.state.Load()
	n := current.byWire[p.Network]
	if n == nil {
		return ErrNetwork
	}
	if !n.peers[peerID] {
		return ErrPeer
	}
	raw, ok := packet.IPOf(p.Payload, p.Sealed)
	if !ok {
		return ErrSealed
	}
	if len(raw) > n.mtu {
		return ErrMTU
	}
	source, ok := n.byNode[p.Source]
	if !ok || source.id == n.self.ID {
		return ErrSource
	}
	destination, ok := n.byNode[p.Destination]
	if !ok {
		return ErrDestination
	}
	info, err := packet.InspectAddresses(raw)
	if err != nil {
		return err
	}
	if info.Source != source.address && !n.admits(source, info.Source) {
		return ErrSource
	}
	if info.Destination != destination.address && !n.admits(destination, info.Destination) {
		return ErrDestination
	}
	if p.Sealed && packet.IsTCP(raw) {
		// TCP is sealed per hop only.
		return ErrSealed
	}
	if destination.id == n.self.ID {
		if e2e := r.e2e.Load(); e2e != nil {
			if raw, err = (*e2e).Open(n.id, source.id, p.Payload, p.Sealed); err != nil {
				return err
			}
		} else if p.Sealed {
			return ErrSealed
		}
		return deliver(ctx, n.id, raw)
	}
	if p.HopLimit <= 1 {
		return packet.ErrHopLimit
	}
	nextHop, ok := n.next(destination.id, func() uint64 { flow, _ := packet.InspectIP(raw); return flow.Flow })
	if !ok {
		return ErrUnreachable
	}
	if nextHop == peerID {
		return fmt.Errorf("route would return packet to ingress neighbor")
	}
	if intercept := r.tcpIntercept.Load(); intercept != nil && packet.IsTCP(raw) && (*intercept)(n.id, raw, nextHop) {
		return nil
	}
	if packet.IsTCP(raw) && r.carriesTCP(n.id, nextHop) {
		return r.refuseTCP(ctx, n, raw, source, destination)
	}
	if packet.IPHopLimit(raw) <= 1 {
		return r.timeExceeded(ctx, n, raw)
	}
	if forward != nil {
		frame[3]--
		packet.DecrementIPHopLimit(frame[packet.HeaderSize:])
		forward(n.id, nextHop)
		return nil
	}
	// Keep the caller's authenticated frame immutable, including its IP header.
	buffer := packetbuf.Get(len(frame))
	defer buffer.Release()
	copy(buffer.Data, frame)
	buffer.Data[3]--
	packet.DecrementIPHopLimit(buffer.Data[packet.HeaderSize:])
	return r.send(ctx, n.id, nextHop, buffer.Data)
}

func (r *Router) timeExceeded(ctx context.Context, n *network, raw []byte) error {
	reply := packet.TimeExceeded(raw, n.self.Address)
	if reply == nil {
		return nil
	}
	buffer, hop, err := r.encapsulate(ctx, n, reply)
	if err != nil || buffer == nil {
		return err
	}
	defer buffer.Release()
	return r.send(ctx, n.id, hop, buffer.Data)
}

// CompactHeader rebuilds the header a compact Link omitted. Source and
// destination are the owners of the inner addresses: the only Nodes fromPeer
// admits for them, so the expanded frame still passes every FromPeer check.
func (r *Router) CompactHeader(header []byte, networkWire [16]byte, hopLimit uint8, payload []byte) bool {
	n := r.state.Load().byWire[networkWire]
	if n == nil {
		return false
	}
	info, err := packet.InspectAddresses(payload)
	if err != nil {
		return false
	}
	source := n.sourceOwner(info.Source)
	destination := n.exit(info.Destination, func() uint64 { flow, _ := packet.InspectIP(payload); return flow.Flow })
	if source == nil || destination == nil {
		return false
	}
	packet.PutHeader(header, networkWire, source.wire, destination.wire, hopLimit, len(payload))
	return true
}

// advertisers returns the Nodes advertising the longest prefix that matches
// ip, without allocations. Overlay addresses never match a prefix, including
// /0, and loopback, multicast and link-local addresses never leave.
func (n *network) advertisers(ip netip.Addr) []exit {
	if n.overlay.Contains(ip) || !ip.IsGlobalUnicast() {
		return nil
	}
	for _, bits := range n.prefixLengths {
		if bits > ip.BitLen() {
			continue
		}
		if exits := n.subnets[netip.PrefixFrom(ip, bits).Masked()]; exits != nil {
			return exits
		}
	}
	return nil
}

// exit chooses the Node that receives traffic to ip: the overlay host, or the
// advertiser of the longest matching prefix with the lowest path cost plus
// metric. A tie goes to the lowest Node ID, or with ECMP to the flow's hash;
// flow is called only then. Unreachable advertisers are skipped; when none is
// reachable traffic drops rather than using a shorter prefix.
func (n *network) exit(ip netip.Addr, flow func() uint64) *node {
	if host := n.byAddress[ip]; host != nil {
		return host
	}
	exits := n.advertisers(ip)
	switch len(exits) {
	case 0:
		return nil
	case 1:
		return exits[0].node
	}
	best, reachable := ^uint64(0), false
	for _, e := range exits {
		if cost, ok := n.exitCost(e); ok && cost < best {
			best, reachable = cost, true
		}
	}
	if !reachable {
		return exits[0].node // next hop lookup reports it unreachable
	}
	ties := uint64(0)
	for _, e := range exits {
		if cost, ok := n.exitCost(e); ok && cost == best {
			ties++
		}
	}
	pick := uint64(0)
	if ties > 1 && n.ecmp {
		pick = flow() % ties
	}
	// Exits are in Node ID order, so pick 0 is the lowest ID.
	for _, e := range exits {
		if cost, ok := n.exitCost(e); ok && cost == best {
			if pick == 0 {
				return e.node
			}
			pick--
		}
	}
	return nil
}

func (n *network) exitCost(e exit) (uint64, bool) {
	if e.node.id == n.self.ID {
		return uint64(e.metric), true
	}
	cost, ok := n.costs[e.node.id]
	return cost + uint64(e.metric), ok
}

// admits reports whether candidate may send or receive traffic for ip: it is
// the overlay host, or it advertises a prefix containing ip. Each hop chooses
// its own exit, so a transit Node need not agree with the ingress's choice.
func (n *network) admits(candidate *node, ip netip.Addr) bool {
	if candidate == nil {
		return false
	}
	if host := n.byAddress[ip]; host != nil {
		return host == candidate
	}
	if n.overlay.Contains(ip) || !ip.IsGlobalUnicast() {
		return false
	}
	for _, bits := range n.prefixLengths {
		if bits > ip.BitLen() {
			continue
		}
		for _, e := range n.subnets[netip.PrefixFrom(ip, bits).Masked()] {
			if e.node == candidate {
				return true
			}
		}
	}
	return false
}

// sourceOwner names a source Node for a header a compact Link omitted: the
// overlay host, or an advertiser of the longest matching prefix other than
// this Node, which never receives its own traffic from a peer.
func (n *network) sourceOwner(ip netip.Addr) *node {
	if host := n.byAddress[ip]; host != nil {
		return host
	}
	var self *node
	for _, e := range n.advertisers(ip) {
		if e.node.id != n.self.ID {
			return e.node
		}
		self = e.node
	}
	return self
}

// next returns the next hop toward destination: the lowest Node ID, or with
// ECMP one of the equal-cost hops by the flow's hash.
func (n *network) next(destination model.ID, flow func() uint64) (model.ID, bool) {
	hops := n.routes[destination]
	switch {
	case len(hops) == 0:
		return "", false
	case len(hops) == 1 || !n.ecmp:
		return hops[0], true
	}
	return hops[flow()%uint64(len(hops))], true
}

// FromWireGuard accepts plaintext only after WireGuard authenticates the peer
// and enforces its /32 or /128 AllowedIP. The active snapshot checks it again.
func (r *Router) FromWireGuard(ctx context.Context, networkID model.ID, raw []byte) error {
	n := r.state.Load().networks[networkID]
	if n == nil {
		return ErrNetwork
	}
	info, err := packet.InspectAddresses(raw)
	if err != nil {
		return err
	}
	client := n.wireguard[info.Source]
	if client == nil {
		return ErrSource
	}
	buffer, hop, err := r.encapsulateSource(ctx, n, raw, client)
	if err != nil || buffer == nil {
		return err
	}
	defer buffer.Release()
	return r.send(ctx, networkID, hop, buffer.Data)
}
