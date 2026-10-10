package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"github.com/eWloYW8/GraphWAN/internal/tunnel"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// kernelTUN simulates application TCP through the actual Agent TUN API. The
// application and GraphWAN have independent TCP sequence/congestion state.
type kernelTUN struct {
	config   tunnel.Config
	stack    *stack.Stack
	link     *channel.Endpoint
	ctx      context.Context
	cancel   context.CancelFunc
	packets  chan kernelPacket
	writes   atomic.Uint64
	batches  atomic.Uint64
	gsos     atomic.Uint64
	readGSOs atomic.Uint64
	once     sync.Once
}

type kernelPacket struct {
	raw         []byte
	segmentSize int
}

func newKernelTUN(config tunnel.Config, offload ...bool) (*kernelTUN, error) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &kernelTUN{config: config, ctx: ctx, cancel: cancel, packets: make(chan kernelPacket, 4096)}
	d.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	d.link = channel.New(4096, uint32(config.MTU), "")
	if len(offload) > 0 && offload[0] {
		d.link.SupportedGSOKind = stack.HostGSOSupported
	}
	if err := d.stack.CreateNIC(1, d.link); err != nil {
		d.Close()
		return nil, errors.New(err.String())
	}
	a, protocol := applicationAddress(config.Address.Addr())
	if err := d.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddressWithPrefix{Address: a, PrefixLen: config.Address.Bits()}}, stack.AddressProperties{}); err != nil {
		d.Close()
		return nil, errors.New(err.String())
	}
	d.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	go func() {
		for {
			p := d.link.ReadContext(ctx)
			if p == nil {
				return
			}
			view := p.ToView()
			raw := append([]byte(nil), view.AsSlice()...)
			view.Release()
			completeKernelChecksum(raw, p)
			segmentSize := 0
			if p.GSOOptions.Type != stack.GSONone && p.Data().Size() > int(p.GSOOptions.MSS) {
				segmentSize = p.HeaderSize() + int(p.GSOOptions.MSS)
			}
			p.DecRef()
			select {
			case d.packets <- kernelPacket{raw, segmentSize}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return d, nil
}
func (d *kernelTUN) Read(p []byte) (int, error) {
	select {
	case packet := <-d.packets:
		if len(packet.raw) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet.raw), nil
	case <-d.ctx.Done():
		return 0, net.ErrClosed
	}
}
func (d *kernelTUN) Write(p []byte) (int, error) {
	d.writes.Add(1)
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), p...))})
	protocol := ipv4.ProtocolNumber
	if p[0]>>4 == 6 {
		protocol = ipv6.ProtocolNumber
	}
	d.link.InjectInbound(protocol, packet)
	packet.DecRef()
	return len(p), nil
}

func (d *kernelTUN) BatchSize() int { return packetbuf.BatchSize }
func (d *kernelTUN) ReadBatch(buffers [][]byte, sizes []int) (int, error) {
	n, err := d.Read(buffers[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	count := 1
	for count < len(buffers) {
		select {
		case packet := <-d.packets:
			sizes[count] = copy(buffers[count], packet.raw)
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

func (d *kernelTUN) ReadOffloadBatch(buffers [][]byte, sizes, segmentSizes []int) (int, error) {
	clear(segmentSizes)
	select {
	case packet := <-d.packets:
		if len(packet.raw) > len(buffers[0]) {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(buffers[0], packet.raw)
		segmentSizes[0] = packet.segmentSize
		if packet.segmentSize > 0 {
			d.readGSOs.Add(1)
		}
		return 1, nil
	case <-d.ctx.Done():
		return 0, net.ErrClosed
	}
}

func (d *kernelTUN) ReadOwnedOffloadBatch(buffers [][]byte, sizes, segmentSizes []int, owners []*stack.PacketBuffer) (int, error) {
	n, err := d.ReadOffloadBatch(buffers, sizes, segmentSizes)
	if err != nil {
		return n, err
	}
	for i := range n {
		raw := buffers[i][:sizes[i]]
		if !packet.IsTCP(raw) || packet.HasExtensionFragment(raw) {
			continue
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
		p.NetworkProtocolNumber = ipv4.ProtocolNumber
		if raw[0]>>4 == 6 {
			p.NetworkProtocolNumber = ipv6.ProtocolNumber
		}
		p.RXChecksumValidated = true
		// Kernel CHECKSUM_PARTIAL does not contain a complete TCP checksum.
		// Corrupt the checksum deliberately so NIC flag normalization cannot
		// silently turn this integration test into a software-checksum test.
		start := 20
		if raw[0]>>4 == 6 {
			start = 40
		}
		if len(raw) >= start+20 {
			data := p.AsSlices()[0]
			data[start+16] ^= 0xff
		}
		owners[i] = p
	}
	return n, nil
}
func (d *kernelTUN) WriteBatch(packets [][]byte) error {
	d.batches.Add(1)
	for _, p := range packets {
		if _, err := d.Write(p); err != nil {
			return err
		}
	}
	return nil
}

func (d *kernelTUN) WriteTCPPacket(p *stack.PacketBuffer) error {
	d.batches.Add(1)
	d.writes.Add(1)
	if p.GSOOptions.Type != stack.GSONone && p.Data().Size() > int(p.GSOOptions.MSS) {
		d.gsos.Add(1)
	}
	view := p.ToView()
	raw := append([]byte(nil), view.AsSlice()...)
	view.Release()
	completeKernelChecksum(raw, p)
	incoming := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	d.link.InjectInbound(p.NetworkProtocolNumber, incoming)
	incoming.DecRef()
	return nil
}

func completeKernelChecksum(raw []byte, p *stack.PacketBuffer) {
	// Complete the checksum as a kernel TUN does for CHECKSUM_PARTIAL.
	if p.GSOOptions.NeedsCsum {
		start := int(p.GSOOptions.L3HdrLen)
		var source, destination tcpip.Address
		if raw[0]>>4 == 4 {
			source, destination = header.IPv4(raw).SourceAddress(), header.IPv4(raw).DestinationAddress()
		} else {
			source, destination = header.IPv6(raw).SourceAddress(), header.IPv6(raw).DestinationAddress()
		}
		tcpHeader := header.TCP(raw[start:])
		tcpHeader.SetChecksum(0)
		pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, source, destination, uint16(len(raw)-start))
		tcpHeader.SetChecksum(^checksum.Checksum(raw[start:], pseudo))
	}
}
func (d *kernelTUN) Name() string                 { return "memory-tun" }
func (d *kernelTUN) Configuration() tunnel.Config { return d.config }
func (d *kernelTUN) Close() error {
	d.once.Do(func() {
		d.cancel()
		d.stack.Close()
		for _, ep := range d.stack.CleanupEndpoints() {
			ep.Abort()
		}
		d.link.Close()
	})
	return nil
}

func applicationAddress(addr netip.Addr) (tcpip.Address, tcpip.NetworkProtocolNumber) {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4()), ipv4.ProtocolNumber
	}
	return tcpip.AddrFrom16(addr.As16()), ipv6.ProtocolNumber
}

func streamAgents(t *testing.T, carrier model.Transport, configure ...func(*model.State)) ([3]*DataPlane, [3]*kernelTUN, model.State) {
	t.Helper()
	state := testutil.Topology()
	state.Agents = state.Agents[:3]
	state.Networks[0].Nodes = state.Networks[0].Nodes[:3]
	state.Networks[0].Edges = state.Networks[0].Edges[:2]
	for i := range state.Agents {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		listener.Close()
		state.Agents[i].ListenPort = port
		state.Agents[i].Endpoints = []model.Endpoint{{ID: testutil.ID(30 + i), Transport: carrier, Source: model.Manual, URL: fmt.Sprintf("%s://127.0.0.1:%d", carrier, port)}}
	}
	for i := range state.Networks[0].Edges {
		state.Networks[0].Edges[i].Transports = []model.Transport{carrier}
	}
	for _, configure := range configure {
		configure(&state)
	}
	var agents [3]*DataPlane
	var devices [3]*kernelTUN
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for i := range agents {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		configured := DataPlaneOptions{}
		configured.BindHost = "127.0.0.1"
		configured.TunnelFactory = func(cfg tunnel.Config) (tunnel.Device, error) {
			device, err := newKernelTUN(cfg, true)
			devices[i] = device
			return device, err
		}
		agent, err := NewDataPlane(ctx, ed25519.NewKeyFromSeed(seed), configured)
		if err != nil {
			t.Fatal(err)
		}
		agents[i] = agent
		t.Cleanup(func() { agent.Close() })
		snapshot, err := routing.Compile(state, state.Agents[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := agent.Apply(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	// Each Edge chooses streams or packets when a connection starts. Start
	// after every Edge has a healthy Link and, where offered, stream support.
	deadline := time.Now().Add(30 * time.Second)
	for {
		ready := true
		for _, agent := range agents {
			current := agent.state.Load()
			for _, network := range current.snapshot.Networks {
				for _, peer := range network.Peers {
					if peer.Node.WireGuard != nil {
						continue
					}
					found := false
					for _, status := range agent.Report() {
						if status.EdgeID == peer.Edge.ID && status.Healthy {
							found = true
						}
					}
					ready = ready && found
					if streamCarrier(carrier) {
						ready = ready && current.mesh.StreamsAvailable(network.ID, peer.Node.ID)
					}
				}
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer links did not become ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return agents, devices, state
}

func TestTCPStreamsAcrossGraph(t *testing.T) {
	for _, carrier := range []model.Transport{model.TCP, model.QUIC, model.WS, model.WSS, model.GRPC} {
		t.Run(string(carrier), func(t *testing.T) {
			_, devices, state := streamAgents(t, carrier)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			target := state.Networks[0].Nodes[2].Address
			listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8080}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			payload := bytes.Repeat([]byte("TCP bytes through A-B-C with backpressure\n"), 64*1024)
			if testing.Short() {
				payload = payload[:80*1024]
			}
			digest := sha256.Sum256(payload)
			serverErr := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				if conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr() != state.Networks[0].Nodes[0].Address {
					serverErr <- errors.New("source address changed")
					return
				}
				raw, err := io.ReadAll(conn)
				if err == nil && !bytes.Equal(raw, payload) {
					err = errors.New("stream bytes changed")
				}
				if err == nil {
					_, err = conn.Write(digest[:])
				}
				if err == nil {
					err = conn.(*gonet.TCPConn).CloseWrite()
				}
				serverErr <- err
			}()
			conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8080}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(response, digest[:]) {
				t.Fatalf("response after request EOF: %x, %v", response, err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if count := devices[1].writes.Load(); count != 0 {
				t.Fatalf("transit TCP escaped to TUN: %d packets", count)
			}
			if devices[0].batches.Load() == 0 || devices[2].batches.Load() == 0 {
				t.Fatal("TCP access bypassed the TUN batch interface")
			}
			if streamCarrier(carrier) && devices[2].gsos.Load() == 0 {
				t.Fatal("native access TCP bypassed host segmentation offload")
			}
			if devices[0].readGSOs.Load() == 0 {
				t.Fatal("native access TCP was split before stack ingress")
			}
		})
	}
}

// streamCarrier reports transports whose Links carry streams; QUIC Links
// carry datagrams, and UDP is unreliable.
func streamCarrier(carrier model.Transport) bool {
	return carrier == model.TCP || carrier == model.WS || carrier == model.WSS || carrier == model.GRPC
}

// Edges without stream support forward TCP as packets, end to end.
func TestTCPPacketsOnEdgesWithoutStreams(t *testing.T) {
	agents, devices, state := streamAgents(t, model.UDP)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("TCP packets over UDP Links\n"), 8*1024)
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		raw, _ := io.ReadAll(conn)
		received <- raw
	}()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if raw := <-received; !bytes.Equal(raw, payload) {
		t.Fatal("TCP bytes changed over UDP Links")
	}
	network := state.Networks[0].ID
	for i, agent := range agents {
		agent.state.Load().tcp[network].flows.mu.Lock()
		owned := len(agent.state.Load().tcp[network].flows.flows)
		agent.state.Load().tcp[network].flows.mu.Unlock()
		if owned != 0 {
			t.Fatalf("agent %d terminated TCP on Edges without streams", i)
		}
	}
}

func transferApplication(t *testing.T, source, destination *kernelTUN, target netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	address, protocol := applicationAddress(target)
	listener, err := gonet.ListenTCP(destination.stack, tcpip.FullAddress{NIC: 1, Addr: address, Port: 8081}, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("bidirectional application bytes"), 100000)
	if testing.Short() {
		payload = payload[:80*1024]
	}
	serverErr := make(chan error, 1)
	seen := make(chan netip.AddrPort, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		seen <- conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		raw, err := io.ReadAll(conn)
		if err == nil && !bytes.Equal(raw, payload) {
			err = errors.New("stream payload changed")
		}
		if err == nil {
			_, err = conn.Write([]byte("complete response"))
		}
		if err == nil {
			err = conn.(*gonet.TCPConn).CloseWrite()
		}
		serverErr <- err
	}()
	conn, err := gonet.DialContextTCP(ctx, source.stack, tcpip.FullAddress{NIC: 1, Addr: address, Port: 8081}, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if observed := <-seen; observed != conn.LocalAddr().(*net.TCPAddr).AddrPort() {
		t.Fatalf("TCP source tuple changed: %s", observed)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil || string(raw) != "complete response" {
		t.Fatal(string(raw), err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestTCPStreamsOnOneWayReachableEdge(t *testing.T) {
	for _, carrier := range []model.Transport{model.TCP, model.QUIC, model.GRPC} {
		t.Run(string(carrier), func(t *testing.T) {
			agents, devices, state := streamAgents(t, carrier, func(s *model.State) { s.Agents[2].Endpoints = nil })
			transferApplication(t, devices[0], devices[2], state.Networks[0].Nodes[2].Address)
			if devices[1].writes.Load() != 0 {
				t.Fatal("stream used transit TUN")
			}
			var tx uint64
			for _, l := range agents[0].Report() {
				tx += l.TXBytes
			}
			if tx < 80*1024 {
				t.Fatalf("stream traffic missing from link telemetry: %d", tx)
			}
		})
	}
}

func TestTCPIPv6AndConfigurationRefresh(t *testing.T) {
	agents, devices, state := streamAgents(t, model.TCP, func(s *model.State) {
		s.Networks[0].CIDR = netip.MustParsePrefix("fd00:42::/64")
		for i := range s.Networks[0].Nodes {
			s.Networks[0].Nodes[i].Address = netip.MustParseAddr(fmt.Sprintf("fd00:42::%d", i+1))
		}
	})
	previous := agents[0].state.Load().tcp[state.Networks[0].ID]
	state.Revision++
	state.Networks[0].Nodes[0].Name = "renamed access node"
	snapshot, err := routing.Compile(state, state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := agents[0].Apply(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if agents[0].state.Load().tcp[state.Networks[0].ID] != previous {
		t.Fatal("display/config refresh replaced TCP state")
	}
	transferApplication(t, devices[0], devices[2], state.Networks[0].Nodes[2].Address)
}

func TestTCPWireGuardAccessBoundary(t *testing.T) {
	for _, sourceLeaf := range []bool{false, true} {
		t.Run(fmt.Sprintf("source_leaf_%v", sourceLeaf), func(t *testing.T) {
			gatewayIndex := 2
			if sourceLeaf {
				gatewayIndex = 0
			}
			leafID := testutil.ID(80)
			leafAddress := netip.MustParseAddr("10.42.0.10")
			agents, devices, state := streamAgents(t, model.TCP, func(s *model.State) {
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				n := &s.Networks[0]
				n.Nodes = append(n.Nodes, model.Node{ID: leafID, Name: "WG access", Address: leafAddress, WireGuard: &model.WireGuardNode{PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}})
				n.Edges = append(n.Edges, model.Edge{ID: testutil.ID(81), A: n.Nodes[gatewayIndex].ID, B: leafID, Weight: 1, Enabled: true, Transports: []model.Transport{model.WireGuard}, Methods: model.ConnectionMethods{IPv4Direct: true}})
			})
			leaf, err := newKernelTUN(tunnel.Config{Address: netip.PrefixFrom(leafAddress, 24), MTU: model.DefaultMTU})
			if err != nil {
				t.Fatal(err)
			}
			defer leaf.Close()
			gateway := agents[gatewayIndex]
			snapshot, err := routing.Compile(state, state.Agents[gatewayIndex].ID)
			if err != nil {
				t.Fatal(err)
			}
			// Hub cryptography has its own integration tests. Here, join its
			// authenticated plaintext boundary to the simulated leaf's TCP stack.
			router, err := forwarding.New(snapshot, func(ctx context.Context, network, remote model.ID, frame []byte) error {
				if remote != leafID {
					return gateway.state.Load().mesh.Send(ctx, network, remote, frame)
				}
				p, err := packet.ParseView(frame)
				if err != nil {
					return err
				}
				_, err = leaf.Write(p.Payload)
				return err
			}, gateway.deliver)
			if err != nil {
				t.Fatal(err)
			}
			next := *gateway.state.Load()
			next.router = router
			gateway.state.Store(&next)
			go func() {
				raw := make([]byte, model.MaxMTU+1)
				for {
					n, err := leaf.Read(raw)
					if err != nil {
						return
					}
					gateway.receiveWireGuard(state.Networks[0].ID, raw[:n])
				}
			}()
			if sourceLeaf {
				transferApplication(t, leaf, devices[2], state.Networks[0].Nodes[2].Address)
			} else {
				transferApplication(t, devices[0], leaf, leafAddress)
			}
			if devices[1].writes.Load() != 0 || devices[gatewayIndex].writes.Load() != 0 {
				t.Fatal("WireGuard stream leaked into transit TUN")
			}
		})
	}
}

func TestTCPRevocationInterruptsEstablishedStream(t *testing.T) {
	agents, devices, state := streamAgents(t, model.TCP)
	target := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8082}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8082}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("target not connected")
	}
	defer server.Close()
	state.Revision++
	state.Networks[0].Edges[0].Enabled = false
	snapshot, err := routing.Compile(state, state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := agents[0].Apply(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatalf("revoked flow did not reset: %v", err)
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("revoked flow remained blocked")
	}
}
