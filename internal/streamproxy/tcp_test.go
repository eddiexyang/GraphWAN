package streamproxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type halfPipe struct{ net.Conn }

func (p halfPipe) CloseWrite() error { return p.Close() }

func TestNativeAccessOutputRetainsPacketAndGSO(t *testing.T) {
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("native payload"))})
	packet.GSOOptions = stack.GSO{Type: stack.GSOTCPv4, MSS: 1228, NeedsCsum: true}
	defer packet.DecRef()
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	calls := 0
	link := &accessLink{Endpoint: channel.New(8, 1280, ""), writeTCP: func(got *stack.PacketBuffer) error {
		calls++
		if got != packet || got.GSOOptions != packet.GSOOptions || string(got.Data().AsRange().ToSlice()) != "native payload" {
			t.Fatal("native output changed packet ownership or offload metadata")
		}
		return nil
	}}
	if n, err := link.WritePackets(packets); n != 1 || err != nil || calls != 1 || link.NumQueued() != 0 {
		t.Fatal("native output entered the packet queue", n, err, calls)
	}
	link.Close()
	if n, err := link.WritePackets(packets); n != 0 || err == nil || calls != 1 {
		t.Fatal("closed native output accepted another packet", n, err)
	}
}

func TestNativeAccessOutputReportsPartialFailure(t *testing.T) {
	var packets stack.PacketBufferList
	for range 2 {
		packets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("data"))}))
	}
	defer packets.DecRef()
	calls := 0
	link := &accessLink{Endpoint: channel.New(8, 1280, ""), writeTCP: func(*stack.PacketBuffer) error {
		calls++
		if calls == 2 {
			return io.ErrClosedPipe
		}
		return nil
	}}
	defer link.Close()
	n, err := link.WritePackets(packets)
	if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok || n != 1 || link.NumQueued() != 0 {
		t.Fatal("native partial failure was not propagated", n, err)
	}
}

func TestEngineCloseInterruptsIncompleteAccessHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	synack := make(chan struct{}, 1)
	engine, err := NewEngine(ctx, 1280, func([]byte) error {
		select {
		case synack <- struct{}{}:
		default:
		}
		return nil
	}, func(context.Context, netip.AddrPort, netip.AddrPort) (Conn, error) {
		a, b := net.Pipe()
		b.Close()
		return halfPipe{a}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	application := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	link := channel.New(8, 1280, "")
	application.CreateNIC(1, link)
	application.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}), PrefixLen: 24}}, stack.AddressProperties{})
	application.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	defer func() {
		application.Close()
		for _, ep := range application.CleanupEndpoints() {
			ep.Abort()
		}
		link.Close()
	}()
	go func() {
		conn, _ := gonet.DialContextTCP(ctx, application, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), Port: 443}, ipv4.ProtocolNumber)
		if conn != nil {
			conn.Close()
		}
	}()
	p := link.ReadContext(ctx)
	if p == nil {
		t.Fatal("client SYN unavailable")
	}
	view := p.ToView()
	engine.Inject(view.AsSlice())
	view.Release()
	p.DecRef()
	select {
	case <-synack:
	case <-ctx.Done():
		t.Fatal("access handshake not started")
	}
	done := make(chan struct{})
	go func() { engine.Close(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("TCP stack shutdown leaked an incomplete handshake")
	}
}
