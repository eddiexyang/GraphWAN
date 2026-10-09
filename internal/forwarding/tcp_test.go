package forwarding_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func TestTCPStreamAdmissionAndRoutes(t *testing.T) {
	s := testutil.Topology()
	n := s.Networks[0]
	routers := map[model.ID]*forwarding.Router{}
	for _, node := range n.Nodes {
		snapshot, err := routing.Compile(s, node.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		r, err := forwarding.New(snapshot, func(context.Context, model.ID, model.ID, []byte) error { t.Fatal("TCP used packet sender"); return nil }, func(context.Context, model.ID, []byte) error { t.Fatal("TCP used packet delivery"); return nil })
		if err != nil {
			t.Fatal(err)
		}
		routers[node.ID] = r
	}
	a, b, c := n.Nodes[0].ID, n.Nodes[1].ID, n.Nodes[2].ID
	request, err := routers[a].TCPRequest(n.ID, netip.MustParseAddrPort("10.42.0.1:34567"), netip.MustParseAddrPort("10.42.0.3:443"))
	if err != nil {
		t.Fatal(err)
	}
	if next, local, err := routers[a].TCPRoute(request, ""); err != nil || local || next != b {
		t.Fatalf("source route: %s %v %v", next, local, err)
	}
	if next, local, err := routers[b].TCPRoute(request, a); err != nil || local || next != c {
		t.Fatalf("transit route: %s %v %v", next, local, err)
	}
	if _, local, err := routers[c].TCPRoute(request, b); err != nil || !local {
		t.Fatalf("destination: %v %v", local, err)
	}
	for name, mutate := range map[string]func(){
		"unknown network":   func() { request.Network = testutil.ID(99) },
		"spoofed source":    func() { request.Source = c },
		"wrong destination": func() { request.Destination = b },
		"zero port":         func() { request.To = netip.MustParseAddrPort("10.42.0.3:0") },
		"exhausted hops":    func() { request.Hops = 1 },
	} {
		original := request
		mutate()
		if _, _, err := routers[b].TCPRoute(request, a); err == nil {
			t.Fatalf("admitted %s", name)
		}
		request = original
	}
	if _, _, err := routers[b].TCPRoute(request, testutil.ID(99)); !errors.Is(err, forwarding.ErrPeer) {
		t.Fatal("unconfigured ingress", err)
	}
	raw := ipv4("10.42.0.1", "10.42.0.3")
	raw[9] = 6
	if err := routers[a].FromTunnel(context.Background(), n.ID, raw); !errors.Is(err, forwarding.ErrTCPPacket) {
		t.Fatal("TCP packet fallback", err)
	}
	frame, err := (packet.Packet{Header: packet.Header{Network: n.ID, Source: a, Destination: c, HopLimit: 10}, Payload: raw}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := routers[b].FromPeer(context.Background(), a, frame); !errors.Is(err, forwarding.ErrTCPPacket) {
		t.Fatal("peer TCP packet fallback", err)
	}
}

func TestTCPGSOAdmissionPreservesMTUAndOwnership(t *testing.T) {
	s := testutil.Topology()
	n := s.Networks[0]
	snapshot, err := routing.Compile(s, n.Nodes[0].AgentID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := forwarding.New(snapshot, func(context.Context, model.ID, model.ID, []byte) error { return nil }, func(context.Context, model.ID, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64000)
	copy(raw, ipv4("10.42.0.1", "10.42.0.3"))
	raw[9], raw[32] = 6, 0x50
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
	if err := r.TCPIngressGSO(n.ID, raw, n.MTU); err != nil {
		t.Fatal("valid GSO rejected", err)
	}
	if err := r.TCPIngressGSO(n.ID, raw, n.MTU+1); !errors.Is(err, forwarding.ErrMTU) {
		t.Fatal("oversized segment admitted", err)
	}
	if err := r.TCPIngress(n.ID, raw, false); !errors.Is(err, forwarding.ErrMTU) {
		t.Fatal("ordinary ingress bypassed MTU", err)
	}
	if err := r.TCPIngress(n.ID, raw, true); !errors.Is(err, forwarding.ErrMTU) {
		t.Fatal("WireGuard ingress bypassed MTU", err)
	}
	raw[15] = 3
	if err := r.TCPIngressGSO(n.ID, raw, n.MTU); !errors.Is(err, forwarding.ErrSource) {
		t.Fatal("spoofed GSO source admitted", err)
	}
	raw[15], raw[9] = 1, 17
	if err := r.TCPIngressGSO(n.ID, raw, n.MTU); err == nil {
		t.Fatal("UDP used TCP GSO admission")
	}
}

func TestTCPOutputBatchPreservesOrderAndDestinationPolicy(t *testing.T) {
	state := testutil.Topology()
	network := state.Networks[0]
	snapshot, err := routing.Compile(state, network.Nodes[0].AgentID)
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "single packet fallback", true: "batch delivery"}[batch], func(t *testing.T) {
			var delivered [][]byte
			var batchSizes []int
			deliver := func(_ context.Context, id model.ID, raw []byte) error {
				if id != network.ID {
					t.Fatal("packet changed network")
				}
				delivered = append(delivered, bytes.Clone(raw))
				return nil
			}
			options := forwarding.BatchOptions{}
			if batch {
				options.Deliver = func(ctx context.Context, id model.ID, packets [][]byte) error {
					batchSizes = append(batchSizes, len(packets))
					for _, raw := range packets {
						if err := deliver(ctx, id, raw); err != nil {
							return err
						}
					}
					return nil
				}
			}
			router, err := forwarding.New(snapshot, func(context.Context, model.ID, model.ID, []byte) error {
				t.Fatal("access output escaped to a graph packet Link")
				return nil
			}, deliver, options)
			if err != nil {
				t.Fatal(err)
			}
			first := ipv4("10.42.0.2", "10.42.0.1")
			first[9] = 6
			second := bytes.Clone(first)
			second[4] = 1
			third := bytes.Clone(first)
			third[4] = 2
			unknown := ipv4("10.42.0.2", "10.42.0.99")
			unknown[9] = 6
			err = router.TCPOutputBatch(context.Background(), network.ID, [][]byte{first, second, unknown, third})
			if !errors.Is(err, forwarding.ErrDestination) {
				t.Fatal("unknown destination admitted", err)
			}
			if !reflect.DeepEqual(delivered, [][]byte{first, second, third}) {
				t.Fatal("access packet order or filtering changed")
			}
			if batch && !reflect.DeepEqual(batchSizes, []int{2, 1}) {
				t.Fatal("valid local burst was split", batchSizes)
			}
		})
	}
}
