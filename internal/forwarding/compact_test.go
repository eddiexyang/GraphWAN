package forwarding_test

import (
	"bytes"
	"context"
	"net/netip"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// Every hop carries only the hop limit and IP packet, as a compact Link does.
// The receiver's rebuilt header must equal the sender's routing fields, so
// forwarding, transit and admission behave exactly as with full frames.
func TestCompactHeaderRebuildsRoutedFrames(t *testing.T) {
	state := testutil.Topology()
	n := &state.Networks[0]
	n.Nodes[2].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: netip.MustParsePrefix("192.168.10.0/24"), GatewayMode: model.GatewayOff}}
	routers := map[model.ID]*forwarding.Router{}
	var delivered model.ID
	var payload []byte
	hops := 0
	for _, node := range n.Nodes {
		node := node
		snapshot, err := routing.Compile(state, node.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		r, err := forwarding.New(snapshot, func(ctx context.Context, network, next model.ID, frame []byte) error {
			hops++
			rebuilt := make([]byte, len(frame))
			if !routers[next].CompactHeader(rebuilt, [16]byte(frame[8:24]), frame[3], frame[packet.HeaderSize:]) {
				t.Fatalf("hop %d: compact header not rebuilt", hops)
			}
			copy(rebuilt[packet.HeaderSize:], frame[packet.HeaderSize:])
			if !bytes.Equal(rebuilt[:56], frame[:56]) {
				t.Fatalf("hop %d: rebuilt header %x, sent %x", hops, rebuilt[:56], frame[:56])
			}
			return routers[next].FromPeer(ctx, node.ID, rebuilt)
		}, func(_ context.Context, _ model.ID, raw []byte) error {
			delivered, payload = node.ID, append([]byte(nil), raw...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		routers[node.ID] = r
	}
	ctx := context.Background()
	a, c := n.Nodes[0].ID, n.Nodes[2].ID
	for _, tc := range []struct {
		from, to model.ID
		raw      []byte
	}{
		{a, c, ipv4("10.42.0.1", "192.168.10.7")},
		{c, a, ipv4("192.168.10.7", "10.42.0.1")},
	} {
		hops, delivered = 0, ""
		if err := routers[tc.from].FromTunnel(ctx, n.ID, tc.raw); err != nil {
			t.Fatal(err)
		}
		if delivered != tc.to || hops != 2 {
			t.Fatalf("delivered to %s after %d hops", delivered, hops)
		}
		// Transit decrements the IP TTL; addresses and payload are unchanged.
		if !bytes.Equal(payload[12:], tc.raw[12:]) {
			t.Fatal("payload changed in transit")
		}
	}
	// Addresses without an admitted owner have no header to rebuild.
	header := make([]byte, packet.HeaderSize)
	full, err := (packet.Packet{Header: packet.Header{Network: n.ID, Source: a, Destination: c, HopLimit: 1}, Payload: []byte{0}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire := [16]byte(full[8:24])
	for _, raw := range [][]byte{ipv4("10.42.0.1", "203.0.113.9"), ipv4("10.99.0.1", "10.42.0.1"), {0x45}} {
		if routers[a].CompactHeader(header, wire, 8, raw) {
			t.Fatalf("rebuilt a header for unadmitted packet %x", raw)
		}
	}
	if routers[a].CompactHeader(header, [16]byte{1}, 8, ipv4("10.42.0.1", "10.42.0.2")) {
		t.Fatal("rebuilt a header for an unknown network")
	}
}
