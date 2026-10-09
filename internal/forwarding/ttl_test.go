package forwarding_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func TestTraceroute(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("v6=%t/batch=%t", v6, batch), func(t *testing.T) {
				s := testutil.Topology()
				n := &s.Networks[0]
				if v6 {
					n.CIDR = netip.MustParsePrefix("fd00::/64")
					for i := range n.Nodes {
						n.Nodes[i].Address = netip.MustParseAddr(fmt.Sprintf("fd00::%d", i+1))
					}
				}
				routers := map[model.ID]*forwarding.Router{}
				var delivered model.ID
				var payload []byte
				for _, node := range n.Nodes {
					snap, err := routing.Compile(s, node.AgentID)
					if err != nil {
						t.Fatal(err)
					}
					r, err := forwarding.New(snap, func(ctx context.Context, network, next model.ID, frame []byte) error {
						before := bytes.Clone(frame)
						var err error
						if batch {
							err = routers[next].FromPeerBatch(ctx, node.ID, [][]byte{frame})
						} else {
							err = routers[next].FromPeer(ctx, node.ID, frame)
						}
						if !bytes.Equal(before, frame) {
							t.Error("mutated caller frame")
						}
						return err
					}, func(_ context.Context, _ model.ID, raw []byte) error {
						delivered = node.ID
						payload = bytes.Clone(raw)
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
					routers[node.ID] = r
				}
				for _, ttl := range []byte{0, 1, 2, 64} {
					raw := ipv4("10.42.0.1", "10.42.0.3")
					h := 20
					if v6 {
						h = 40
						raw = make([]byte, 48)
						raw[0], raw[6], raw[7] = 0x60, 17, ttl
						binary.BigEndian.PutUint16(raw[4:6], 8)
						a, c := n.Nodes[0].Address.As16(), n.Nodes[2].Address.As16()
						copy(raw[8:24], a[:])
						copy(raw[24:40], c[:])
					} else {
						raw[8] = ttl
						var sum uint32
						for i := 0; i < 20; i += 2 {
							sum += uint32(binary.BigEndian.Uint16(raw[i : i+2]))
						}
						for sum>>16 != 0 {
							sum = sum&65535 + sum>>16
						}
						binary.BigEndian.PutUint16(raw[10:12], ^uint16(sum))
					}
					before := bytes.Clone(raw)
					delivered = ""
					payload = nil
					var err error
					if batch {
						err = routers[n.Nodes[0].ID].FromTunnelBatch(context.Background(), n.ID, [][]byte{raw})
					} else {
						err = routers[n.Nodes[0].ID].FromTunnel(context.Background(), n.ID, raw)
					}
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(raw, before) {
						t.Fatal("mutated source")
					}
					if ttl <= 1 {
						info, err := packet.InspectAddresses(payload)
						if err != nil || delivered != n.Nodes[0].ID || info.Source != n.Nodes[1].Address || info.Destination != n.Nodes[0].Address {
							t.Fatalf("expiry at B: %s %v %v", delivered, info, err)
						}
						if !bytes.Equal(payload[h+8:], raw) {
							t.Fatal("quote changed")
						}
					} else if delivered != n.Nodes[2].ID || packet.IPHopLimit(payload) != ttl-1 {
						t.Fatal("destination delivery", delivered)
					}
				}
			})
		}
	}
}
