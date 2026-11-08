package forwarding_test

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// A transit Node forwards a frame it owns in the same buffer, with both hop
// limits decremented in place; a batch allocates the same however many frames
// it holds.
func TestOwnedTransitForwardsInPlace(t *testing.T) {
	state := testutil.Topology()
	n := state.Networks[0]
	snapshots := map[model.ID]model.Snapshot{}
	for _, node := range n.Nodes {
		snapshot, err := routing.Compile(state, node.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		snapshots[node.ID] = snapshot
	}
	// A frame from A to a Node that A reaches through a transit.
	var frame []byte
	var first model.ID
	for _, destination := range n.Nodes[1:] {
		ingress, err := forwarding.New(snapshots[n.Nodes[0].ID], func(_ context.Context, _, next model.ID, f []byte) error {
			frame, first = append([]byte(nil), f...), next
			return nil
		}, func(context.Context, model.ID, []byte) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		raw := ipv4(n.Nodes[0].Address.String(), destination.Address.String())
		if err := ingress.FromTunnel(context.Background(), n.ID, raw); err != nil {
			t.Fatal(err)
		}
		if first != destination.ID {
			break
		}
		frame = nil
	}
	if frame == nil {
		t.Fatal("no destination behind a transit")
	}
	var sent *packetbuf.Buffer
	transit, err := forwarding.New(snapshots[first], func(context.Context, model.ID, model.ID, []byte) error {
		t.Fatal("transit copied the frame")
		return nil
	}, func(context.Context, model.ID, []byte) error { t.Fatal("delivered at the transit"); return nil },
		forwarding.BatchOptions{SendOwned: func(_ context.Context, _, _ model.ID, owners []*packetbuf.Buffer) error {
			sent = owners[0]
			for _, owner := range owners[1:] {
				owner.Release()
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	owner := packetbuf.Get(len(frame))
	copy(owner.Data, frame)
	data := owner.Data
	if err := transit.FromPeerOwnedBatch(context.Background(), n.Nodes[0].ID, []*packetbuf.Buffer{owner}); err != nil {
		t.Fatal(err)
	}
	if sent != owner || &sent.Data[0] != &data[0] {
		t.Fatal("transit did not forward its own buffer")
	}
	if sent.Data[3] != frame[3]-1 || sent.Data[packet.HeaderSize+8] != frame[packet.HeaderSize+8]-1 {
		t.Fatalf("hop limits %d/%d, want %d/%d", sent.Data[3], sent.Data[packet.HeaderSize+8], frame[3]-1, frame[packet.HeaderSize+8]-1)
	}
	if binary.BigEndian.Uint16(sent.Data[packet.HeaderSize+10:]) == binary.BigEndian.Uint16(frame[packet.HeaderSize+10:]) {
		t.Fatal("IPv4 checksum not updated")
	}
	sent.Release()
	batch := func(size int) float64 {
		owners := make([]*packetbuf.Buffer, size)
		return testing.AllocsPerRun(100, func() {
			for i := range owners {
				owners[i] = packetbuf.Get(len(frame))
				copy(owners[i].Data, frame)
			}
			transit.FromPeerOwnedBatch(context.Background(), n.Nodes[0].ID, owners)
			sent.Release()
		})
	}
	if raceEnabled {
		return
	}
	if one, many := batch(1), batch(64); many != one {
		t.Fatalf("%.0f allocations for one frame, %.0f for 64", one, many)
	}
}
