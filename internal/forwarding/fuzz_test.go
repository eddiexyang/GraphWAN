package forwarding_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

// A neighbor chooses every byte of the frames it sends, and a masked frame's
// Nodes are not authenticated by any hop: the router forwards, delivers or
// refuses each without panicking.
func FuzzFromPeer(f *testing.F) {
	state := testutil.Topology()
	n := state.Networks[0]
	snapshot, err := routing.Compile(state, n.Nodes[1].AgentID)
	if err != nil {
		f.Fatal(err)
	}
	r, err := forwarding.New(snapshot, func(context.Context, model.ID, model.ID, []byte) error { return nil }, func(context.Context, model.ID, []byte) error { return nil })
	if err != nil {
		f.Fatal(err)
	}
	ip := packet.UDP(netipPort(n.Nodes[0].Address, 1), netipPort(n.Nodes[2].Address, 2), []byte("payload"))
	frame, _ := (packet.Packet{Header: packet.Header{Network: n.ID, Source: n.Nodes[0].ID, Destination: n.Nodes[2].ID, HopLimit: 9}, Payload: ip}).MarshalBinary()
	f.Add(frame, true)
	f.Add(frame, false)
	f.Fuzz(func(t *testing.T, raw []byte, sealed bool) {
		if len(raw) > packet.HeaderSize {
			packet.SetSealed(raw, sealed)
		}
		r.FromPeer(context.Background(), n.Nodes[0].ID, raw)
		if len(raw) > packet.HeaderSize {
			var header [packet.HeaderSize]byte
			r.CompactHeader(header[:], [16]byte(raw[8:24]), raw[3], raw[packet.HeaderSize:])
		}
	})
}

func netipPort(address netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(address, port)
}
