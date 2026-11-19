package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

func icmpTo(src, dst netip.Addr) []byte {
	raw := make([]byte, 28)
	raw[0], raw[3], raw[8], raw[9], raw[20] = 0x45, 28, 64, 1, 8
	copy(raw[12:16], src.AsSlice())
	copy(raw[16:20], dst.AsSlice())
	return raw
}

func TestDeliverDropsPacketsForAnotherNetwork(t *testing.T) {
	a, b := model.ID("a"), model.ID("b")
	d := &packetTestTUN{out: make(chan []byte, 4), done: make(chan struct{})}
	defer d.Close()
	r := &DataPlane{}
	r.state.Store(&runtimeState{
		snapshot: model.Snapshot{Networks: []model.NetworkConfig{
			{ID: a, CIDR: netip.MustParsePrefix("6.6.6.0/24")},
			{ID: b, CIDR: netip.MustParsePrefix("7.7.7.0/24")},
		}},
		devices:     map[model.ID]*runtimeTunnel{a: newRuntimeTunnel(d)},
		selfAddress: map[model.ID]netip.Addr{a: netip.MustParseAddr("6.6.6.4"), b: netip.MustParseAddr("7.7.7.13")},
	})
	src := netip.MustParseAddr("6.6.6.11")
	for _, dst := range []string{"7.7.7.2", "7.7.7.13"} {
		if err := r.deliver(context.Background(), a, icmpTo(src, netip.MustParseAddr(dst))); !errors.Is(err, forwarding.ErrDestination) {
			t.Fatalf("deliver to %s: %v", dst, err)
		}
	}
	if err := r.deliverBatch(context.Background(), a, [][]byte{icmpTo(src, netip.MustParseAddr("7.7.7.2"))}); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{"6.6.6.4", "1.1.1.1"} {
		if err := r.deliver(context.Background(), a, icmpTo(src, netip.MustParseAddr(dst))); err != nil {
			t.Fatalf("deliver to %s: %v", dst, err)
		}
	}
	for _, want := range []string{"6.6.6.4", "1.1.1.1"} {
		got, _ := netip.AddrFromSlice((<-d.out)[16:20])
		if got.String() != want {
			t.Fatalf("TUN received %s, want %s", got, want)
		}
	}
	if len(d.out) != 0 {
		t.Fatal("a packet for another network reached the TUN")
	}
}
