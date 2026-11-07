package packet

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestUDPRoundTrip(t *testing.T) {
	for _, pair := range [][2]string{{"10.0.0.1:18263", "10.0.0.2:18263"}, {"[fd00::1]:18263", "[fd00::2]:18263"}} {
		source, destination := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
		raw := UDP(source, destination, []byte("replay"))
		gotSource, gotDestination, payload, ok := UDPDatagram(raw)
		if !ok || gotSource != source || gotDestination != destination || !bytes.Equal(payload, []byte("replay")) {
			t.Fatalf("%s: got %v %v %q %v", pair[0], gotSource, gotDestination, payload, ok)
		}
		if _, err := InspectIP(raw); err != nil {
			t.Fatalf("%s: %v", pair[0], err)
		}
	}
	if UDP(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("[fd00::2]:1"), nil) != nil {
		t.Fatal("mixed address families")
	}
}
