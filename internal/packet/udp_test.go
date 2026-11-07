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

func TestTCPFlowHashMatchesPackets(t *testing.T) {
	for _, pair := range [][2]netip.AddrPort{
		{netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("192.168.1.9:443")},
		{netip.MustParseAddrPort("[fd00::1]:40000"), netip.MustParseAddrPort("[2001:db8::9]:443")},
	} {
		raw := UDP(pair[0], pair[1], []byte("x"))
		if pair[0].Addr().Is4() {
			raw[9] = 6
		} else {
			raw[6] = 6
		}
		info, err := InspectIP(raw)
		if err != nil {
			t.Fatal(err)
		}
		if TCPFlowHash(pair[0], pair[1]) != info.Flow {
			t.Fatalf("%v: stream hash differs from the packet's flow", pair)
		}
	}
}
