package packet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// A seal leaves the IP header and a UDP header readable, except in a later
// fragment, which has none, and authenticates them without the fields hops
// change.
func TestSealedHeaders(t *testing.T) {
	raw := UDP(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:2"), []byte("payload"))
	if Readable(raw) != 28 {
		t.Fatalf("readable %d", Readable(raw))
	}
	var a, b [MaxReadable]byte
	before := bytes.Clone(Authenticated(&a, raw))
	DecrementIPHopLimit(raw)
	raw[1] |= 3 // congestion experienced
	if !bytes.Equal(before, Authenticated(&b, raw)) {
		t.Fatal("a hop's changes are authenticated")
	}
	raw[23]++
	if bytes.Equal(before, Authenticated(&b, raw)) {
		t.Fatal("the destination port is not authenticated")
	}
	binary.BigEndian.PutUint16(raw[6:8], 1)
	if Readable(raw) != 20 {
		t.Fatal("a later fragment's payload is readable")
	}
	v6 := UDP(netip.MustParseAddrPort("[fd00::1]:1"), netip.MustParseAddrPort("[fd00::2]:2"), []byte("payload"))
	if Readable(v6) != 48 {
		t.Fatalf("readable %d", Readable(v6))
	}
}
