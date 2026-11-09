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
	if HeaderLen(raw) != 28 {
		t.Fatalf("header %d", HeaderLen(raw))
	}
	var a, b [MaxReadable]byte
	before := bytes.Clone(Authenticated(&a, raw))
	DecrementIPHopLimit(raw)
	raw[1] |= 3 // congestion experienced
	if !bytes.Equal(before, Authenticated(&b, raw)) {
		t.Fatal("a hop's changes are authenticated")
	}
	raw[26] ^= 0xff // the UDP checksum
	if !bytes.Equal(before, Authenticated(&b, raw)) {
		t.Fatal("the L4 checksum is authenticated")
	}
	raw[23]++
	if bytes.Equal(before, Authenticated(&b, raw)) {
		t.Fatal("the destination port is not authenticated")
	}
	binary.BigEndian.PutUint16(raw[6:8], 1)
	if HeaderLen(raw) != 20 {
		t.Fatal("a later fragment's payload is readable")
	}
	v6 := UDP(netip.MustParseAddrPort("[fd00::1]:1"), netip.MustParseAddrPort("[fd00::2]:2"), []byte("payload"))
	if HeaderLen(v6) != 48 {
		t.Fatalf("header %d", HeaderLen(v6))
	}
}

// The destination computes the checksums a seal does not authenticate again:
// a hop's change to them does not survive, except in a fragment, whose L4
// checksum covers the whole datagram.
func TestRestoreChecksums(t *testing.T) {
	icmp := func(source, destination string) []byte {
		raw := UDP(netip.MustParseAddrPort(source), netip.MustParseAddrPort(destination), []byte("echo payload"))
		if raw[0]>>4 == 4 {
			raw[9] = 1
			binary.BigEndian.PutUint16(raw[10:12], 0)
			binary.BigEndian.PutUint16(raw[10:12], ipChecksum(raw[:20]))
			l4 := raw[20:]
			l4[0], l4[1], l4[2], l4[3] = 8, 0, 0, 0
			binary.BigEndian.PutUint16(l4[2:4], ipChecksum(l4))
			return raw
		}
		raw[6] = 58
		l4 := raw[40:]
		l4[0], l4[1], l4[2], l4[3] = 128, 0, 0, 0
		pseudo := append(append([]byte{}, raw[8:40]...), 0, 0, 0, 0, 0, 0, 0, 58)
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(l4)))
		binary.BigEndian.PutUint16(l4[2:4], ipChecksum(append(pseudo, l4...)))
		return raw
	}
	for name, raw := range map[string][]byte{
		"udp4":   UDP(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:2"), []byte("odd payload")),
		"udp6":   UDP(netip.MustParseAddrPort("[fd00::1]:1"), netip.MustParseAddrPort("[fd00::2]:2"), []byte("odd payload")),
		"icmp4":  icmp("10.0.0.1:0", "10.0.0.2:0"),
		"icmpv6": icmp("[fd00::1]:0", "[fd00::2]:0"),
	} {
		want := bytes.Clone(raw)
		at := HeaderLen(raw) - 8 + 2
		if name == "udp4" || name == "udp6" {
			at += 4
		}
		raw[at] ^= 0x5a
		raw[at+1] ^= 0xa5
		if raw[0]>>4 == 4 {
			raw[10] ^= 0xff
		}
		RestoreChecksums(raw)
		if !bytes.Equal(raw, want) {
			t.Fatalf("%s: checksums not restored", name)
		}
	}
	fragment := UDP(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:2"), []byte("first fragment"))
	binary.BigEndian.PutUint16(fragment[6:8], 0x2000) // more fragments
	binary.BigEndian.PutUint16(fragment[26:28], 0x1234)
	RestoreChecksums(fragment)
	if binary.BigEndian.Uint16(fragment[26:28]) != 0x1234 || ipChecksum(fragment[:20]) != 0 {
		t.Fatal("a fragment's checksums")
	}
}
