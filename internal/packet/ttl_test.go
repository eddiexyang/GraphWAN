package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestTimeExceeded(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		raw := make([]byte, 1500)
		source := netip.MustParseAddr("10.0.0.2")
		h := 20
		if v6 {
			h = 40
			source = netip.MustParseAddr("fd00::2")
			raw[0], raw[6], raw[7] = 0x60, 17, 2
			binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-40))
			s, d := netip.MustParseAddr("fd00::1").As16(), netip.MustParseAddr("fd00::3").As16()
			copy(raw[8:24], s[:])
			copy(raw[24:40], d[:])
		} else {
			raw[0], raw[8], raw[9] = 0x45, 2, 17
			binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
			copy(raw[12:20], []byte{10, 0, 0, 1, 10, 0, 0, 3})
			binary.BigEndian.PutUint16(raw[10:12], ipChecksum(raw[:20]))
		}
		DecrementIPHopLimit(raw)
		if IPHopLimit(raw) != 1 {
			t.Fatal("hop limit")
		}
		reply := TimeExceeded(raw, source)
		info, err := InspectAddresses(reply)
		if err != nil || info.Source != source {
			t.Fatalf("reply: %v %v", info, err)
		}
		if v6 {
			if len(reply) != 1280 || reply[40] != 3 {
				t.Fatal("v6 bounds/type")
			}
			pseudo := make([]byte, 40+len(reply)-h)
			copy(pseudo, reply[8:40])
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(reply)-h))
			pseudo[39] = 58
			copy(pseudo[40:], reply[h:])
			if ipChecksum(pseudo) != 0 {
				t.Fatal("v6 checksum")
			}
			raw[6], raw[40] = 58, 1
		} else {
			if len(reply) != 576 || reply[20] != 11 || ipChecksum(reply[:20]) != 0 || ipChecksum(reply[20:]) != 0 || ipChecksum(raw[:20]) != 0 {
				t.Fatal("v4 checksum/type/bounds")
			}
			raw[9], raw[20] = 1, 3
			raw[10], raw[11] = 0, 0
			binary.BigEndian.PutUint16(raw[10:12], ipChecksum(raw[:20]))
		}
		if TimeExceeded(raw, source) != nil {
			t.Fatal("error to error")
		}
	}
}

func TestTimeExceededExtensionsAndFragments(t *testing.T) {
	raw := make([]byte, 56)
	raw[0], raw[6], raw[7] = 0x60, 60, 1
	binary.BigEndian.PutUint16(raw[4:6], 16)
	s, d := netip.MustParseAddr("fd00::1").As16(), netip.MustParseAddr("fd00::3").As16()
	copy(raw[8:24], s[:])
	copy(raw[24:40], d[:])
	source := netip.MustParseAddr("fd00::2")
	raw[40] = 58
	raw[48] = 128
	if TimeExceeded(raw, source) == nil {
		t.Fatal("echo behind destination options suppressed")
	}
	raw[48] = 3
	if TimeExceeded(raw, source) != nil {
		t.Fatal("error behind destination options answered")
	}
	raw[6], raw[40] = 44, 17
	binary.BigEndian.PutUint16(raw[42:44], 8)
	if TimeExceeded(raw, source) != nil {
		t.Fatal("noninitial v6 fragment answered")
	}
	binary.BigEndian.PutUint16(raw[42:44], 1)
	if TimeExceeded(raw, source) == nil {
		t.Fatal("initial v6 fragment suppressed")
	}
	raw[6], raw[41] = 60, 255
	if TimeExceeded(raw, source) != nil {
		t.Fatal("truncated extension answered")
	}

	raw = make([]byte, 32)
	raw[0], raw[8], raw[9] = 0x46, 2, 17
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	copy(raw[12:20], []byte{10, 0, 0, 1, 10, 0, 0, 3})
	raw[20], raw[21] = 1, 1 // NOP options followed by end-of-options.
	fix := func() { raw[10], raw[11] = 0, 0; binary.BigEndian.PutUint16(raw[10:12], ipChecksum(raw[:24])) }
	fix()
	DecrementIPHopLimit(raw)
	source = netip.MustParseAddr("10.0.0.2")
	if ipChecksum(raw[:24]) != 0 || TimeExceeded(raw, source) == nil {
		t.Fatal("IPv4 options checksum/reply")
	}
	binary.BigEndian.PutUint16(raw[6:8], 1)
	fix()
	if TimeExceeded(raw, source) != nil {
		t.Fatal("noninitial v4 fragment answered")
	}
	binary.BigEndian.PutUint16(raw[6:8], 0x2000)
	fix()
	if TimeExceeded(raw, source) == nil {
		t.Fatal("initial v4 fragment suppressed")
	}
	raw[12] = 0
	fix()
	if TimeExceeded(raw, source) != nil {
		t.Fatal("invalid source answered")
	}
	raw[12] = 10
	raw[16] = 224
	fix()
	if TimeExceeded(raw, source) != nil {
		t.Fatal("multicast answered")
	}
}
