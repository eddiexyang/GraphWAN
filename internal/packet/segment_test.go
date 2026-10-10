package packet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func testTCPPacket(v4 bool, payload int, flags byte) []byte {
	var raw []byte
	tcpStart := 20
	if v4 {
		raw = make([]byte, 20+32+payload)
		raw[0], raw[8], raw[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
		binary.BigEndian.PutUint16(raw[4:6], 0x1234)
		raw[6] = 0x40 // DF
		copy(raw[12:16], []byte{7, 7, 7, 1})
		copy(raw[16:20], []byte{7, 7, 7, 2})
	} else {
		tcpStart = 40
		raw = make([]byte, 40+32+payload)
		raw[0], raw[6], raw[7] = 0x60, 6, 64
		binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-40))
		raw[8], raw[23] = 0xfd, 1
		raw[24], raw[39] = 0xfd, 2
	}
	tcp := raw[tcpStart:]
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 0xfffff000)
	tcp[12], tcp[13] = 8<<4, flags
	copy(tcp[20:32], []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2}) // NOP NOP timestamp
	for i := range payload {
		tcp[32+i] = byte(i)
	}
	return raw
}

func validTCP(t *testing.T, raw []byte) {
	t.Helper()
	offset := tcpOffset(raw)
	tcp := raw[offset:]
	pseudo := uint32(6) + uint32(len(tcp))
	if raw[0]>>4 == 4 {
		if fold(sum(raw[:offset], 0)) != 0xffff {
			t.Fatal("bad IPv4 checksum")
		}
		pseudo = sum(raw[12:20], pseudo)
	} else {
		pseudo = sum(raw[8:40], pseudo)
	}
	if fold(sum(tcp, pseudo)) != 0xffff {
		t.Fatal("bad TCP checksum")
	}
}

func TestSegmentTCP(t *testing.T) {
	for _, v4 := range []bool{true, false} {
		raw := testTCPPacket(v4, 3000, TCPAck|TCPPsh|TCPFin|TCPCwr)
		header := tcpOffset(raw) + 32
		var segments [][]byte
		if err := SegmentTCP(raw, 1200, func(b []byte) error { segments = append(segments, b); return nil }); err != nil {
			t.Fatal(err)
		}
		if len(segments) != 3 {
			t.Fatalf("got %d segments", len(segments))
		}
		var joined []byte
		for i, s := range segments {
			validTCP(t, s)
			tcp := s[tcpOffset(s):]
			if seq := binary.BigEndian.Uint32(tcp[4:8]); seq != 0xfffff000+uint32(i*1200) {
				t.Fatalf("segment %d sequence %x", i, seq)
			}
			last, first := i == len(segments)-1, i == 0
			if (tcp[13]&TCPFin != 0) != last || (tcp[13]&TCPPsh != 0) != last || (tcp[13]&TCPCwr != 0) != first || tcp[13]&TCPAck == 0 {
				t.Fatalf("segment %d flags %x", i, tcp[13])
			}
			if !v4 && (!bytes.Equal(s[:4], raw[:4]) || !bytes.Equal(s[6:40], raw[6:40]) || int(binary.BigEndian.Uint16(s[4:6])) != len(s)-40) {
				t.Fatal("IPv6 header changed")
			}
			if v4 && binary.BigEndian.Uint16(s[4:6]) != 0x1234+uint16(i) {
				t.Fatal("IPv4 ID not incremented")
			}
			joined = append(joined, s[header:]...)
		}
		if !bytes.Equal(joined, raw[header:]) {
			t.Fatal("payload changed")
		}
	}
}

func TestSegmentTCPCompletesPartialChecksum(t *testing.T) {
	raw := testTCPPacket(true, 100, TCPAck)
	var out []byte
	if err := SegmentTCP(raw, 1400, func(b []byte) error { out = b; return nil }); err != nil {
		t.Fatal(err)
	}
	validTCP(t, out)
	if !bytes.Equal(out[:10], raw[:10]) || !bytes.Equal(out[12:36], raw[12:36]) || !bytes.Equal(out[38:], raw[38:]) {
		t.Fatal("single segment changed beyond its checksum")
	}
}

func TestTCPFlow(t *testing.T) {
	src, dst, flags, ok := TCPFlow(testTCPPacket(true, 0, TCPSyn))
	if !ok || src != netip.MustParseAddrPort("7.7.7.1:40000") || dst != netip.MustParseAddrPort("7.7.7.2:443") || flags != TCPSyn {
		t.Fatal(src, dst, flags, ok)
	}
	fragment := testTCPPacket(true, 0, TCPSyn)
	fragment[6], fragment[7] = 0x20, 0 // MF
	if _, _, _, ok := TCPFlow(fragment); ok {
		t.Fatal("fragment classified")
	}
}
