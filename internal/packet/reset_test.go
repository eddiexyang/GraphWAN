package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// tcpPacket builds a TCP packet with a 20-byte header and payload.
func tcpPacket(source, destination netip.AddrPort, seq, ack uint32, flags byte, payload []byte) []byte {
	out := UDP(source, destination, make([]byte, 12+len(payload)))
	header := 20
	if source.Addr().Is4() {
		out[9] = 6
	} else {
		out[6], header = 6, 40
	}
	tcp := out[header:]
	clear(tcp)
	binary.BigEndian.PutUint16(tcp[0:2], source.Port())
	binary.BigEndian.PutUint16(tcp[2:4], destination.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12], tcp[13] = 5<<4, flags
	copy(tcp[20:], payload)
	return out
}

func TestTCPReset(t *testing.T) {
	for _, pair := range [][2]netip.AddrPort{
		{netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("192.168.1.9:443")},
		{netip.MustParseAddrPort("[fd00::1]:40000"), netip.MustParseAddrPort("[2001:db8::9]:443")},
	} {
		for _, tc := range []struct {
			name     string
			flags    byte
			payload  int
			seq, ack uint32
			want     byte
		}{
			{"data", TCPAck | TCPPsh, 100, 7, 0, TCPRst},
			{"syn", TCPSyn, 0, 0, 1001, TCPRst | TCPAck},
			{"fin", TCPFin, 10, 0, 1011, TCPRst | TCPAck},
		} {
			raw := tcpPacket(pair[0], pair[1], 1000, 7, tc.flags, make([]byte, tc.payload))
			reset := TCPReset(raw)
			from, to, flags, ok := TCPFlow(reset)
			if !ok || from != pair[1] || to != pair[0] || flags != tc.want {
				t.Fatalf("%v %s: reset %v -> %v flags %#x", pair[0], tc.name, from, to, flags)
			}
			offset := tcpOffset(reset)
			tcp := reset[offset:]
			if got := binary.BigEndian.Uint32(tcp[4:8]); got != tc.seq {
				t.Fatalf("%s: seq %d, want %d", tc.name, got, tc.seq)
			}
			if got := binary.BigEndian.Uint32(tcp[8:12]); got != tc.ack {
				t.Fatalf("%s: ack %d, want %d", tc.name, got, tc.ack)
			}
			var pseudo []byte
			if pair[0].Addr().Is4() {
				if ipChecksum(reset[:20]) != 0 {
					t.Fatal("IPv4 header checksum")
				}
				pseudo = append(append(pseudo, reset[12:20]...), 0, 6, 0, byte(len(tcp)))
			} else {
				pseudo = append(append(pseudo, reset[8:40]...), 0, 0, 0, byte(len(tcp)), 0, 0, 0, 6)
			}
			if ipChecksum(append(pseudo, tcp...)) != 0 {
				t.Fatalf("%s: TCP checksum", tc.name)
			}
		}
		if TCPReset(tcpPacket(pair[0], pair[1], 1, 1, TCPRst, nil)) != nil {
			t.Fatal("answered a reset")
		}
	}
}
