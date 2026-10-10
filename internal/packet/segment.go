package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
	TCPCwr = 0x80
)

// tcpOffset finds the TCP header of an unfragmented packet, or returns -1.
func tcpOffset(raw []byte) int {
	if len(raw) < 20 {
		return -1
	}
	if raw[0]>>4 == 4 {
		header := int(raw[0]&15) * 4
		if raw[9] != 6 || header < 20 || binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
			return -1
		}
		return header
	}
	if raw[0]>>4 != 6 || len(raw) < 40 {
		return -1
	}
	next, offset := raw[6], 40
	for range 16 {
		switch next {
		case 6:
			return offset
		case 0, 43, 60:
			if offset+2 > len(raw) {
				return -1
			}
			next, offset = raw[offset], offset+(int(raw[offset+1])+1)*8
		case 51:
			if offset+2 > len(raw) {
				return -1
			}
			next, offset = raw[offset], offset+(int(raw[offset+1])+2)*4
		default:
			// Fragments and unknown extensions are not classified.
			return -1
		}
		if offset > len(raw) {
			return -1
		}
	}
	return -1
}

// TCPFlow returns the addresses, ports and flags of an unfragmented TCP packet.
func TCPFlow(raw []byte) (source, destination netip.AddrPort, flags byte, ok bool) {
	offset := tcpOffset(raw)
	if offset < 0 || offset+20 > len(raw) {
		return
	}
	var src, dst netip.Addr
	if raw[0]>>4 == 4 {
		src, dst = netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20]))
	} else {
		src, dst = netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
	}
	tcp := raw[offset:]
	source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2]))
	destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4]))
	return source, destination, tcp[13], true
}

// SegmentTCP splits a TCP packet into segments carrying at most mss payload
// bytes, as a NIC performs TSO. Every segment gets complete IP and TCP
// checksums, so the input may carry a partial (offloaded) checksum.
func SegmentTCP(raw []byte, mss int, emit func([]byte) error) error {
	offset := tcpOffset(raw)
	if offset < 0 || offset+20 > len(raw) || mss <= 0 {
		return errors.New("invalid TCP segmentation input")
	}
	header := offset + int(raw[offset+12]>>4)*4
	if header < offset+20 || header > len(raw) {
		return errors.New("invalid TCP header")
	}
	payload := len(raw) - header
	count := max(1, (payload+mss-1)/mss)
	flags := raw[offset+13]
	sequence := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
	v4 := raw[0]>>4 == 4
	for i := range count {
		start := header + i*mss
		end := min(start+mss, len(raw))
		out := make([]byte, header+end-start)
		copy(out, raw[:header])
		copy(out[header:], raw[start:end])
		tcp := out[offset:]
		binary.BigEndian.PutUint32(tcp[4:8], sequence+uint32(i*mss))
		segmentFlags := flags
		if i != count-1 {
			segmentFlags &^= TCPFin | TCPPsh
		}
		if i != 0 {
			segmentFlags &^= TCPCwr
		}
		tcp[13] = segmentFlags
		if v4 {
			binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
			binary.BigEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(raw[4:6])+uint16(i))
			binary.BigEndian.PutUint16(out[10:12], 0)
			binary.BigEndian.PutUint16(out[10:12], ^fold(sum(out[:offset], 0)))
		} else {
			binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
		}
		binary.BigEndian.PutUint16(tcp[16:18], 0)
		pseudo := uint32(6) + uint32(len(tcp))
		if v4 {
			pseudo = sum(out[12:20], pseudo)
		} else {
			pseudo = sum(out[8:40], pseudo)
		}
		binary.BigEndian.PutUint16(tcp[16:18], ^fold(sum(tcp, pseudo)))
		if err := emit(out); err != nil {
			return err
		}
	}
	return nil
}

func sum(b []byte, initial uint32) uint32 {
	s := initial
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return uint16(s)
}

// TCPHeaderLength returns the IP and TCP header bytes before the TCP payload.
func TCPHeaderLength(raw []byte) (int, bool) {
	offset := tcpOffset(raw)
	if offset < 0 || offset+20 > len(raw) {
		return 0, false
	}
	header := offset + int(raw[offset+12]>>4)*4
	return header, header >= offset+20 && header <= len(raw)
}
