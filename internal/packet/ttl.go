package packet

import (
	"encoding/binary"
	"net/netip"
)

// IPHopLimit requires a packet already validated by InspectAddresses.
func IPHopLimit(raw []byte) byte {
	if raw[0]>>4 == 4 {
		return raw[8]
	}
	return raw[7]
}

// DecrementIPHopLimit mutates an owned, validated packet with a hop limit > 1.
func DecrementIPHopLimit(raw []byte) {
	if raw[0]>>4 == 6 {
		raw[7]--
		return
	}
	raw[8]--
	raw[10], raw[11] = 0, 0
	binary.BigEndian.PutUint16(raw[10:12], ipChecksum(raw[:int(raw[0]&15)*4]))
}

// TimeExceeded quotes the original packet, bounded by the IP minimum MTU.
// A nil reply suppresses errors to errors, noninitial fragments, multicast and
// invalid sources. Unknown/malformed IPv6 extension chains are suppressed too.
func TimeExceeded(raw []byte, source netip.Addr) []byte {
	info, err := InspectAddresses(raw)
	if err != nil || !source.IsGlobalUnicast() || source.Is4() != info.Source.Is4() ||
		!info.Source.IsGlobalUnicast() || !info.Destination.IsGlobalUnicast() {
		return nil
	}
	header, limit := 20, 576
	if source.Is4() {
		offset := int(raw[0]&15) * 4
		if ipChecksum(raw[:offset]) != 0 || binary.BigEndian.Uint16(raw[6:8])&0x1fff != 0 || raw[12] == 0 {
			return nil
		}
		if raw[9] == 1 {
			if offset >= len(raw) {
				return nil
			}
			switch raw[offset] {
			case 3, 4, 5, 11, 12:
				return nil
			}
		}
	} else {
		header, limit = 40, 1280
		next, offset := raw[6], 40
		for {
			if offset >= len(raw) {
				return nil
			}
			switch next {
			case 0, 43, 60, 51:
				if offset+2 > len(raw) {
					return nil
				}
				size := (int(raw[offset+1]) + 1) * 8
				if next == 51 {
					size = (int(raw[offset+1]) + 2) * 4
				}
				next, offset = raw[offset], offset+size
				continue
			case 44:
				if offset+8 > len(raw) || binary.BigEndian.Uint16(raw[offset+2:offset+4])&0xfff8 != 0 {
					return nil
				}
				next, offset = raw[offset], offset+8
				continue
			case 58:
				if raw[offset] < 128 || raw[offset] == 137 {
					return nil
				}
			case 6, 17:
			default:
				return nil
			}
			break
		}
	}
	out := make([]byte, header+8+min(len(raw), limit-header-8))
	msg := out[header:]
	copy(msg[8:], raw)
	if source.Is4() {
		out[0], out[8], out[9], msg[0] = 0x45, 64, 1, 11
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		s, d := source.As4(), info.Source.As4()
		copy(out[12:16], s[:])
		copy(out[16:20], d[:])
		binary.BigEndian.PutUint16(out[10:12], ipChecksum(out[:20]))
		binary.BigEndian.PutUint16(msg[2:4], ipChecksum(msg))
	} else {
		out[0], out[6], out[7], msg[0] = 0x60, 58, 64, 3
		binary.BigEndian.PutUint16(out[4:6], uint16(len(msg)))
		s, d := source.As16(), info.Source.As16()
		copy(out[8:24], s[:])
		copy(out[24:40], d[:])
		pseudo := make([]byte, 40+len(msg))
		copy(pseudo, out[8:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
		pseudo[39] = 58
		copy(pseudo[40:], msg)
		binary.BigEndian.PutUint16(msg[2:4], ipChecksum(pseudo))
	}
	return out
}

func ipChecksum(raw []byte) uint16 {
	var sum uint32
	for len(raw) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(raw))
		raw = raw[2:]
	}
	if len(raw) > 0 {
		sum += uint32(raw[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
