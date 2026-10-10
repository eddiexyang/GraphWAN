package packet

import "encoding/binary"

// IsTCP recognizes TCP behind IPv4 options and IPv6 extension headers. Fragmented
// TCP enters the local stack for reassembly; it must never fall back to IP tunneling.
// InspectAddresses must validate the base IP header before calling this function.
func IsTCP(raw []byte) bool {
	if len(raw) < 20 {
		return false
	}
	if raw[0]>>4 == 4 {
		return raw[9] == 6
	}
	if raw[0]>>4 != 6 || len(raw) < 40 {
		return false
	}
	next, offset := raw[6], 40
	for i := 0; i < 16; i++ {
		switch next {
		case 6:
			return true
		case 0, 43, 60:
			if offset+2 > len(raw) {
				return false
			}
			size := (int(raw[offset+1]) + 1) * 8
			next, offset = raw[offset], offset+size
		case 51:
			if offset+2 > len(raw) {
				return false
			}
			size := (int(raw[offset+1]) + 2) * 4
			next, offset = raw[offset], offset+size
		case 44:
			if offset+8 > len(raw) {
				return false
			}
			// Extensions after a noninitial fragment require access-side cached
			// classification. Such UDP fragments remain valid packet payloads.
			if binary.BigEndian.Uint16(raw[offset+2:offset+4])&0xfff8 != 0 {
				return raw[offset] == 6
			}
			next, offset = raw[offset], offset+8
		default:
			return false
		}
		if offset > len(raw) {
			return false
		}
	}
	return false
}
