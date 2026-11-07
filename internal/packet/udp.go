package packet

import (
	"encoding/binary"
	"net/netip"
)

// UDP builds an unfragmented UDP packet with complete checksums. It returns nil
// for mismatched address families.
func UDP(source, destination netip.AddrPort, payload []byte) []byte {
	if source.Addr().Is4() != destination.Addr().Is4() {
		return nil
	}
	header := 40
	if source.Addr().Is4() {
		header = 20
	}
	out := make([]byte, header+8+len(payload))
	udp := out[header:]
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	pseudo := make([]byte, 0, 40+len(udp))
	if source.Addr().Is4() {
		out[0], out[8], out[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		s, d := source.Addr().As4(), destination.Addr().As4()
		copy(out[12:16], s[:])
		copy(out[16:20], d[:])
		binary.BigEndian.PutUint16(out[10:12], ipChecksum(out[:20]))
		pseudo = append(append(append(pseudo, s[:]...), d[:]...), 0, 17)
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(udp)))
	} else {
		out[0], out[6], out[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(out[4:6], uint16(len(udp)))
		s, d := source.Addr().As16(), destination.Addr().As16()
		copy(out[8:24], s[:])
		copy(out[24:40], d[:])
		pseudo = append(append(pseudo, s[:]...), d[:]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(udp)))
		pseudo = append(pseudo, 0, 0, 0, 17)
	}
	checksum := ipChecksum(append(pseudo, udp...))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return out
}

// UDPDatagram returns the addresses, ports and payload of an unfragmented UDP
// packet without IPv6 extension headers.
func UDPDatagram(raw []byte) (source, destination netip.AddrPort, payload []byte, ok bool) {
	var header int
	var src, dst netip.Addr
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4:
		header = int(raw[0]&15) * 4
		if raw[9] != 17 || header < 20 || binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
			return
		}
		src, dst = netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20]))
	case len(raw) >= 40 && raw[0]>>4 == 6:
		if raw[6] != 17 {
			return
		}
		header = 40
		src, dst = netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
	default:
		return
	}
	if header+8 > len(raw) {
		return
	}
	udp := raw[header:]
	size := int(binary.BigEndian.Uint16(udp[4:6]))
	if size < 8 || size > len(udp) {
		return
	}
	source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(udp[0:2]))
	destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(udp[2:4]))
	return source, destination, udp[8:size], true
}

// IsUDP reports UDP in the base IPv4 or IPv6 header of a validated packet.
func IsUDP(raw []byte) bool {
	switch raw[0] >> 4 {
	case 4:
		return len(raw) >= 20 && raw[9] == 17
	case 6:
		return len(raw) >= 40 && raw[6] == 17
	}
	return false
}
