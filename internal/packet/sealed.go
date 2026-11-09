package packet

import "encoding/binary"

// A packet sealed end to end between its source and destination Nodes keeps
// its IP header and, unless it is a later fragment, the 8-byte header of a
// UDP, ICMP or ICMPv6 packet readable, so every hop can route and admit it.
// The rest is sealed in place and Trailer bytes follow the IP packet: the
// packet's sequence, its session and the tag. The overlay header's Sealed
// flag marks such a frame; the frame's payload is then the IP packet and its
// trailer.
const (
	Trailer = 24
	// Sealed is the overlay header's flag byte value for a sealed packet.
	Sealed = 1
	// MaxReadable bounds HeaderLen: an IPv4 header with options and 8 bytes.
	MaxReadable = 60 + 8
)

// IsSealed reports a frame whose header carries the Sealed flag.
func IsSealed(frame []byte) bool { return frame[6] == Sealed }

// SetSealed sets or clears a frame's Sealed flag.
func SetSealed(frame []byte, sealed bool) {
	frame[6] = 0
	if sealed {
		frame[6] = Sealed
	}
}

// IPOf returns the IP packet of a frame's payload, without its trailer.
func IPOf(payload []byte, sealed bool) ([]byte, bool) {
	if !sealed {
		return payload, true
	}
	if len(payload) <= Trailer {
		return nil, false
	}
	return payload[:len(payload)-Trailer], true
}

// HeaderLen returns how many leading bytes of raw, an IP packet that
// InspectAddresses accepted, travel readable when it is sealed: the IP header,
// and the 8-byte header of a UDP, ICMP or ICMPv6 packet that is not a later
// fragment.
func HeaderLen(raw []byte) int {
	var header, protocol int
	if raw[0]>>4 == 4 {
		header, protocol = int(raw[0]&15)*4, int(raw[9])
		if binary.BigEndian.Uint16(raw[6:8])&0x1fff != 0 {
			return header
		}
	} else {
		header, protocol = 40, int(raw[6])
	}
	switch protocol {
	case 1, 17, 58:
		if len(raw) >= header+8 {
			return header + 8
		}
	}
	return header
}

// Authenticated writes raw's readable headers to dst as a seal authenticates
// them: without the fields hops change, the hop limit and the IPv4 header
// checksum, without ECN, which a congested hop may mark, and without the L4
// checksum, which the destination computes again (RestoreChecksums).
func Authenticated(dst *[MaxReadable]byte, raw []byte) []byte {
	ad := dst[:copy(dst[:], raw[:HeaderLen(raw)])]
	header := 40
	if ad[0]>>4 == 4 {
		header = int(ad[0]&15) * 4
		ad[1] &^= 3
		ad[8] = 0
		ad[10], ad[11] = 0, 0
	} else {
		ad[1] &^= 0x30
		ad[7] = 0
	}
	if len(ad) > header {
		if l4 := ad[header:]; protocolOf(ad) == 17 {
			l4[6], l4[7] = 0, 0
		} else {
			l4[2], l4[3] = 0, 0
		}
	}
	return ad
}

func protocolOf(raw []byte) byte {
	if raw[0]>>4 == 4 {
		return raw[9]
	}
	return raw[6]
}

// RestoreChecksums computes the IPv4 header checksum and the UDP, ICMP or
// ICMPv6 checksum of an opened sealed packet again, as its seal does not
// authenticate them. A fragment keeps its L4 checksum, which covers the whole
// datagram.
func RestoreChecksums(raw []byte) {
	header := 40
	if raw[0]>>4 == 4 {
		header = int(raw[0]&15) * 4
		raw[10], raw[11] = 0, 0
		binary.BigEndian.PutUint16(raw[10:12], ipChecksum(raw[:header]))
		if binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
			return
		}
	}
	if HeaderLen(raw) == header {
		return
	}
	protocol, l4 := protocolOf(raw), raw[header:]
	var sum uint32
	if protocol != 1 {
		// The pseudo-header: addresses, L4 length and protocol.
		if header == 40 {
			sum = checksumAdd(sum, raw[8:40])
		} else {
			sum = checksumAdd(sum, raw[12:20])
		}
		sum += uint32(len(l4)>>16) + uint32(len(l4)&0xffff) + uint32(protocol)
	}
	at := 2
	if protocol == 17 {
		at = 6
	}
	l4[at], l4[at+1] = 0, 0
	checksum := checksumFold(checksumAdd(sum, l4))
	if checksum == 0 && protocol == 17 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(l4[at:at+2], checksum)
}

// checksumAdd adds raw's 16-bit words to sum, the last byte padded with zero.
func checksumAdd(sum uint32, raw []byte) uint32 {
	for len(raw) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(raw))
		raw = raw[2:]
	}
	if len(raw) > 0 {
		sum += uint32(raw[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
