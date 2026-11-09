package packet

import "encoding/binary"

// A packet sealed end to end between its source and destination Nodes keeps
// its IP header and, unless it is a later fragment, the 8-byte header of a
// UDP, ICMP or ICMPv6 packet readable, so every hop can route and admit it.
// The rest is sealed in place and Trailer bytes follow the IP packet: the tag,
// the packet's sequence and its session. The overlay header's Sealed flag
// marks such a frame; the frame's payload is then the IP packet and its
// trailer.
const (
	Trailer = 24
	// Sealed is the overlay header's flag byte value for a sealed packet.
	Sealed = 1
	// MaxReadable bounds Readable: an IPv4 header with options and 8 bytes.
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

// Readable returns how many leading bytes of raw, an IP packet that
// InspectAddresses accepted, travel readable when it is sealed.
func Readable(raw []byte) int {
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
// checksum, and without ECN, which a congested hop may mark.
func Authenticated(dst *[MaxReadable]byte, raw []byte) []byte {
	ad := dst[:copy(dst[:], raw[:Readable(raw)])]
	if ad[0]>>4 == 4 {
		ad[1] &^= 3
		ad[8] = 0
		ad[10], ad[11] = 0, 0
	} else {
		ad[1] &^= 0x30
		ad[7] = 0
	}
	return ad
}
