package packet

import "encoding/binary"

// TCPReset answers a TCP packet with a reset from its destination to its
// source, as RFC 9293 prescribes for a segment without a connection. It
// returns nil for resets and for packets it cannot parse.
func TCPReset(raw []byte) []byte {
	source, destination, flags, ok := TCPFlow(raw)
	if !ok || flags&TCPRst != 0 {
		return nil
	}
	offset := tcpOffset(raw)
	tcp := raw[offset:]
	dataOffset := int(tcp[12]>>4) * 4
	total := len(raw)
	if raw[0]>>4 == 4 {
		total = int(binary.BigEndian.Uint16(raw[2:4]))
	} else {
		total = 40 + int(binary.BigEndian.Uint16(raw[4:6]))
	}
	if dataOffset < 20 || offset+dataOffset > total || total > len(raw) {
		return nil
	}
	// The reply reuses the UDP builder's IP header and pseudo-header layout.
	out := UDP(destination, source, make([]byte, 12))
	if out == nil {
		return nil
	}
	header := 20
	if source.Addr().Is6() {
		header = 40
	}
	reply := out[header:]
	clear(reply)
	binary.BigEndian.PutUint16(reply[0:2], destination.Port())
	binary.BigEndian.PutUint16(reply[2:4], source.Port())
	if flags&TCPAck != 0 {
		copy(reply[4:8], tcp[8:12])
		reply[13] = TCPRst
	} else {
		length := uint32(total - offset - dataOffset)
		if flags&TCPSyn != 0 {
			length++
		}
		if flags&TCPFin != 0 {
			length++
		}
		binary.BigEndian.PutUint32(reply[8:12], binary.BigEndian.Uint32(tcp[4:8])+length)
		reply[13] = TCPRst | TCPAck
	}
	reply[12] = 5 << 4
	pseudo := make([]byte, 0, 40+len(reply))
	if header == 20 {
		out[9] = 6
		binary.BigEndian.PutUint16(out[10:12], 0)
		binary.BigEndian.PutUint16(out[10:12], ipChecksum(out[:20]))
		pseudo = append(append(pseudo, out[12:20]...), 0, 6)
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(reply)))
	} else {
		out[6] = 6
		pseudo = append(pseudo, out[8:40]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(reply)))
		pseudo = append(pseudo, 0, 0, 0, 6)
	}
	binary.BigEndian.PutUint16(reply[16:18], ipChecksum(append(pseudo, reply...)))
	return out
}
