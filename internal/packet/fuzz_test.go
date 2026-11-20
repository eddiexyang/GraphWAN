package packet

import (
	"bytes"
	"net/netip"
	"testing"
)

// Peers and local applications choose every byte these parsers see; none of
// them may panic or read past the packet, whatever arrives.
func FuzzPacketParsers(f *testing.F) {
	f.Add(UDP(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:2"), []byte("payload")))
	f.Add(UDP(netip.MustParseAddrPort("[fd00::1]:1"), netip.MustParseAddrPort("[fd00::2]:2"), []byte("payload")))
	f.Add(make([]byte, HeaderSize+20))
	f.Fuzz(func(t *testing.T, raw []byte) {
		ParseView(raw)
		ReadFrame(bytes.NewReader(raw))
		IsTCP(raw)
		IsUDP(raw)
		HasExtensionFragment(raw)
		var classifier FragmentClassifier
		classifier.Classify(bytes.Clone(raw))
		UDPDatagram(raw)
		TCPFlow(raw)
		TCPHeaderLength(raw)
		if _, err := InspectIP(raw); err != nil {
			return
		}
		HeaderLen(raw)
		var readable [MaxReadable]byte
		Authenticated(&readable, raw)
		IPOf(raw, true)
		IPHopLimit(raw)
		DecrementIPHopLimit(bytes.Clone(raw))
		RestoreChecksums(bytes.Clone(raw))
		TimeExceeded(raw, netip.MustParseAddr("10.0.0.9"))
		TCPReset(raw)
		SegmentTCP(bytes.Clone(raw), 536, func([]byte) error { return nil })
	})
}
