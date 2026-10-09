package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func extensionFragments(protocol byte) ([]byte, []byte) {
	first, later := make([]byte, 72), make([]byte, 64)
	for _, raw := range [][]byte{first, later} {
		raw[0], raw[6], raw[8], raw[24], raw[40] = 0x60, 44, 0xfd, 0xfd, 60
		binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-40))
		binary.BigEndian.PutUint32(raw[44:48], 1234)
	}
	first[43], first[48] = 1, protocol
	later[43] = 24
	return first, later
}

func TestExtensionFragmentClassificationPreservesUDPAndTCP(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		for _, reordered := range []bool{false, true} {
			var classifier FragmentClassifier
			first, later := extensionFragments(protocol)
			if !HasExtensionFragment(first) || !HasExtensionFragment(later) {
				t.Fatal("extension fragment missed")
			}
			if _, err := InspectAddresses(first); err != nil {
				t.Fatal(err)
			}
			if reordered {
				if _, packets := classifier.Classify(later); len(packets) != 0 {
					t.Fatal("unknown transport forwarded before initial fragment")
				}
			}
			tcp, packets := classifier.Classify(first)
			if tcp != (protocol == 6) || !bytes.Equal(packets[0], first) {
				t.Fatal("initial fragment classification changed")
			}
			if reordered {
				if len(packets) != 2 || !bytes.Equal(packets[1], later) {
					t.Fatal("held fragment changed or disappeared")
				}
			} else {
				tcp, packets = classifier.Classify(later)
				if tcp != (protocol == 6) || len(packets) != 1 || !bytes.Equal(packets[0], later) {
					t.Fatal("later fragment classification changed")
				}
			}
		}
	}
}
