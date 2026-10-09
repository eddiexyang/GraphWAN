package packet

import "testing"

func TestTCPWithIPOptionsExtensionsAndFragments(t *testing.T) {
	v4 := make([]byte, 44)
	v4[0], v4[9] = 0x46, 6
	if !IsTCP(v4) {
		t.Fatal("IPv4 options hid TCP")
	}
	v4[6] = 0x20
	if !IsTCP(v4) {
		t.Fatal("fragmented IPv4 TCP escaped")
	}
	v6 := make([]byte, 76)
	v6[0], v6[6] = 0x60, 0
	v6[40], v6[48], v6[56] = 43, 44, 6
	if !IsTCP(v6) {
		t.Fatal("IPv6 extensions hid TCP")
	}
	v6[58] = 0x10
	if !IsTCP(v6) {
		t.Fatal("fragmented IPv6 TCP escaped")
	}
	v6[56] = 17
	if IsTCP(v6) {
		t.Fatal("UDP classified as TCP")
	}
	if IsTCP(v6[:45]) {
		t.Fatal("truncated extension chain classified as TCP")
	}
}
