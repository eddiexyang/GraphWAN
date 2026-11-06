package transport

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"net/netip"
	"strings"
	"testing"
)

func stunVector(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// RFC 5769 sections 2.2 and 2.3.
const (
	rfc5769IPv4 = `0101003c 2112a442 b7e7a701 bc34d686 fa87dfae
		8022000b 74657374 20766563 746f7220
		00200008 0001a147 e112a643
		00080014 2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7
		80280004 c07d4c96`
	rfc5769IPv6 = `01010048 2112a442 b7e7a701 bc34d686 fa87dfae
		8022000b 74657374 20766563 746f7220
		00200014 0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9
		00080014 a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41
		80280004 c8fb0b4c`
)

func TestSTUNResponseVectors(t *testing.T) {
	for _, test := range []struct {
		raw  string
		ipv4 bool
		want string
	}{
		{rfc5769IPv4, true, "192.0.2.1:32853"},
		{rfc5769IPv6, false, "[2001:db8:1234:5678:11:2233:4455:6677]:32853"},
	} {
		result, ok := parseSTUNResponse(stunVector(t, test.raw), test.ipv4)
		if !ok || result.err != nil || result.address != netip.MustParseAddrPort(test.want) {
			t.Fatalf("parse = %v, %v; want %s", result, ok, test.want)
		}
		if _, ok := parseSTUNResponse(stunVector(t, test.raw), !test.ipv4); ok {
			t.Fatal("accepted a mapping of the other family")
		}
	}
}

func TestSTUNRejectsBadFingerprint(t *testing.T) {
	raw := stunVector(t, rfc5769IPv4)
	raw[len(raw)-1] ^= 1
	if _, ok := parseSTUNResponse(raw, true); ok {
		t.Fatal("accepted a bad fingerprint")
	}
}

// stunResponse builds a response to id with the given attributes and a
// fingerprint.
func stunResponse(kind uint16, id [12]byte, attributes ...stunAttribute) []byte {
	raw := make([]byte, 20)
	binary.BigEndian.PutUint16(raw[0:2], kind)
	binary.BigEndian.PutUint32(raw[4:8], stunMagicCookie)
	copy(raw[8:20], id[:])
	attributes = append(attributes, stunAttribute{kind: stunAttrFingerprint, value: make([]byte, 4)})
	for _, attribute := range attributes {
		raw = binary.BigEndian.AppendUint16(raw, attribute.kind)
		raw = binary.BigEndian.AppendUint16(raw, uint16(len(attribute.value)))
		raw = append(raw, attribute.value...)
		raw = append(raw, make([]byte, (4-len(attribute.value)%4)%4)...)
	}
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)-20))
	binary.BigEndian.PutUint32(raw[len(raw)-4:], crc32.ChecksumIEEE(raw[:len(raw)-8])^stunFingerprintXOR)
	return raw
}

func TestSTUNResponseAttributes(t *testing.T) {
	request, id, err := stunRequest()
	if err != nil {
		t.Fatal(err)
	}
	if [12]byte(request[8:20]) != id || binary.BigEndian.Uint32(request[24:28]) != crc32.ChecksumIEEE(request[:20])^stunFingerprintXOR {
		t.Fatalf("request = %x", request)
	}
	mapped := []byte{0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(mapped[2:4], 3478^stunMagicCookie>>16)
	binary.BigEndian.PutUint32(mapped[4:8], 0xcb007105^stunMagicCookie)
	result, ok := parseSTUNResponse(stunResponse(stunBindingSuccess, id, stunAttribute{stunLegacyXORMappedAddress, mapped}), true)
	if !ok || result.err != nil || result.address != netip.MustParseAddrPort("203.0.113.5:3478") {
		t.Fatalf("legacy XOR-MAPPED-ADDRESS: %v, %v", result, ok)
	}
	result, ok = parseSTUNResponse(stunResponse(stunBindingSuccess, id, stunAttribute{0x0031, []byte{1}}, stunAttribute{stunAttrXORMappedAddress, mapped}), true)
	if !ok || result.err == nil {
		t.Fatalf("unknown required attribute: %v, %v", result, ok)
	}
	result, ok = parseSTUNResponse(stunResponse(stunBindingSuccess, id, stunAttribute{0x8031, []byte{1}}, stunAttribute{stunAttrXORMappedAddress, mapped}), true)
	if !ok || result.err != nil {
		t.Fatalf("unknown optional attribute: %v, %v", result, ok)
	}
	result, ok = parseSTUNResponse(stunResponse(stunBindingError, id, stunAttribute{stunAttrErrorCode, []byte{0, 0, 4, 20, 'x'}}), true)
	if !ok || result.err == nil || !strings.Contains(result.err.Error(), "420") {
		t.Fatalf("error response: %v, %v", result, ok)
	}
	if _, ok := parseSTUNResponse(stunResponse(stunBindingSuccess, id), true); ok {
		t.Fatal("accepted a success without a mapping")
	}
	if _, ok := parseSTUNResponse(stunResponse(stunBindingSuccess, id, stunAttribute{stunAttrXORMappedAddress, mapped[:6]}), true); ok {
		t.Fatal("accepted a short mapping")
	}
}
