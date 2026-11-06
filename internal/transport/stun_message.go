package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
)

// RFC 8489 message encoding, limited to what a Binding client needs.
const (
	stunMagicCookie    = 0x2112a442
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunBindingError   = 0x0111

	stunAttrErrorCode          = 0x0009
	stunAttrMessageIntegrity   = 0x0008
	stunAttrXORMappedAddress   = 0x0020
	stunAttrIntegritySHA256    = 0x001c
	stunAttrFingerprint        = 0x8028
	stunFingerprintXOR         = 0x5354554e
	stunLegacyXORMappedAddress = 0x8020 // draft-ietf-behave-rfc3489bis-02, MS-TURN
)

// stunKnownRequired lists the comprehension-required attributes of STUN, TURN
// and ICE that a response may carry. Any other one rejects the response.
var stunKnownRequired = map[uint16]bool{
	0x0001: true, 0x0006: true, 0x0008: true, 0x0009: true, 0x000a: true,
	0x000c: true, 0x000d: true, 0x0012: true, 0x0013: true, 0x0014: true,
	0x0015: true, 0x0016: true, 0x0017: true, 0x0018: true, 0x0019: true,
	0x001a: true, 0x001c: true, 0x001d: true, 0x001e: true, 0x0020: true,
	0x0022: true, 0x0024: true, 0x0025: true, 0x002a: true,
}

type stunAttribute struct {
	kind  uint16
	value []byte
}

// stunRequest returns a Binding request with a random transaction ID and a
// FINGERPRINT.
func stunRequest() (raw []byte, id [12]byte, err error) {
	if _, err = rand.Read(id[:]); err != nil {
		return nil, id, err
	}
	raw = make([]byte, 28)
	binary.BigEndian.PutUint16(raw[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(raw[2:4], 8)
	binary.BigEndian.PutUint32(raw[4:8], stunMagicCookie)
	copy(raw[8:20], id[:])
	binary.BigEndian.PutUint16(raw[20:22], stunAttrFingerprint)
	binary.BigEndian.PutUint16(raw[22:24], 4)
	binary.BigEndian.PutUint32(raw[24:28], crc32.ChecksumIEEE(raw[:20])^stunFingerprintXOR)
	return raw, id, nil
}

// decodeSTUN splits a whole message into attributes. Attributes after a
// MESSAGE-INTEGRITY other than those RFC 8489 allows there are dropped.
func decodeSTUN(raw []byte) ([]stunAttribute, error) {
	if len(raw) < 20 || binary.BigEndian.Uint32(raw[4:8]) != stunMagicCookie {
		return nil, errors.New("invalid STUN header")
	}
	size := int(binary.BigEndian.Uint16(raw[2:4]))
	if len(raw) < 20+size {
		return nil, errors.New("truncated STUN message")
	}
	var attributes []stunAttribute
	var integrity, integritySHA256 bool
	for b := raw[20 : 20+size]; len(b) > 0; {
		if len(b) < 4 {
			return nil, errors.New("truncated STUN attribute header")
		}
		kind, length := binary.BigEndian.Uint16(b[0:2]), int(binary.BigEndian.Uint16(b[2:4]))
		if kind == stunLegacyXORMappedAddress {
			kind = stunAttrXORMappedAddress
		}
		padded := (length + 3) &^ 3
		b = b[4:]
		if len(b) < padded {
			return nil, errors.New("truncated STUN attribute")
		}
		value := b[:length]
		b = b[padded:]
		trailing := kind == stunAttrIntegritySHA256 || kind == stunAttrFingerprint
		if integrity && !trailing || !integrity && integritySHA256 && kind != stunAttrFingerprint {
			continue
		}
		attributes = append(attributes, stunAttribute{kind: kind, value: value})
		integrity = integrity || kind == stunAttrMessageIntegrity
		integritySHA256 = integritySHA256 || kind == stunAttrIntegritySHA256
	}
	return attributes, nil
}

func stunGet(attributes []stunAttribute, kind uint16) ([]byte, bool) {
	for _, attribute := range attributes {
		if attribute.kind == kind {
			return attribute.value, true
		}
	}
	return nil, false
}

func parseSTUNResponse(raw []byte, ipv4 bool) (stunResult, bool) {
	attributes, err := decodeSTUN(raw)
	if err != nil {
		return stunResult{}, false
	}
	if fingerprint, ok := stunGet(attributes, stunAttrFingerprint); ok {
		end := len(raw) - 8
		if attributes[len(attributes)-1].kind != stunAttrFingerprint || len(fingerprint) != 4 || end < 20 ||
			binary.BigEndian.Uint32(fingerprint) != crc32.ChecksumIEEE(raw[:end])^stunFingerprintXOR {
			return stunResult{}, false
		}
	}
	for _, attribute := range attributes {
		if attribute.kind < 0x8000 && !stunKnownRequired[attribute.kind] {
			return stunResult{err: errors.New("unknown required STUN attribute")}, true
		}
	}
	switch binary.BigEndian.Uint16(raw[0:2]) {
	case stunBindingError:
		value, ok := stunGet(attributes, stunAttrErrorCode)
		if !ok || len(value) < 4 {
			return stunResult{}, false
		}
		return stunResult{err: fmt.Errorf("STUN binding rejected: %d", int(value[2]&7)*100+int(value[3]))}, true
	case stunBindingSuccess:
	default:
		return stunResult{}, false
	}
	value, ok := stunGet(attributes, stunAttrXORMappedAddress)
	if !ok || len(value) < 8 {
		return stunResult{}, false
	}
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
	copy(mask[4:], raw[8:20])
	var ip netip.Addr
	switch family, address := binary.BigEndian.Uint16(value[0:2]), value[4:]; {
	case family == 1 && len(address) == 4:
		ip = netip.AddrFrom4([4]byte{address[0] ^ mask[0], address[1] ^ mask[1], address[2] ^ mask[2], address[3] ^ mask[3]})
	case family == 2 && len(address) == 16:
		var v6 [16]byte
		for i := range v6 {
			v6[i] = address[i] ^ mask[i]
		}
		ip = netip.AddrFrom16(v6).Unmap()
	default:
		return stunResult{}, false
	}
	port := binary.BigEndian.Uint16(value[2:4]) ^ stunMagicCookie>>16
	if !stunUnicast(ip) || ip.Is4() != ipv4 || port == 0 {
		return stunResult{}, false
	}
	return stunResult{address: netip.AddrPortFrom(ip, port)}, true
}
