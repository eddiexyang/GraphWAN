//go:build linux

package tunnel

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/eWloYW8/GraphWAN/internal/packet"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// decodeOffloadRead keeps TCP in the large segments already produced by Linux.
// gVisor validates complete checksums, so finish CHECKSUM_PARTIAL once for the
// whole packet rather than splitting, copying and checksumming every MSS first.
// UDP segmentation follows WireGuard's native TUN adapter and preserves each
// datagram's length, IPv4 ID and checksum before it enters graph forwarding.
func decodeOffloadRead(input []byte, buffers [][]byte, sizes, segmentSizes []int, borrowTCP ...bool) (int, error) {
	if len(input) < 10 {
		return 0, errors.New("invalid TUN offload input")
	}
	return decodeOffloadPacket(input[:10], input[10:], buffers, sizes, segmentSizes, len(borrowTCP) > 0 && borrowTCP[0], false)
}

func decodeOffloadPacket(virtio, raw []byte, buffers [][]byte, sizes, segmentSizes []int, borrow, checksumOffload bool) (int, error) {
	if len(virtio) != 10 || len(buffers) == 0 || len(sizes) < len(buffers) || len(segmentSizes) < len(buffers) {
		return 0, errors.New("invalid TUN offload input")
	}
	clear(segmentSizes)
	flags, kind := virtio[0], virtio[1]&^byte(unix.VIRTIO_NET_HDR_GSO_ECN)
	mss := int(binary.LittleEndian.Uint16(virtio[4:6]))
	start := int(binary.LittleEndian.Uint16(virtio[6:8]))
	offset := int(binary.LittleEndian.Uint16(virtio[8:10]))
	info, err := packet.InspectAddresses(raw)
	if err != nil {
		return 0, err
	}
	if kind == unix.VIRTIO_NET_HDR_GSO_NONE {
		if flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 && !(checksumOffload && kernelTCPChecksumOffload(virtio, raw)) {
			if start+offset+2 > len(raw) {
				return 0, errors.New("invalid TUN checksum offset")
			}
			// Linux stores the pseudo-header seed in the checksum field.
			initial := binary.BigEndian.Uint16(raw[start+offset:])
			binary.BigEndian.PutUint16(raw[start+offset:], 0)
			binary.BigEndian.PutUint16(raw[start+offset:], ^checksum.Checksum(raw[start:], initial))
		}
		if borrow && packet.IsTCP(raw) {
			buffers[0], sizes[0] = raw, len(raw)
			return 1, nil
		}
		if len(raw) > len(buffers[0]) {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(buffers[0], raw)
		return 1, nil
	}
	if mss == 0 || start < 20 || start > len(raw) || info.Source.Is6() && start < 40 {
		return 0, errors.New("invalid TUN segmentation metadata")
	}
	transportStart, transportProtocol := offloadTransport(raw)
	if transportStart != start {
		return 0, errors.New("TUN checksum start disagrees with IP headers")
	}
	var protocol tcpip.TransportProtocolNumber
	var headerSize int
	switch kind {
	case unix.VIRTIO_NET_HDR_GSO_TCPV4, unix.VIRTIO_NET_HDR_GSO_TCPV6:
		if transportProtocol != unix.IPPROTO_TCP || (kind == unix.VIRTIO_NET_HDR_GSO_TCPV4) != info.Source.Is4() || offset != 16 || start+20 > len(raw) {
			return 0, errors.New("invalid TUN TCP offload")
		}
		headerSize = start + int(raw[start+12]>>4)*4
		if headerSize < start+20 || headerSize > start+60 || headerSize >= len(raw) {
			return 0, errors.New("invalid TUN TCP header")
		}
		protocol = unix.IPPROTO_TCP
	case unix.VIRTIO_NET_HDR_GSO_UDP_L4:
		if transportProtocol != unix.IPPROTO_UDP || offset != 6 || start+8 >= len(raw) {
			return 0, errors.New("invalid TUN UDP offload")
		}
		headerSize, protocol = start+8, unix.IPPROTO_UDP
	default:
		return 0, errors.New("unsupported TUN offload type")
	}
	finishChecksum := func(out []byte) {
		var source, destination tcpip.Address
		if info.Source.Is4() {
			source, destination = header.IPv4(out).SourceAddress(), header.IPv4(out).DestinationAddress()
			binary.BigEndian.PutUint16(out[10:], 0)
			binary.BigEndian.PutUint16(out[10:], ^checksum.Checksum(out[:int(out[0]&15)*4], 0))
		} else {
			source, destination = header.IPv6(out).SourceAddress(), header.IPv6(out).DestinationAddress()
		}
		binary.BigEndian.PutUint16(out[start+offset:], 0)
		seed := header.PseudoHeaderChecksum(protocol, source, destination, uint16(len(out)-start))
		value := ^checksum.Checksum(out[start:], seed)
		if value == 0 && protocol == unix.IPPROTO_UDP {
			value = 0xffff
		}
		binary.BigEndian.PutUint16(out[start+offset:], value)
	}
	if protocol == unix.IPPROTO_TCP {
		if !borrow && len(raw) > len(buffers[0]) {
			return 0, io.ErrShortBuffer
		}
		if checksumOffload && kernelTCPChecksumOffload(virtio, raw) {
			// Keep Linux's transport checksum state. Only the small IPv4
			// header needs normalization for the large ingress segment.
			if info.Source.Is4() {
				binary.BigEndian.PutUint16(raw[10:], 0)
				binary.BigEndian.PutUint16(raw[10:], ^checksum.Checksum(raw[:int(raw[0]&15)*4], 0))
			}
		} else {
			finishChecksum(raw)
		}
		if borrow {
			buffers[0], sizes[0] = raw, len(raw)
		} else {
			sizes[0] = copy(buffers[0], raw)
		}
		segmentSizes[0] = headerSize + min(mss, len(raw)-headerSize)
		return 1, nil
	}
	count := (len(raw) - headerSize + mss - 1) / mss
	if count > len(buffers) {
		return 0, io.ErrShortBuffer
	}
	for i := range count {
		payload := raw[headerSize+i*mss : min(headerSize+(i+1)*mss, len(raw))]
		size := headerSize + len(payload)
		if size > len(buffers[i]) {
			return 0, io.ErrShortBuffer
		}
		out := buffers[i][:size]
		copy(out, raw[:headerSize])
		copy(out[headerSize:], payload)
		if info.Source.Is4() {
			binary.BigEndian.PutUint16(out[2:], uint16(size))
			binary.BigEndian.PutUint16(out[4:], binary.BigEndian.Uint16(raw[4:])+uint16(i))
		} else {
			binary.BigEndian.PutUint16(out[4:], uint16(size-40))
		}
		binary.BigEndian.PutUint16(out[start+4:], uint16(size-start))
		finishChecksum(out)
		sizes[i] = size
	}
	return count, nil
}

// Only kernel-described, unfragmented TCP may retain checksum offload. A
// partial checksum must identify the actual TCP checksum field, not just an
// arbitrary in-bounds offset. Full packet injection retains normal validation.
func kernelTCPChecksumOffload(virtio, raw []byte) bool {
	if len(virtio) != 10 || len(raw) < 20 || virtio[0]&(unix.VIRTIO_NET_HDR_F_NEEDS_CSUM|unix.VIRTIO_NET_HDR_F_DATA_VALID) == 0 {
		return false
	}
	start, protocol := offloadTransport(raw)
	if protocol != unix.IPPROTO_TCP || start < 0 || start+20 > len(raw) {
		return false
	}
	headerSize := int(raw[start+12]>>4) * 4
	if headerSize < 20 || start+headerSize > len(raw) {
		return false
	}
	return virtio[0]&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM == 0 ||
		int(binary.LittleEndian.Uint16(virtio[6:8])) == start && binary.LittleEndian.Uint16(virtio[8:10]) == 16
}

// GSO represents a complete transport segment, never IP fragments. Derive the
// transport offset instead of trusting hdr_len or csum_start from virtio alone.
func offloadTransport(raw []byte) (int, byte) {
	if raw[0]>>4 == 4 {
		if binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
			return -1, 0
		}
		return int(raw[0]&15) * 4, raw[9]
	}
	next, offset := raw[6], 40
	for range 16 {
		switch next {
		case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
			return offset, next
		case 0, 43, 60, 51:
			if offset+2 > len(raw) {
				return -1, 0
			}
			size := (int(raw[offset+1]) + 1) * 8
			if next == 51 {
				size = (int(raw[offset+1]) + 2) * 4
			}
			next, offset = raw[offset], offset+size
			if offset > len(raw) {
				return -1, 0
			}
		default:
			return -1, 0
		}
	}
	return -1, 0
}
