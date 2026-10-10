//go:build linux

package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestNativeTCPWriteReturnsBackpressureWithoutParking(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	fill := make([]byte, 4096)
	for {
		_, err := unix.Write(fd, fill)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("data"))})
	defer packet.DecRef()
	device := &native{file: writer}
	done := make(chan error, 1)
	go func() { done <- device.WriteTCPPacket(packet) }()
	select {
	case err := <-done:
		if !errors.Is(err, unix.EAGAIN) {
			t.Fatal("full native output did not return backpressure", err)
		}
	case <-time.After(time.Second):
		writer.Close()
		t.Fatal("native output parked while holding the stack caller")
	}
}

func datagramReadFixture(t *testing.T) (*native, func([]byte)) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "TUN packet fixture")
	device := &native{file: file}
	t.Cleanup(func() {
		file.Close()
		unix.Close(fds[1])
		if device.ingressView != nil {
			device.ingressView.Release()
		}
	})
	return device, func(packet []byte) {
		t.Helper()
		if n, err := unix.Write(fds[1], packet); err != nil || n != len(packet) {
			t.Fatal(n, err)
		}
	}
}

func ordinaryUDPReadFixture() []byte {
	packet := offloadFixture(false, true)
	packet[1] = unix.VIRTIO_NET_HDR_GSO_NONE
	clear(packet[4:6])
	raw := packet[10:]
	ip := header.IPv4(raw)
	ip.SetChecksum(^checksum.Checksum(raw[:20], 0))
	// CHECKSUM_PARTIAL carries the kernel's pseudo-header seed.
	seed := header.PseudoHeaderChecksum(unix.IPPROTO_UDP, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(raw)-20))
	binary.BigEndian.PutUint16(raw[20+6:], seed)
	return packet
}

func TestOwnedOffloadReadBatchesQueuedDatagrams(t *testing.T) {
	device, write := datagramReadFixture(t)
	packet := ordinaryUDPReadFixture()
	for range 3 {
		write(packet)
	}
	buffers := [][]byte{make([]byte, 65535), make([]byte, 9001), make([]byte, 9001), make([]byte, 9001)}
	sizes, segments := make([]int, 4), make([]int, 4)
	owners := make([]*stack.PacketBuffer, 4)
	n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners)
	if err != nil || n != 3 {
		t.Fatal("queued datagrams lost their read batch", n, err)
	}
	for i := range n {
		if sizes[i] != len(packet)-10 || segments[i] != 0 || owners[i] != nil {
			t.Fatal("datagram ownership or length changed", i)
		}
		verifyOffloadChecksum(t, buffers[i][:sizes[i]], true)
	}
}

func TestOwnedOffloadReadWaitsForFirstPacketAndClose(t *testing.T) {
	device, write := datagramReadFixture(t)
	buffers := [][]byte{make([]byte, 65535), make([]byte, 9001)}
	sizes, segments := make([]int, 2), make([]int, 2)
	owners := make([]*stack.PacketBuffer, 2)
	type result struct {
		count int
		err   error
	}
	done := make(chan result, 1)
	read := func() {
		n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners)
		done <- result{n, err}
	}
	go read()
	select {
	case got := <-done:
		t.Fatal("idle read returned before receiving a packet", got)
	case <-time.After(20 * time.Millisecond):
	}
	write(ordinaryUDPReadFixture())
	select {
	case got := <-done:
		if got.count != 1 || got.err != nil {
			t.Fatal("read waited to fill an incomplete burst", got)
		}
		verifyOffloadChecksum(t, buffers[0][:sizes[0]], true)
	case <-time.After(time.Second):
		t.Fatal("read did not return its available packet")
	}
	go read()
	select {
	case got := <-done:
		t.Fatal("second idle read returned prematurely", got)
	case <-time.After(20 * time.Millisecond):
	}
	if err := device.file.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		// RawConn returns the poll descriptor's closing error without the
		// os.File.Read wrapper that normalizes it to os.ErrClosed.
		if got.count != 0 || got.err == nil {
			t.Fatal("descriptor close did not cancel the empty read", got)
		}
	case <-time.After(time.Second):
		t.Fatal("close left the reader blocked")
	}
}

func BenchmarkOwnedOffloadQueuedDatagrams(b *testing.B) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "TUN packet benchmark")
	device := &native{file: file}
	defer func() {
		file.Close()
		unix.Close(fds[1])
		if device.ingressView != nil {
			device.ingressView.Release()
		}
	}()
	const batch = 32
	packet := ordinaryUDPReadFixture()
	buffers := make([][]byte, batch)
	for i := range buffers {
		buffers[i] = make([]byte, 65535)
	}
	sizes, segments := make([]int, batch), make([]int, batch)
	owners := make([]*stack.PacketBuffer, batch)
	b.ReportAllocs()
	b.SetBytes(int64(batch * (len(packet) - 10)))
	for b.Loop() {
		for range batch {
			if n, err := unix.Write(fds[1], packet); err != nil || n != len(packet) {
				b.Fatal(n, err)
			}
		}
		if n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners); err != nil || n != batch {
			b.Fatal(n, err)
		}
	}
}

func TestOwnedOffloadReadDefersGSOTailWithoutLoss(t *testing.T) {
	device, write := datagramReadFixture(t)
	ordinary := ordinaryUDPReadFixture()
	write(ordinary)
	write(ordinary)
	write(offloadFixture(false, true)) // Expands into three datagrams.
	buffers := [][]byte{make([]byte, 65535), make([]byte, 9001), make([]byte, 9001), make([]byte, 9001)}
	sizes, segments := make([]int, 4), make([]int, 4)
	owners := make([]*stack.PacketBuffer, 4)
	if n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners); n != 2 || err != nil || device.pendingOffloadSize == 0 {
		t.Fatal("GSO tail was dropped at the batch boundary", n, err)
	}
	if n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners); n != 3 || err != nil || device.pendingOffloadSize != 0 {
		t.Fatal("pending GSO datagrams were not delivered", n, err)
	}
	for i := range 3 {
		verifyOffloadChecksum(t, buffers[i][:sizes[i]], true)
	}
}

func TestOwnedOffloadMixedBatchRestoresBorrowedStorage(t *testing.T) {
	device, write := datagramReadFixture(t)
	udp := ordinaryUDPReadFixture()
	write(udp)
	write(offloadFixture(false, false))
	buffers := [][]byte{make([]byte, 65535), make([]byte, 9001), make([]byte, 9001)}
	scratch := buffers[1]
	sizes, segments := make([]int, 3), make([]int, 3)
	owners := make([]*stack.PacketBuffer, 3)
	if n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners); n != 2 || err != nil || owners[1] == nil {
		t.Fatal("mixed batch lost the TCP owner", n, err)
	}
	owner := owners[1]
	original := owner.Data().AsRange().ToSlice()
	owners[1] = nil
	write(udp)
	write(udp)
	if n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners); n != 2 || err != nil || &buffers[1][0] != &scratch[0] || !bytes.Equal(owner.Data().AsRange().ToSlice(), original) {
		t.Fatal("later datagrams overwrote borrowed TCP storage", n, err)
	}
	owner.DecRef()
}

func offloadFixture(v6, udp bool) []byte {
	start, transport, protocol, kind := 20, 20, byte(6), byte(unix.VIRTIO_NET_HDR_GSO_TCPV4)
	if v6 {
		start, kind = 40, unix.VIRTIO_NET_HDR_GSO_TCPV6
	}
	if udp {
		transport, protocol, kind = 8, 17, unix.VIRTIO_NET_HDR_GSO_UDP_L4
	}
	raw := make([]byte, start+transport+2401)
	if v6 {
		raw[0], raw[6], raw[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
		raw[8], raw[23], raw[24], raw[39] = 0x20, 1, 0x20, 2
	} else {
		raw[0], raw[8], raw[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		binary.BigEndian.PutUint16(raw[4:], 99)
		copy(raw[12:20], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	}
	binary.BigEndian.PutUint16(raw[start:], 1234)
	binary.BigEndian.PutUint16(raw[start+2:], 5678)
	offset := 16
	if udp {
		offset = 6
		binary.BigEndian.PutUint16(raw[start+4:], uint16(len(raw)-start))
	} else {
		raw[start+12], raw[start+13] = 0x50, 0x18
	}
	for i := start + transport; i < len(raw); i++ {
		raw[i] = byte(i)
	}
	input := make([]byte, 10+len(raw))
	input[0], input[1] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, kind
	// hdr_len can be the whole first forwarded packet; derive real headers.
	binary.LittleEndian.PutUint16(input[2:], uint16(len(raw)))
	binary.LittleEndian.PutUint16(input[4:], 1200)
	binary.LittleEndian.PutUint16(input[6:], uint16(start))
	binary.LittleEndian.PutUint16(input[8:], uint16(offset))
	copy(input[10:], raw)
	return input
}

func verifyOffloadChecksum(t *testing.T, raw []byte, udp bool) {
	t.Helper()
	var from, to tcpip.Address
	start := 20
	if raw[0]>>4 == 4 {
		h := header.IPv4(raw)
		if !h.IsChecksumValid() || int(h.TotalLength()) != len(raw) {
			t.Fatal("invalid IPv4 header")
		}
		from, to = h.SourceAddress(), h.DestinationAddress()
	} else {
		start = 40
		h := header.IPv6(raw)
		if int(h.PayloadLength())+40 != len(raw) {
			t.Fatal("invalid IPv6 length")
		}
		from, to = h.SourceAddress(), h.DestinationAddress()
	}
	protocol := tcpip.TransportProtocolNumber(6)
	if udp {
		protocol = 17
		if int(binary.BigEndian.Uint16(raw[start+4:])) != len(raw)-start {
			t.Fatal("invalid UDP length")
		}
	}
	seed := header.PseudoHeaderChecksum(protocol, from, to, uint16(len(raw)-start))
	if checksum.Checksum(raw[start:], seed) != 0xffff {
		t.Fatal("invalid transport checksum")
	}
}

func TestOffloadReadTCPAndUDP(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, udp := range []bool{false, true} {
			input := offloadFixture(v6, udp)
			buffers := [][]byte{make([]byte, 65535), make([]byte, 9000), make([]byte, 9000)}
			sizes, segments := make([]int, 3), []int{1, 1, 1}
			count, err := decodeOffloadRead(input, buffers, sizes, segments)
			if err != nil {
				t.Fatal(v6, udp, err)
			}
			start := 20
			if v6 {
				start = 40
			}
			if !udp {
				if count != 1 || sizes[0] != len(input)-10 || segments[0] != start+20+1200 {
					t.Fatal("TCP GSO was split or its segment bound changed", count, sizes, segments)
				}
				verifyOffloadChecksum(t, buffers[0][:sizes[0]], false)
				continue
			}
			if count != 3 || sizes[0] != start+8+1200 || sizes[2] != start+8+1 {
				t.Fatal("UDP datagram boundaries changed", sizes)
			}
			var payload []byte
			for i := range count {
				if segments[i] != 0 {
					t.Fatal("UDP bypassed ordinary MTU admission")
				}
				out := buffers[i][:sizes[i]]
				verifyOffloadChecksum(t, out, true)
				if !v6 && binary.BigEndian.Uint16(out[4:]) != 99+uint16(i) {
					t.Fatal("IPv4 ID changed")
				}
				payload = append(payload, out[start+8:]...)
			}
			if !bytes.Equal(payload, input[10+start+8:]) {
				t.Fatal("UDP payload changed")
			}
		}
	}
}

func TestOffloadReadRejectsMalformedMetadata(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"short virtio":        func(p []byte) []byte { return p[:9] },
		"zero MSS":            func(p []byte) []byte { clear(p[4:6]); return p },
		"bad checksum start":  func(p []byte) []byte { binary.LittleEndian.PutUint16(p[6:], 65535); return p },
		"bad checksum offset": func(p []byte) []byte { binary.LittleEndian.PutUint16(p[8:], 65535); return p },
		"bad TCP header":      func(p []byte) []byte { p[10+20+12] = 0; return p },
		"wrong IP family":     func(p []byte) []byte { p[1] = unix.VIRTIO_NET_HDR_GSO_TCPV6; return p },
	} {
		t.Run(name, func(t *testing.T) {
			p := mutate(offloadFixture(false, false))
			if _, err := decodeOffloadRead(p, [][]byte{make([]byte, 65535)}, make([]int, 1), make([]int, 1)); err == nil {
				t.Fatal("malformed offload accepted")
			}
		})
	}
}

func TestOffloadTCPBorrowedViewLifetime(t *testing.T) {
	input := offloadFixture(false, false)
	buffers := [][]byte{make([]byte, 65535)}
	sizes, segments := make([]int, 1), make([]int, 1)
	count, err := decodeOffloadRead(input, buffers, sizes, segments, true)
	if err != nil || count != 1 || &buffers[0][0] != &input[10] {
		t.Fatal("TCP offload did not expose its borrowed read view", count, err)
	}
	verifyOffloadChecksum(t, buffers[0][:sizes[0]], false)
}

func TestOwnedOffloadReadPreservesKernelChecksumAndStorage(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		device := &native{file: read}
		buffers := [][]byte{make([]byte, 65535)}
		sizes, segments := make([]int, 1), make([]int, 1)
		owners := make([]*stack.PacketBuffer, 1)
		input := offloadFixture(v6, false)
		start := 20
		if v6 {
			start = 40
		}
		binary.BigEndian.PutUint16(input[10+start+16:], 0x1234)
		if _, err := write.Write(input); err != nil {
			t.Fatal(err)
		}
		n, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners)
		if err != nil || n != 1 || owners[0] == nil || !owners[0].RXChecksumValidated {
			t.Fatal("owned checksum offload was lost", n, err)
		}
		first := owners[0]
		if binary.BigEndian.Uint16(buffers[0][start+16:]) != 0x1234 {
			t.Fatal("kernel checksum seed was recomputed")
		}
		parts := first.AsSlices()
		headerSize := start + 20
		if len(parts) != 2 || len(parts[0]) != headerSize || &parts[1][0] != &buffers[0][headerSize] {
			t.Fatal("payload storage was copied before ownership transfer")
		}
		original := first.Data().AsRange().ToSlice()
		owners[0] = nil
		input[len(input)-1] ^= 0xff
		if _, err := write.Write(input); err != nil {
			t.Fatal(err)
		}
		if _, err := device.ReadOwnedOffloadBatch(buffers, sizes, segments, owners); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Data().AsRange().ToSlice(), original) {
			t.Fatal("a subsequent read overwrote stack-owned storage")
		}
		first.DecRef()
		owners[0].DecRef()
		read.Close()
		write.Close()
	}
}

func TestKernelChecksumOffloadRejectsInvalidMetadata(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"missing flags": func(p []byte) { p[0] = 0 },
		"wrong field":   func(p []byte) { binary.LittleEndian.PutUint16(p[8:], 14) },
		"wrong start":   func(p []byte) { binary.LittleEndian.PutUint16(p[6:], 21) },
		"fragment":      func(p []byte) { binary.BigEndian.PutUint16(p[10+6:], 0x2000) },
		"UDP":           func(p []byte) { p[10+9] = 17 },
	} {
		t.Run(name, func(t *testing.T) {
			input := offloadFixture(false, false)
			mutate(input)
			if kernelTCPChecksumOffload(input[:10], input[10:]) {
				t.Fatal("invalid kernel checksum metadata accepted")
			}
		})
	}
}
