//go:build linux

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"io"
	"net"
	"os"
	"sync"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type native struct {
	file                *os.File
	device              wgtun.Device
	readBuffers         [][]byte
	readSizes           []int
	offloadReadBuffer   [10 + 65535]byte
	offloadScratch      []byte
	ownedScratch        [][]byte
	pendingVirtio       [10]byte
	pendingOffloadSize  int
	ownedReadMu         sync.Mutex
	ingressView         *buffer.View
	readNext, readCount int
	writeMu             sync.Mutex
	writeBuffers        [packetbuf.BatchSize][]byte
	config              Config
	once                sync.Once
	closeError          error
}

func Open(config Config) (Device, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	config = config.withName()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open TUN: %w", err)
	}
	var file *os.File
	success := false
	defer func() {
		if !success {
			if file != nil {
				file.Close()
			} else {
				unix.Close(fd)
			}
		}
	}()
	request, err := unix.NewIfreq(config.Name)
	if err != nil {
		return nil, err
	}
	// EXCL prevents attaching to another process's pre-existing interface. Without
	// PERSIST, closing this owned descriptor removes its interface and routes.
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL | unix.IFF_VNET_HDR)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		return nil, fmt.Errorf("create TUN %s (requires CAP_NET_ADMIN): %w", config.Name, err)
	}
	// An unattached TUN descriptor cannot be registered with epoll. Construct
	// the Go file only after TUNSETIFF, so idle reads can wait and be canceled.
	file = os.NewFile(uintptr(fd), "/dev/net/tun")
	device := &native{config: config, file: file}
	link, err := netlink.LinkByName(config.Name)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetMTU(link, config.MTU); err != nil {
		return nil, err
	}
	bits := 128
	if config.Address.Addr().Is4() {
		bits = 32
	}
	address := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(config.Address.Addr().AsSlice()), Mask: net.CIDRMask(config.Address.Bits(), bits)}}
	if bits == 128 {
		address.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrAdd(link, address); err != nil {
		return nil, fmt.Errorf("configure TUN address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("activate TUN: %w", err)
	}
	device.device, err = wgtun.CreateTUNFromFile(file, config.MTU)
	if err != nil {
		return nil, fmt.Errorf("initialize TUN offloads: %w", err)
	}
	// Link changes are owned by our reconciler; drain the adapter's notifications.
	go func() {
		for range device.device.Events() {
		}
	}()
	success = true
	return device, nil
}
func (d *native) Name() string          { return d.config.Name }
func (d *native) Configuration() Config { return d.config }

// Read retains compatibility with single-packet users while draining every
// segment of a kernel GSO packet. The agent uses ReadBatch directly.
func (d *native) Read(raw []byte) (int, error) {
	if d.readBuffers == nil {
		d.readBuffers = make([][]byte, d.BatchSize())
		d.readSizes = make([]int, d.BatchSize())
		for i := range d.readBuffers {
			d.readBuffers[i] = make([]byte, model.MaxMTU+1)
		}
	}
	if d.readNext == d.readCount {
		var err error
		d.readCount, err = d.ReadBatch(d.readBuffers, d.readSizes)
		d.readNext = 0
		if err != nil {
			return 0, err
		}
		if d.readCount == 0 {
			return 0, io.ErrNoProgress
		}
	}
	i := d.readNext
	d.readNext++
	if len(raw) < d.readSizes[i] {
		return 0, io.ErrShortBuffer
	}
	return copy(raw, d.readBuffers[i][:d.readSizes[i]]), nil
}
func (d *native) BatchSize() int { return d.device.BatchSize() }
func (d *native) ReadBatch(buffers [][]byte, sizes []int) (int, error) {
	return d.device.Read(buffers, sizes, 0)
}

func (d *native) ReadOffloadBatch(buffers [][]byte, sizes, segmentSizes []int) (int, error) {
	if d.offloadScratch == nil && len(buffers) > 0 {
		d.offloadScratch = buffers[0]
	}
	if len(buffers) > 0 {
		buffers[0] = d.offloadScratch
	}
	n, err := d.file.Read(d.offloadReadBuffer[:])
	if err != nil {
		return 0, err
	}
	return decodeOffloadRead(d.offloadReadBuffer[:n], buffers, sizes, segmentSizes, true)
}

func (d *native) ReadOwnedOffloadBatch(buffers [][]byte, sizes, segmentSizes []int, owners []*stack.PacketBuffer) (int, error) {
	d.ownedReadMu.Lock()
	defer d.ownedReadMu.Unlock()
	if len(buffers) == 0 || len(owners) < len(buffers) {
		return 0, errors.New("invalid TUN owned batch")
	}
	if d.offloadScratch == nil {
		d.offloadScratch = buffers[0]
	}
	if d.ownedScratch == nil {
		d.ownedScratch = append([][]byte(nil), buffers...)
	}
	if len(d.ownedScratch) != len(buffers) {
		return 0, errors.New("TUN owned batch capacity changed")
	}
	// Every slot can borrow TCP storage. Restore the caller's UDP scratch
	// before a new batch so a released TCP owner is never written through.
	copy(buffers, d.ownedScratch)
	raw, err := d.file.SyscallConn()
	if err != nil {
		return 0, err
	}
	count := 0
	var readErr error
	var virtio [10]byte
	parts := [2][]byte{virtio[:], nil}
	// Keep the poll-descriptor reference, callback and virtio storage for the
	// whole bounded burst. Waiting is permitted only before its first packet;
	// later EAGAIN returns the packets already available without another wait.
	err = raw.Read(func(fd uintptr) bool {
		for count < len(buffers) {
			if d.ingressView == nil {
				d.ingressView = buffer.NewViewSize(65535)
			}
			view := d.ingressView
			n := 0
			if d.pendingOffloadSize > 0 {
				virtio = d.pendingVirtio
				n = len(virtio) + d.pendingOffloadSize
				d.pendingOffloadSize = 0
			} else {
				parts[1] = view.AsSlice()
				for {
					n, readErr = unix.Readv(int(fd), parts[:])
					if readErr != unix.EINTR {
						break
					}
				}
				if readErr == unix.EAGAIN {
					readErr = nil
					return count > 0
				}
				if readErr != nil {
					return true
				}
			}
			if n < len(virtio) {
				readErr = io.ErrUnexpectedEOF
				return true
			}
			decoded, decodeErr := d.decodeOwnedOffload(virtio[:], view, n-len(virtio), buffers[count:], sizes[count:], segmentSizes[count:], owners[count:])
			if errors.Is(decodeErr, io.ErrShortBuffer) && count > 0 {
				// A UDP GSO packet can expand beyond this batch's remaining
				// slots. Keep its owned read view for the next complete batch.
				d.pendingVirtio, d.pendingOffloadSize = virtio, n-len(virtio)
				return true
			}
			if decodeErr != nil {
				readErr = decodeErr
				return true
			}
			count += decoded
			if owners[count-1] != nil {
				// Preserve the low-latency TCP path while batching datagrams.
				return true
			}
		}
		return true
	})
	if err != nil {
		return count, err
	}
	return count, readErr
}

func (d *native) decodeOwnedOffload(virtio []byte, view *buffer.View, size int, buffers [][]byte, sizes, segmentSizes []int, owners []*stack.PacketBuffer) (int, error) {
	// A separate virtio vector keeps IP storage within gVisor's pooled 64-KiB
	// size class. Linux fills the final owned chunk, avoiding an ingress copy.
	data := view.AsSlice()[:size]
	n, err := decodeOffloadPacket(virtio, data, buffers, sizes, segmentSizes, true, true)
	if err != nil {
		return 0, err
	}
	if n == 1 && len(buffers[0]) > 0 && &buffers[0][0] == &data[0] {
		checksumValidated := kernelTCPChecksumOffload(virtio, data)
		protocol := ipv4.ProtocolNumber
		if data[0]>>4 == 6 {
			protocol = ipv6.ProtocolNumber
		}
		var payload buffer.Buffer
		if segmentSizes[0] > 0 {
			start, _ := offloadTransport(data)
			headerSize := start + int(data[start+12]>>4)*4
			// Header access uses copy-on-write after TCP clones a packet.
			// Give headers their own small chunk so PullUp never clones the
			// complete jumbo payload merely to read or update a TCP/IP field.
			payload = buffer.MakeWithData(data[:headerSize])
			view.CapLength(len(data))
			view.TrimFront(headerSize)
			body := buffer.MakeWithView(view)
			payload.Merge(&body)
			d.ingressView = nil
		} else {
			// ACKs and other small ordinary packets should retain only their
			// own size class; the jumbo read scratch can serve the next read.
			payload = buffer.MakeWithData(data)
		}
		owner := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: payload})
		owner.RXChecksumValidated, owner.NetworkProtocolNumber = checksumValidated, protocol
		owners[0] = owner
	}
	return n, nil
}
func (d *native) Write(raw []byte) (int, error) {
	if err := d.WriteBatch([][]byte{raw}); err != nil {
		return 0, err
	}
	return len(raw), nil
}
func (d *native) WriteBatch(packets [][]byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	// GRO mutates its inputs and needs headroom for the virtio header and room
	// to append adjacent TCP segments. Copy only at this ownership boundary.
	for len(packets) > 0 {
		count := min(len(packets), len(d.writeBuffers))
		for i, raw := range packets[:count] {
			if len(raw) == 0 || len(raw) > 65535 {
				return errors.New("invalid TUN packet size")
			}
			if d.writeBuffers[i] == nil {
				d.writeBuffers[i] = make([]byte, 65535+10)
			}
			d.writeBuffers[i] = d.writeBuffers[i][:len(raw)+10]
			copy(d.writeBuffers[i][10:], raw)
		}
		_, err := d.device.Write(d.writeBuffers[:count], 10)
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EIO) {
			return fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		if err != nil {
			return err
		}
		packets = packets[count:]
	}
	return nil
}

// WriteTCPPacket passes the stack's host-GSO metadata to Linux, following
// sing-tun's native gVisor writer. The kernel owns segmentation/checksum work.
func (d *native) WriteTCPPacket(packet *stack.PacketBuffer) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	var virtio [10]byte
	gso := packet.GSOOptions
	if gso.Type != stack.GSONone {
		binary.LittleEndian.PutUint16(virtio[2:4], uint16(packet.HeaderSize()))
		if gso.NeedsCsum {
			virtio[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
			binary.LittleEndian.PutUint16(virtio[6:8], gso.L3HdrLen)
			binary.LittleEndian.PutUint16(virtio[8:10], gso.CsumOffset)
		}
		if packet.Data().Size() > int(gso.MSS) {
			switch gso.Type {
			case stack.GSOTCPv4:
				virtio[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
			case stack.GSOTCPv6:
				virtio[1] = unix.VIRTIO_NET_HDR_GSO_TCPV6
			default:
				return errors.New("unsupported TCP segmentation type")
			}
			binary.LittleEndian.PutUint16(virtio[4:6], gso.MSS)
		}
	}
	parts := append([][]byte{virtio[:]}, packet.AsSlices()...)
	raw, err := d.file.SyscallConn()
	if err != nil {
		return err
	}
	var writeErr error
	// The stack may hold an endpoint lock while emitting a packet. A native
	// link write must return backpressure rather than parking behind TUN I/O;
	// protocol retry and device recovery retain responsibility for failures.
	err = raw.Control(func(fd uintptr) {
		for {
			n, callErr := unix.Writev(int(fd), parts)
			if errors.Is(callErr, unix.EINTR) {
				continue
			}
			writeErr = callErr
			if callErr == nil && n != packet.Size()+len(virtio) {
				writeErr = io.ErrShortWrite
			}
			break
		}
	})
	if err != nil {
		return err
	}
	if errors.Is(writeErr, unix.ENODEV) || errors.Is(writeErr, unix.EIO) {
		return fmt.Errorf("%w: %w", ErrUnavailable, writeErr)
	}
	return writeErr
}
func (d *native) Close() error {
	d.once.Do(func() {
		d.closeError = d.device.Close()
		d.ownedReadMu.Lock()
		if d.ingressView != nil {
			d.ingressView.Release()
			d.ingressView = nil
		}
		d.ownedReadMu.Unlock()
	})
	return d.closeError
}
