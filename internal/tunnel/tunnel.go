// Package tunnel owns operating-system TUN interfaces and their virtual routes.
package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"regexp"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Config struct {
	Name    string
	Address netip.Prefix
	MTU     int
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$`)

func (c Config) Validate() error {
	if c.Name != "" && !validName.MatchString(c.Name) {
		return errors.New("invalid TUN interface name")
	}
	if !c.Address.IsValid() || c.Address.Addr().IsUnspecified() || c.Address.Addr().IsMulticast() || c.Address.Addr().Is4In6() || c.Address.Bits() == 0 {
		return errors.New("invalid TUN virtual address")
	}
	if c.MTU < model.DefaultMTU || c.MTU > model.MaxMTU {
		return errors.New("invalid TUN MTU")
	}
	return nil
}
func (c Config) withName() Config {
	if c.Name == "" {
		var raw [6]byte
		rand.Read(raw[:])
		c.Name = "gw" + hex.EncodeToString(raw[:])
	}
	return c
}

// ErrUnavailable marks a failed device rather than a single rejected packet.
var ErrUnavailable = errors.New("TUN device unavailable")

// Device supports one reader and concurrent packet writes. Close is idempotent
// and interrupts pending I/O; it releases only resources owned by this device.
type Device interface {
	io.ReadWriteCloser
	Name() string
	Configuration() Config
}
type Factory func(Config) (Device, error)

// MTUSetter optionally updates a live device without creating a second interface
// with the same address. On error, the previous MTU remains in effect unless
// ErrUnavailable reports failed restoration. Calls may race with Configuration
// and Close; the adapter must serialize those operations.
type MTUSetter interface {
	SetMTU(int) error
}

// Reconfigurable changes address, prefix and MTU on an owned live interface.
// An empty Name preserves its name; renaming is not supported. On error the old
// configuration is restored, unless ErrUnavailable signals that restoration
// failed and the caller must retire the device. Configuration and Close may run
// concurrently with Reconfigure.
type Reconfigurable interface {
	Reconfigure(Config) error
}

// BatchDevice amortizes kernel I/O without changing packet boundaries. Reads
// fill caller-owned buffers; writes must not modify or retain their input.
// Implementations support one reader and concurrent writers, like Device.
type BatchDevice interface {
	Device
	BatchSize() int
	ReadBatch(buffers [][]byte, sizes []int) (int, error)
	WriteBatch(packets [][]byte) error
}

// TCPPacketWriter accepts access-stack packet buffers synchronously, preserving
// their segmentation/checksum metadata without copying or retaining ownership.
type TCPPacketWriter interface {
	WriteTCPPacket(*stack.PacketBuffer) error
}

// OffloadReader preserves native TCP GSO packets for the access stack, while
// returning separate datagrams for UDP. segmentSizes contains the maximum IP
// segment length (including headers), or zero for an ordinary packet. Only one
// of Read, ReadBatch and ReadOffloadBatch may consume a device at a time.
// A reader may replace a TCP buffer with a borrowed view valid until its next
// read. Consumers must synchronously finish admission and take ownership then.
type OffloadReader interface {
	ReadOffloadBatch(buffers [][]byte, sizes, segmentSizes []int) (int, error)
}

// OwnedOffloadReader reads native TCP directly into access-stack storage.
// Each non-nil owner is transferred to the caller, including on read errors;
// it must be injected or released before the next read. Datagrams have no owner
// and use the caller's ordinary buffers. Admission still uses segmentSizes.
type OwnedOffloadReader interface {
	ReadOwnedOffloadBatch(buffers [][]byte, sizes, segmentSizes []int, owners []*stack.PacketBuffer) (int, error)
}
