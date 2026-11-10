//go:build linux

package transport

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
)

// ConfigureTCP is called on raw sockets before wrapping them in TLS or HTTP.
// Non-TCP connections (e.g. in-memory adapters) need no kernel configuration.
func ConfigureTCP(conn net.Conn) error {
	return setTCPWriteBacklog(conn, TCPNotSentLowWater)
}

// UseKernelTCPBacklog removes the packet carrier's explicit unsent-byte bound
// from an admitted native byte stream. Zero selects the host's global default.
func UseKernelTCPBacklog(conn net.Conn) error {
	return setTCPWriteBacklog(conn, 0)
}

func setTCPWriteBacklog(conn net.Conn, lowWater int) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, lowWater)
	}); err != nil {
		return err
	}
	if optionErr != nil {
		return fmt.Errorf("set TCP unsent backlog: %w", optionErr)
	}
	return nil
}

// TCPReceiveWindow reports a TCP connection's receive buffer, which the
// kernel tunes as the connection's transfer needs it: SO_RCVBUF.
func TCPReceiveWindow(conn net.Conn) (int, bool) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, false
	}
	size := 0
	if raw.Control(func(fd uintptr) {
		size, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}) != nil || err != nil {
		return 0, false
	}
	return size, true
}
