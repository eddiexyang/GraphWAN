package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/eWloYW8/GraphWAN/internal/gateway"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
	"golang.org/x/sys/unix"
)

// kernelEgress counts the Agents of this process that use the host's kernel
// egress rules, which they share.
var kernelEgress struct {
	mu    sync.Mutex
	users int
}

// enableKernelEgress installs the rules for the first Agent that uses them
// and reports whether this Agent may.
func enableKernelEgress(ctx context.Context) bool {
	kernelEgress.mu.Lock()
	defer kernelEgress.mu.Unlock()
	if kernelEgress.users == 0 {
		if err := gateway.EnableKernelEgress(ctx); err != nil {
			return false
		}
	}
	kernelEgress.users++
	return true
}

func disableKernelEgress(ctx context.Context) {
	kernelEgress.mu.Lock()
	defer kernelEgress.mu.Unlock()
	if kernelEgress.users--; kernelEgress.users == 0 {
		gateway.DisableKernelEgress(ctx)
	}
}

// localDestination reports an address of one of this host's interfaces.
func localDestination(addr netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if prefix, ok := a.(*net.IPNet); ok {
			if local, ok := netip.AddrFromSlice(prefix.IP); ok && local.Unmap() == addr.Unmap() {
				return true
			}
		}
	}
	return false
}

// dialKernel connects from the connection's original source to a destination
// on this host, or in a gateway subnet, with a kernel socket; the kernel
// egress rules return the replies to it, and a SNAT gateway masquerades it.
func dialKernel(ctx context.Context, from, to netip.AddrPort) (streamproxy.Conn, error) {
	dialer := net.Dialer{
		LocalAddr: net.TCPAddrFromAddrPort(from),
		Control: func(_, _ string, raw syscall.RawConn) error {
			var err error
			control := raw.Control(func(fd uintptr) {
				level, option := unix.SOL_IP, unix.IP_TRANSPARENT
				if from.Addr().Is6() {
					level, option = unix.SOL_IPV6, unix.IPV6_TRANSPARENT
				}
				if err = unix.SetsockoptInt(int(fd), level, option, 1); err == nil {
					err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, gateway.EgressMark)
				}
			})
			return errors.Join(control, err)
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", to.String())
	if err != nil {
		return nil, err
	}
	return &kernelConn{conn: conn.(*net.TCPConn)}, nil
}

// kernelConn is an egress's kernel socket. Its bytes go straight between the
// socket and the session's frames: reads fill the frames, and writes gather
// the opened records where they are.
type kernelConn struct{ conn *net.TCPConn }

func (c *kernelConn) Read(p []byte) (int, error)  { return c.conn.Read(p) }
func (c *kernelConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *kernelConn) Close() error                { return c.conn.Close() }
func (c *kernelConn) CloseWrite() error           { return c.conn.CloseWrite() }

// Abort resets the connection.
func (c *kernelConn) Abort() {
	c.conn.SetLinger(0)
	c.conn.Close()
}

// ReadInto reads what has arrived into dst's frames, without a copy when dst
// takes reads directly.
func (c *kernelConn) ReadInto(dst io.Writer) (int, error) {
	if frames, ok := dst.(interface {
		Fill(func([]byte) (int, error)) (int, error)
	}); ok {
		return frames.Fill(c.conn.Read)
	}
	buf := make([]byte, streamproxy.RoomOf(dst, 64<<10))
	n, err := c.conn.Read(buf)
	if n > 0 {
		dst.Write(buf[:n])
	}
	return n, err
}

// ReadFrom writes what src receives, gathering a session's opened records
// from where they are.
func (c *kernelConn) ReadFrom(src io.Reader) (int64, error) {
	if session, ok := src.(interface {
		DrainTo(io.Writer) (int64, error)
	}); ok {
		return session.DrainTo(c.conn)
	}
	return io.CopyBuffer(struct{ io.Writer }{c.conn}, src, make([]byte, 64<<10))
}
