package streamproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ClientConn exposes a GraphNet stream as a net.Conn. The upload queue and
// download pipe retain deadlines, backpressure, and directional EOF.
func ClientConn(parent context.Context, stream Conn, from, to netip.AddrPort, release func()) net.Conn {
	applicationRead, relayWrite := net.Pipe()
	upload := &clientUpload{}
	upload.readable.L = &upload.mu
	upload.writable.L = &upload.mu
	ctx, cancel := context.WithCancel(parent)
	app := &clientConn{
		reader: applicationRead,
		upload: upload,
		stream: stream,
		local:  net.TCPAddrFromAddrPort(from),
		remote: net.TCPAddrFromAddrPort(to),
		cancel: cancel,
		ctx:    ctx,
	}
	go func() {
		defer cancel()
		defer release()
		pump := &clientPump{upload: upload, writer: relayWrite, unread: &app.unread}
		relay(ctx, pump, stream, func(err error) {
			app.failure.CompareAndSwap(nil, &err)
		})
		if end, ok := stream.(interface {
			Done() <-chan struct{}
			Abort()
		}); ok {
			select {
			case <-end.Done():
			case <-ctx.Done():
				end.Abort()
			}
		}
	}()
	return app
}

type clientPump struct {
	upload *clientUpload
	writer net.Conn
	unread *atomic.Int64
}

func (p *clientPump) Read(b []byte) (int, error) {
	return p.upload.read(len(b), func(data []byte) (int, error) {
		n := copy(b, data)
		b = b[n:]
		return n, nil
	})
}

func (p *clientPump) ReadInto(dst io.Writer) (int, error) {
	return p.upload.read(RoomOf(dst, 64<<10), dst.Write)
}

func (p *clientPump) Write(b []byte) (int, error) {
	p.unread.Add(int64(len(b)))
	n, err := p.writer.Write(b)
	if n < len(b) {
		p.unread.Add(-int64(len(b) - n))
	}
	return n, err
}

func (p *clientPump) CloseWrite() error { return p.writer.Close() }
func (p *clientPump) Close() error {
	p.upload.closeReader()
	return p.writer.Close()
}

// Allow the input and the framer to overlap by up to two framing reads.
const clientUploadSize = 128 << 10

type clientUpload struct {
	writeMu                 sync.Mutex
	mu                      sync.Mutex
	readable, writable      sync.Cond
	buffer                  []byte
	head                    int
	size                    int
	readClosed, writeClosed bool
	deadline                time.Time
	timer                   *time.Timer
}

func (u *clientUpload) write(b []byte) (int, error) {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	u.mu.Lock()
	defer u.mu.Unlock()
	written := 0
	for len(b) > 0 {
		switch {
		case u.readClosed || u.writeClosed:
			return written, net.ErrClosed
		case !u.deadline.IsZero() && !time.Now().Before(u.deadline):
			return written, os.ErrDeadlineExceeded
		case u.size == clientUploadSize:
			u.writable.Wait()
			continue
		}
		if u.buffer == nil {
			u.buffer = make([]byte, clientUploadSize)
		}
		tail := (u.head + u.size) % len(u.buffer)
		n := copy(u.buffer[tail:tail+min(len(u.buffer)-tail, len(u.buffer)-u.size)], b)
		if u.size == 0 {
			u.readable.Signal()
		}
		u.size += n
		written += n
		b = b[n:]
	}
	return written, nil
}

// write is synchronous and bounded, as required by the frame builder.
func (u *clientUpload) read(limit int, write func([]byte) (int, error)) (int, error) {
	if limit == 0 {
		return 0, nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for u.size == 0 && !u.readClosed && !u.writeClosed {
		u.readable.Wait()
	}
	if u.readClosed {
		return 0, net.ErrClosed
	}
	if u.size == 0 {
		return 0, io.EOF
	}
	if u.size == len(u.buffer) {
		defer u.writable.Signal()
	}
	var read int
	left := min(limit, u.size)
	for left > 0 {
		next := min(left, len(u.buffer)-u.head)
		n, err := write(u.buffer[u.head : u.head+next])
		u.head = (u.head + n) % len(u.buffer)
		u.size -= n
		read += n
		if err != nil {
			return read, err
		}
		if n < next {
			return read, io.ErrShortWrite
		}
		left -= n
	}
	return read, nil
}

func (u *clientUpload) setDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.readClosed || u.writeClosed {
		return net.ErrClosed
	}
	u.deadline = t
	if u.timer != nil {
		u.timer.Stop()
	}
	if !t.IsZero() {
		u.timer = time.AfterFunc(time.Until(t), func() {
			u.mu.Lock()
			u.writable.Signal()
			u.mu.Unlock()
		})
	}
	u.writable.Signal()
	return nil
}

func (u *clientUpload) closeWrite() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.writeClosed = true
	if u.timer != nil {
		u.timer.Stop()
	}
	u.readable.Signal()
	u.writable.Signal()
}

func (u *clientUpload) closeReader() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readClosed = true
	u.buffer, u.size = nil, 0
	if u.timer != nil {
		u.timer.Stop()
	}
	u.readable.Signal()
	u.writable.Signal()
}

type clientConn struct {
	reader        net.Conn
	upload        *clientUpload
	stream        Conn
	local, remote net.Addr
	ctx           context.Context
	cancel        context.CancelFunc
	closing       sync.Once
	eof           atomic.Bool
	unread        atomic.Int64
	failure       atomic.Pointer[error]
}

func (c *clientConn) Read(b []byte) (int, error) {
	n, err := c.reader.Read(b)
	if n > 0 {
		c.unread.Add(-int64(n))
	}
	if err == io.EOF {
		if failure := c.failure.Load(); failure != nil {
			return n, *failure
		}
		c.eof.Store(true)
	}
	return n, err
}

func (c *clientConn) Write(b []byte) (int, error) {
	n, err := c.upload.write(b)
	if err == net.ErrClosed {
		if failure := c.failure.Load(); failure != nil {
			return n, *failure
		}
	}
	return n, err
}

func (c *clientConn) CloseWrite() error {
	c.upload.closeWrite()
	return nil
}

func (c *clientConn) Close() error {
	c.closing.Do(func() {
		if c.unread.Load() > 0 {
			// Closing with unread data resets TCP. Abort the stream before
			// closing the upload queue could let the relay send a FIN.
			if stream, ok := c.stream.(interface{ Abort() }); ok {
				stream.Abort()
			} else {
				_ = c.stream.Close()
			}
			c.cancel()
			c.upload.closeReader()
			_ = c.reader.Close()
			return
		}
		c.upload.closeWrite()
		_ = c.reader.Close()
		if !c.eof.Load() {
			// Give the queued bytes and FIN time to reach the peer.
			timer := time.AfterFunc(orphanLifetime, c.cancel)
			context.AfterFunc(c.ctx, func() { timer.Stop() })
		}
	})
	return nil
}

func (c *clientConn) LocalAddr() net.Addr  { return c.local }
func (c *clientConn) RemoteAddr() net.Addr { return c.remote }
func (c *clientConn) SetReadDeadline(t time.Time) error {
	return c.reader.SetReadDeadline(t)
}
func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return c.upload.setDeadline(t)
}
func (c *clientConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
