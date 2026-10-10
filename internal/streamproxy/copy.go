package streamproxy

import (
	"errors"
	"io"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ReadInto writes immediately available TCP bytes into a bounded, synchronous
// writer. That writer must return promptly: the endpoint owns its read lock.
// The peer's record builder satisfies this contract and copies only once.
func (c *accessConn) ReadInto(dst io.Writer) (int, error) {
	var entry waiter.Entry
	var ready <-chan struct{}
	for {
		result, err := c.endpoint.Read(dst, tcpip.ReadOptions{})
		if result.Count > 0 {
			c.endpoint.ModerateRecvBuf(result.Count)
			return result.Count, nil
		}
		switch err.(type) {
		case nil:
			return 0, nil
		case *tcpip.ErrClosedForReceive:
			return 0, io.EOF
		case *tcpip.ErrWouldBlock:
			if ready == nil {
				entry, ready = waiter.NewChannelEntry(waiter.ReadableEvents)
				c.queue.EventRegister(&entry)
				defer c.queue.EventUnregister(&entry)
				continue
			}
			<-ready
		default:
			return 0, errors.New(err.String())
		}
	}
}

type payloadReader struct {
	io.Reader
	remaining int
}

func (p *payloadReader) Len() int { return p.remaining }
func (p *payloadReader) Read(dst []byte) (int, error) {
	if p.remaining == 0 {
		return 0, io.EOF
	}
	n, err := p.Reader.Read(dst[:min(len(dst), p.remaining)])
	p.remaining -= n
	return n, err
}

type writerOnly struct{ io.Writer }

// ReadFrom lets the endpoint request already decoded peer bytes directly into
// its send-buffer chunk. A bounded read window prevents interactive requests
// from waiting for a full chunk and retains ordinary socket backpressure.
func (c *accessConn) ReadFrom(src io.Reader) (int64, error) {
	window, ok := src.(interface{ ReadWindow() (int, error) })
	if !ok {
		return io.CopyBuffer(writerOnly{c}, src, make([]byte, 64*1024))
	}
	var entry waiter.Entry
	var ready <-chan struct{}
	var total int64
	payload := payloadReader{Reader: src}
	for {
		n, err := window.ReadWindow()
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
		if n <= 0 {
			return total, io.ErrNoProgress
		}
		payload.remaining = n
		for payload.remaining > 0 {
			written, writeErr := c.endpoint.Write(&payload, tcpip.WriteOptions{})
			total += written
			switch writeErr.(type) {
			case nil:
				if written == 0 {
					return total, io.ErrNoProgress
				}
			case *tcpip.ErrWouldBlock:
				if ready == nil {
					entry, ready = waiter.NewChannelEntry(waiter.WritableEvents)
					c.queue.EventRegister(&entry)
					defer c.queue.EventUnregister(&entry)
					continue
				}
				<-ready
			default:
				return total, errors.New(writeErr.String())
			}
		}
	}
}
