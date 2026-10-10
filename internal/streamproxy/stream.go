// Package streamproxy terminates TCP at access boundaries and relays bytes.
package streamproxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

const SetupLimit = 512
const MaxConnections = 256

type Request struct {
	Network     model.ID       `json:"network"`
	Source      model.ID       `json:"source"`
	Destination model.ID       `json:"destination"`
	From        netip.AddrPort `json:"from"`
	To          netip.AddrPort `json:"to"`
	Hops        uint8          `json:"hops"`
}

func (r Request) Validate() error {
	for _, id := range []model.ID{r.Network, r.Source, r.Destination} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if r.Hops == 0 || !r.From.IsValid() || !r.To.IsValid() || r.From.Port() == 0 || r.To.Port() == 0 ||
		!r.From.Addr().IsGlobalUnicast() || !r.To.Addr().IsGlobalUnicast() ||
		r.From.Addr().Is4In6() || r.To.Addr().Is4In6() || r.From.Addr().Zone() != "" || r.To.Addr().Zone() != "" ||
		r.From.Addr().BitLen() != r.To.Addr().BitLen() {
		return errors.New("invalid TCP stream destination or hop limit")
	}
	return nil
}
func WriteRequest(w io.Writer, r Request) error {
	if err := r.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > SetupLimit {
		return errors.New("stream request too large")
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(raw)))
	if err := writeAll(w, prefix[:]); err != nil {
		return err
	}
	return writeAll(w, raw)
}
func ReadRequest(r io.Reader) (Request, error) {
	var request Request
	var prefix [2]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return request, err
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	if size == 0 || size > SetupLimit {
		return request, errors.New("invalid stream request size")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(r, raw); err != nil {
		return request, err
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return request, err
	}
	return request, request.Validate()
}
func writeAll(w io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(raw) {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

type Conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

func During(ctx context.Context, c Conn, operation func() error) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	err := operation()
	if !stop() && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Relay propagates write-half closes so a server can respond after request EOF.
// Errors and cancellation interrupt both directions; there is no byte replay.
func Relay(ctx context.Context, a, b Conn) error {
	closeBoth := sync.OnceFunc(func() { a.Close(); b.Close() })
	abortBoth := func() {
		for _, conn := range []Conn{a, b} {
			if tcp, ok := conn.(interface{ Abort() }); ok {
				tcp.Abort()
			}
		}
		closeBoth()
	}
	stop := context.AfterFunc(ctx, abortBoth)
	defer stop()
	defer closeBoth()
	errs := make(chan error, 2)
	copyTo := func(dst, src Conn) {
		_, err := io.CopyBuffer(dst, src, make([]byte, 64*1024))
		if err == nil {
			err = dst.CloseWrite()
		}
		if err != nil {
			abortBoth()
		}
		errs <- err
	}
	go copyTo(a, b)
	go copyTo(b, a)
	err := errors.Join(<-errs, <-errs)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
