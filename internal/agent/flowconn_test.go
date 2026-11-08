package agent

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// directConn records which of the stack connection's direct copies ran.
type directConn struct {
	net.Conn
	readFrom, readInto bool
}

func (c *directConn) CloseWrite() error { return nil }
func (c *directConn) ReadFrom(src io.Reader) (int64, error) {
	c.readFrom = true
	return io.Copy(io.Discard, src)
}
func (c *directConn) ReadInto(dst io.Writer) (int, error) {
	c.readInto = true
	return dst.Write([]byte("x"))
}

// The egress wraps its stack connection to track the flow; the wrapper keeps
// both direct copies, so relaying adds no intermediate buffer.
func TestFlowConnKeepsDirectCopies(t *testing.T) {
	inner := &directConn{}
	var conn any = &flowConn{Conn: inner, done: func() {}}
	from, ok := conn.(io.ReaderFrom)
	if !ok {
		t.Fatal("no ReadFrom")
	}
	into, ok := conn.(interface{ ReadInto(io.Writer) (int, error) })
	if !ok {
		t.Fatal("no ReadInto")
	}
	from.ReadFrom(bytes.NewReader([]byte("abc")))
	into.ReadInto(io.Discard)
	if !inner.readFrom || !inner.readInto {
		t.Fatalf("delegated ReadFrom %v, ReadInto %v", inner.readFrom, inner.readInto)
	}
}
