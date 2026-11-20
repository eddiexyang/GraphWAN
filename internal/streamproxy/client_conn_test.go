package streamproxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func TestClientConnCloseResetsUnreadData(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	stream := &clientCloseTestStream{Conn: local, aborted: make(chan struct{}), finished: make(chan struct{})}
	released := make(chan struct{})
	addr := netip.MustParseAddrPort("192.0.2.1:1024")
	conn := ClientConn(t.Context(), stream, addr, addr, func() { close(released) }).(*clientConn)
	defer conn.Close()
	if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("unread")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for conn.unread.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("greeting did not reach the application side")
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stream.aborted:
	default:
		t.Fatal("Close did not reset the stream")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("Close did not release the relay")
	}
	select {
	case <-stream.finished:
		t.Fatal("relay sent a FIN for the reset")
	default:
	}
}

type clientCloseTestStream struct {
	net.Conn
	aborted, finished chan struct{}
	abort, finish     sync.Once
}

func (c *clientCloseTestStream) Abort() {
	c.abort.Do(func() {
		close(c.aborted)
		c.Conn.Close()
	})
}

func (c *clientCloseTestStream) CloseWrite() error {
	c.finish.Do(func() { close(c.finished) })
	return nil
}

func TestClientUploadTimeoutAndDrain(t *testing.T) {
	u := &clientUpload{}
	u.readable.L = &u.mu
	u.writable.L = &u.mu
	defer u.closeReader()
	first := bytes.Repeat([]byte{1}, clientUploadSize)
	if n, err := u.write(first); n != len(first) || err != nil {
		t.Fatalf("fill: wrote %d, %v", n, err)
	}
	if err := u.setDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := u.write([]byte{2}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("full queue: wrote %d, %v", n, err)
	}
	if err := u.setDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	half := len(first) / 2
	if n, err := u.read(half, got.Write); n != half || err != nil {
		t.Fatalf("read first half: got %d, %v", n, err)
	}
	last := bytes.Repeat([]byte{2}, half)
	if n, err := u.write(last); n != len(last) || err != nil {
		t.Fatalf("write around ring: wrote %d, %v", n, err)
	}
	u.closeWrite()
	if n, err := u.read(clientUploadSize, got.Write); n != clientUploadSize || err != nil {
		t.Fatalf("drain after half-close: got %d, %v", n, err)
	}
	if _, err := u.read(1, got.Write); err != io.EOF {
		t.Fatalf("drained queue: %v", err)
	}
	if !bytes.Equal(got.Bytes(), append(first, last...)) {
		t.Fatal("queue reordered writes")
	}
}
