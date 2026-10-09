//go:build linux

package mesh

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/transport"
	"golang.org/x/sys/unix"
)

func TestAcceptedByteStreamUsesKernelBacklog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	listener, err := transport.ListenTCP(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := transport.DialTCP(ctx, &net.Dialer{}, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	wrapper := &bufferedConn{Conn: server, reader: bufio.NewReader(server)}
	if err := transport.NewStream(wrapper).UseKernelWriteBacklog(); err != nil {
		t.Fatal(err)
	}
	raw, err := server.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		value, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	})
	if err != nil || optionErr != nil || value != 0 {
		t.Fatalf("admission wrapper retained the packet backlog: %d, %v/%v", value, err, optionErr)
	}
}
