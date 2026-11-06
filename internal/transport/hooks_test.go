package transport

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/sockets"
)

type hookRecorder struct {
	mu       sync.Mutex
	controls map[string]int
	lookups  []string
}

func (r *hookRecorder) hooks() sockets.Hooks {
	return sockets.Hooks{
		Control: func(network, _ string, _ syscall.RawConn) error {
			r.mu.Lock()
			r.controls[network]++
			r.mu.Unlock()
			return nil
		},
		Lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			r.mu.Lock()
			r.lookups = append(r.lookups, network+" "+host)
			r.mu.Unlock()
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	}
}

func (r *hookRecorder) count(network string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.controls[network]
}

// Every socket GraphWAN opens and every name it resolves goes through the
// hooks of its context, so an embedding host can keep them off its own TUN.
func TestSocketHooksApplyToListenAndDial(t *testing.T) {
	r := &hookRecorder{controls: map[string]int{}}
	ctx := sockets.With(context.Background(), r.hooks())

	listener, err := ListenTCP(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if r.count("tcp4") == 0 {
		t.Fatal("TCP listener bypassed the socket hook")
	}
	_, identity, _ := ed25519.GenerateKey(nil)
	udp, quic, err := ListenUDPQUIC(ctx, "127.0.0.1:0", identity)
	if err != nil {
		t.Fatal(err)
	}
	defer quic.Close()
	defer udp.Close()
	if r.count("udp4") == 0 {
		t.Fatal("UDP socket bypassed the socket hook")
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	before := r.count("tcp4")
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := DialTCP(dialCtx, &net.Dialer{}, "tcp4", "graphwan.invalid:"+port)
	if err != nil {
		t.Fatalf("dial through the lookup hook: %v", err)
	}
	conn.Close()
	if r.count("tcp4") == before || len(r.lookups) != 1 || r.lookups[0] != "ip4 graphwan.invalid" {
		t.Fatalf("dial: controls %d→%d, lookups %v", before, r.count("tcp4"), r.lookups)
	}
	before = r.count("tcp4")
	conn, err = DialTCPPort(dialCtx, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, netip.MustParseAddrPort("127.0.0.1:"+port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if r.count("tcp4") == before {
		t.Fatal("punching dial bypassed the socket hook")
	}

	// Without hooks nothing changes: the default resolver and plain sockets.
	conn, err = DialTCP(context.Background(), &net.Dialer{}, "tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
