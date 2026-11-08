package testutil

import (
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"testing"
)

var ports struct {
	sync.Mutex
	used map[uint16]bool
}

// AgentPort returns a loopback port free for both TCP and UDP, as an Agent
// listens on both. It is taken below the kernels' ephemeral ranges, where
// the outgoing sockets of tests running in parallel packages cannot claim it
// between this check and the Agent's listen, and never twice in a process.
func AgentPort(t testing.TB) uint16 {
	t.Helper()
	ports.Lock()
	defer ports.Unlock()
	if ports.used == nil {
		ports.used = make(map[uint16]bool)
	}
	for range 1000 {
		port := uint16(20000 + rand.IntN(12000))
		if ports.used[port] {
			continue
		}
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		tcp, err := net.Listen("tcp4", address)
		if err != nil {
			continue
		}
		udp, err := net.ListenPacket("udp4", address)
		tcp.Close()
		if err != nil {
			continue
		}
		udp.Close()
		ports.used[port] = true
		return port
	}
	t.Fatal("no loopback port free for TCP and UDP")
	return 0
}
