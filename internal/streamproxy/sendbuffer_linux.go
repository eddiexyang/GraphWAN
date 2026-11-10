package streamproxy

import (
	"os"
	"strconv"
	"strings"
)

// SendBuffer, the most a session end keeps, is the kernel's largest TCP send buffer: tcp_wmem's maximum.
func SendBuffer() uint64 {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/tcp_wmem")
	if err != nil {
		return defaultSendBuffer
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 3 {
		return defaultSendBuffer
	}
	size, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil || size == 0 {
		return defaultSendBuffer
	}
	return size
}
