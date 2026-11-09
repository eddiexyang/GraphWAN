//go:build !linux

package agent

import (
	"context"
	"errors"
	"net/netip"

	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

// The kernel egress is Linux's; elsewhere the egress uses its TCP stack.
func enableKernelEgress(context.Context) bool { return false }
func disableKernelEgress(context.Context)     {}
func localDestination(netip.Addr) bool        { return false }

func dialKernel(context.Context, netip.AddrPort, netip.AddrPort) (streamproxy.Conn, error) {
	return nil, errors.New("kernel egress is not supported on this platform")
}
