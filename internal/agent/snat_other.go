//go:build !linux

package agent

import (
	"net/netip"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
)

func checkSNATRoute(state *runtimeState, dst netip.Addr) error {
	if state == nil || !dst.IsValid() || dst.Is4In6() || !dst.IsGlobalUnicast() {
		return forwarding.ErrDestination
	}
	for _, n := range state.snapshot.Networks {
		if n.CIDR.Contains(dst) {
			return forwarding.ErrDestination
		}
	}
	return nil
}
