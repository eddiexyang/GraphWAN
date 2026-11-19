//go:build linux

package agent

import (
	"net"
	"net/netip"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// checkSNATRoute ensures an SNAT gateway TCP dial resolves to an external
// unicast route rather than a host-local address, loopback, or any TUN device
// owned by this Agent.
func checkSNATRoute(state *runtimeState, dst netip.Addr) error {
	if state == nil || !dst.IsValid() || dst.Is4In6() || !dst.IsGlobalUnicast() {
		return forwarding.ErrDestination
	}
	routes, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	if err != nil || len(routes) == 0 {
		return forwarding.ErrDestination
	}
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST {
			return forwarding.ErrDestination
		}
		if len(r.Src) > 0 {
			if src, ok := netip.AddrFromSlice(r.Src); ok {
				src = src.Unmap()
				if src.IsLoopback() || ownedSelfAddress(state, src) {
					return forwarding.ErrDestination
				}
			}
		}
		if len(r.MultiPath) > 0 {
			for _, nh := range r.MultiPath {
				if !validSNATLink(state, nh.LinkIndex) {
					return forwarding.ErrDestination
				}
			}
			continue
		}
		if !validSNATLink(state, r.LinkIndex) {
			return forwarding.ErrDestination
		}
	}
	return nil
}

func validSNATLink(state *runtimeState, index int) bool {
	if index <= 0 || ownedTUNIndex(state, index) {
		return false
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	return true
}

func ownedTUNIndex(state *runtimeState, index int) bool {
	for _, dev := range state.devices {
		if dev == nil {
			continue
		}
		if indexed, ok := dev.Device.(interface{ Index() int }); ok {
			if indexed.Index() == index {
				return true
			}
			continue
		}
		if iface, err := net.InterfaceByName(dev.Name()); err == nil && iface.Index == index {
			return true
		}
	}
	return false
}
