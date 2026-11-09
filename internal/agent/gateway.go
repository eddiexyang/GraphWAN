package agent

import (
	"net/netip"

	"github.com/eWloYW8/GraphWAN/internal/gateway"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

func gatewayEntries(state *runtimeState) []gateway.Entry {
	if state == nil {
		return nil
	}
	var entries []gateway.Entry
	for _, n := range state.snapshot.Networks {
		device := state.devices[n.ID]
		if device == nil || device.failure.Load() != nil {
			continue
		}
		for _, s := range n.Self.AdvertisedSubnets {
			entries = append(entries, gateway.Entry{Interface: device.Name(), Overlay: n.CIDR, Subnet: s.Prefix, Mode: s.GatewayMode})
		}
	}
	return entries
}

// gatewayDestination reports an address in a subnet the node is a gateway
// for in the network, which the host forwards the network's packets to.
func gatewayDestination(state *runtimeState, network model.ID, addr netip.Addr) bool {
	for _, n := range state.snapshot.Networks {
		device := state.devices[n.ID]
		if n.ID != network || device == nil || device.failure.Load() != nil || n.CIDR.Contains(addr) {
			continue
		}
		for _, s := range n.Self.AdvertisedSubnets {
			if s.GatewayMode != model.GatewayOff && s.Prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}
