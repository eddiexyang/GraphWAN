package agent

import (
	"net/netip"

	"github.com/eddiexyang/graphnet/internal/gateway"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
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

// snatDestination reports whether addr matches an advertised subnet of this
// Node whose longest matching prefix in network uses SNAT gateway mode.
func snatDestination(state *runtimeState, network model.ID, addr netip.Addr) bool {
	if state == nil || !addr.IsGlobalUnicast() {
		return false
	}
	for _, n := range state.snapshot.Networks {
		device := state.devices[n.ID]
		if n.ID != network || device == nil || device.failure.Load() != nil || n.CIDR.Contains(addr) {
			continue
		}
		bestBits := -1
		mode := model.GatewayOff
		for _, s := range n.Self.AdvertisedSubnets {
			if s.Prefix.Contains(addr) && s.Prefix.Bits() > bestBits {
				bestBits = s.Prefix.Bits()
				mode = s.GatewayMode
			}
		}
		return mode == model.GatewaySNAT
	}
	return false
}

// crossNetwork reports whether a packet delivered from network is addressed to
// another network this Agent belongs to. The kernel would route it from one TUN
// into the other, so a gateway never hands such packets to the host.
func crossNetwork(state *runtimeState, network model.ID, raw []byte) bool {
	info, err := packet.InspectAddresses(raw)
	if err != nil {
		return false
	}
	for _, n := range state.snapshot.Networks {
		if n.ID != network && n.CIDR.Contains(info.Destination) {
			return true
		}
	}
	return false
}

func ownedSelfAddress(state *runtimeState, addr netip.Addr) bool {
	if state == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, self := range state.selfAddress {
		if self == addr {
			return true
		}
	}
	return false
}
