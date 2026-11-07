package model

import (
	"fmt"
	"net/netip"
)

const MaxAdvertisedSubnets = 64
const MaxNetworkSubnets = 1024

// validateAdvertised checks one Node's entries; total counts the Network's.
// Several Nodes may advertise one prefix, each Node once.
func validateAdvertised(overlay netip.Prefix, entries []AdvertisedSubnet, total *int) error {
	if len(entries) > MaxAdvertisedSubnets {
		return fmt.Errorf("at most %d advertised subnets per node", MaxAdvertisedSubnets)
	}
	for _, entry := range entries {
		p := entry.Prefix
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" ||
			p.Addr().BitLen() != overlay.Addr().BitLen() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			return fmt.Errorf("invalid advertised subnet %s (use a canonical prefix of the overlay address family)", p)
		}
		// Broad routes including /0 are permitted. Overlay addresses always take
		// precedence; a subnet wholly inside the overlay is not an external subnet.
		if p.Bits() >= overlay.Bits() && overlay.Contains(p.Addr()) {
			return fmt.Errorf("advertised subnet %s is inside the overlay", p)
		}
		switch entry.GatewayMode {
		case GatewayOff, GatewayRoute, GatewaySNAT:
		default:
			return fmt.Errorf("invalid automatic gateway mode %q", entry.GatewayMode)
		}
		if countPrefix(entries, p) > 1 {
			return fmt.Errorf("advertised subnet %s is declared more than once on the node", p)
		}
		if *total++; *total > MaxNetworkSubnets {
			return fmt.Errorf("too many advertised subnets in network")
		}
	}
	return nil
}

func countPrefix(entries []AdvertisedSubnet, p netip.Prefix) int {
	count := 0
	for _, entry := range entries {
		if entry.Prefix == p {
			count++
		}
	}
	return count
}

// SharedPrefixes reports whether several Nodes advertise one prefix. Agents
// that predate multiple exits reject such a configuration.
func SharedPrefixes(nodes []Node) bool {
	owners := map[netip.Prefix]bool{}
	for _, node := range nodes {
		for _, entry := range node.AdvertisedSubnets {
			if owners[entry.Prefix] {
				return true
			}
		}
		for _, entry := range node.AdvertisedSubnets {
			owners[entry.Prefix] = true
		}
	}
	return false
}
