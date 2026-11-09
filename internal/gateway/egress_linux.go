package gateway

import (
	"context"
	"fmt"
)

// An Agent connects a TCP session's egress to a destination on its own host
// with a kernel socket bound, transparently, to the connection's original
// source. The replies are addressed to that source, which routes into the
// TUN; these rules bring them back to the socket instead. The socket marks its
// packets EgressMark, nft records the mark on the connection and marks the
// connection's replies ReplyMark, and a policy rule delivers packets marked
// ReplyMark on this host.
const (
	EgressMark = 0x4756
	ReplyMark  = 0x4757
	egressNFT  = "graphwan_egress"
	egressRule = "4757" // the policy rule's priority and table
)

// EnableKernelEgress installs the rules, replacing any left by an Agent that
// did not remove them.
func EnableKernelEgress(ctx context.Context) error {
	script := fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
add table inet %[1]s
add chain inet %[1]s output { type route hook output priority mangle; policy accept; }
add chain inet %[1]s prerouting { type filter hook prerouting priority mangle; policy accept; }
add rule inet %[1]s output meta mark %#[2]x ct mark set %#[3]x
add rule inet %[1]s output ct direction reply ct mark %#[3]x meta mark set %#[3]x
add rule inet %[1]s prerouting ct direction reply ct mark %#[3]x meta mark set %#[3]x
`, egressNFT, EgressMark, ReplyMark)
	if _, err := command(ctx, "nft", script, "-f", "-"); err != nil {
		return err
	}
	for _, family := range []string{"-4", "-6"} {
		command(ctx, "ip", "", family, "rule", "del", "priority", egressRule)
		if _, err := command(ctx, "ip", "", family, "rule", "add", "priority", egressRule, "fwmark", fmt.Sprintf("%#x", ReplyMark), "lookup", egressRule); err != nil {
			DisableKernelEgress(ctx)
			return err
		}
		if _, err := command(ctx, "ip", "", family, "route", "replace", "local", "default", "dev", "lo", "table", egressRule); err != nil {
			DisableKernelEgress(ctx)
			return err
		}
	}
	return nil
}

// DisableKernelEgress removes the rules.
func DisableKernelEgress(ctx context.Context) {
	command(ctx, "nft", "", "delete", "table", "inet", egressNFT)
	for _, family := range []string{"-4", "-6"} {
		command(ctx, "ip", "", family, "rule", "del", "priority", egressRule)
		command(ctx, "ip", "", family, "route", "flush", "table", egressRule)
	}
}
