// Package sockets carries per-instance socket hooks through contexts. A host
// that embeds GraphWAN, for example a proxy client with its own TUN, applies
// the same socket options and DNS to GraphWAN's sockets as to its own
// outbound connections, so they never loop back into that TUN.
//
// Hooks travel in the context because every dial, listen and lookup already
// derives from the context the embedding host starts GraphWAN with. Without
// hooks, behavior is unchanged.
package sockets

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// Hooks are applied to every socket GraphWAN creates and every name it resolves.
type Hooks struct {
	// Control runs after GraphWAN's own socket options, before bind/connect.
	Control func(network, address string, c syscall.RawConn) error
	// Lookup resolves host for network "ip", "ip4" or "ip6".
	Lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type hooksKey struct{}

// With returns a context whose sockets and lookups use hooks.
func With(ctx context.Context, hooks Hooks) context.Context {
	return context.WithValue(ctx, hooksKey{}, hooks)
}

// From returns the hooks of ctx, or none.
func From(ctx context.Context) Hooks {
	hooks, _ := ctx.Value(hooksKey{}).(Hooks)
	return hooks
}

// Control chains own, GraphWAN's socket options, with the hook of ctx.
func Control(ctx context.Context, own func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	hook := From(ctx).Control
	if hook == nil {
		return own
	}
	return func(network, address string, c syscall.RawConn) error {
		if own != nil {
			if err := own(network, address, c); err != nil {
				return err
			}
		}
		return hook(network, address, c)
	}
}

// LookupNetIP resolves host with the hook of ctx, or the default resolver.
func LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if lookup := From(ctx).Lookup; lookup != nil {
		return lookup(ctx, network, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// Dial connects with dialer's options plus the hooks of ctx. With a Lookup
// hook, a host name is resolved by it and each address is tried in turn.
func Dial(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	hooks := From(ctx)
	if hooks.Control == nil && hooks.Lookup == nil {
		return dialer.DialContext(ctx, network, address)
	}
	d := *dialer
	d.Control = Control(ctx, dialer.Control)
	host, port, err := net.SplitHostPort(address)
	if err != nil || hooks.Lookup == nil {
		return d.DialContext(ctx, network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return d.DialContext(ctx, network, address)
	}
	family := "ip"
	switch network {
	case "tcp4", "udp4":
		family = "ip4"
	case "tcp6", "udp6":
		family = "ip6"
	}
	addresses, err := hooks.Lookup(ctx, family, host)
	if err != nil {
		return nil, err
	}
	var errs error
	for _, a := range addresses {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		errs = errors.Join(errs, err)
	}
	if errs == nil {
		errs = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	return nil, errs
}
