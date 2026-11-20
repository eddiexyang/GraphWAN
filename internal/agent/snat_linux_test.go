//go:build linux

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/tunnel"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestDialSNATIsolatesHostAndOtherNetworkRoutes(t *testing.T) {
	if os.Getenv("GRAPHNET_SNAT_NETNS_HELPER") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDialSNATIsolatesHostAndOtherNetworkRoutes$", "-test.v")
		cmd.Env = append(os.Environ(), "GRAPHNET_SNAT_NETNS_HELPER=1")
		attrs := &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		if os.Geteuid() != 0 {
			attrs.Cloneflags |= syscall.CLONE_NEWUSER
			attrs.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
			attrs.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
		}
		cmd.SysProcAttr = attrs
		out, err := cmd.CombinedOutput()
		if err != nil {
			if os.Geteuid() != 0 && errors.Is(err, syscall.EPERM) {
				t.Skipf("network namespace unavailable without privileges: %v", err)
			}
			t.Fatalf("netns helper failed: %v\n%s", err, out)
		}
		return
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}

	// Peer namespace hosts the external TCP server behind two WAN NICs (ECMP).
	runtime.LockOSThread()
	hostNS, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer hostNS.Close()
	peerNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer peerNS.Close()
	if err := netns.Set(hostNS); err != nil {
		t.Fatal(err)
	}
	runtime.UnlockOSThread()

	setupWAN := func(hostName, peerName, hostCIDR, peerCIDR string) (int, net.IP) {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}, PeerName: peerName}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatal(err)
		}
		peerLink, err := netlink.LinkByName(peerName)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetNsFd(peerLink, int(peerNS)); err != nil {
			t.Fatal(err)
		}
		hostLink, err := netlink.LinkByName(hostName)
		if err != nil {
			t.Fatal(err)
		}
		hAddr, err := netlink.ParseAddr(hostCIDR)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(hostLink, hAddr); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(hostLink); err != nil {
			t.Fatal(err)
		}
		pAddr, err := netlink.ParseAddr(peerCIDR)
		if err != nil {
			t.Fatal(err)
		}
		runtime.LockOSThread()
		if err := netns.Set(peerNS); err != nil {
			runtime.UnlockOSThread()
			t.Fatal(err)
		}
		pLink, err := netlink.LinkByName(peerName)
		if err == nil {
			err = netlink.AddrAdd(pLink, pAddr)
		}
		if err == nil {
			err = netlink.LinkSetUp(pLink)
		}
		_ = netns.Set(hostNS)
		runtime.UnlockOSThread()
		if err != nil {
			t.Fatal(err)
		}
		return hostLink.Attrs().Index, pAddr.IP
	}

	wan0Idx, wan0GW := setupWAN("wan0", "pwan0", "198.51.100.1/30", "198.51.100.2/30")
	wan1Idx, wan1GW := setupWAN("wan1", "pwan1", "198.51.100.5/30", "198.51.100.6/30")

	// Start an external TCP target on 203.0.113.10:8080 inside peerNS.
	listenerReady := make(chan error, 1)
	serverDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := netns.Set(peerNS); err != nil {
			listenerReady <- err
			return
		}
		loPeer, err := netlink.LinkByName("lo")
		if err == nil {
			err = netlink.LinkSetUp(loPeer)
		}
		if err == nil {
			addr, _ := netlink.ParseAddr("203.0.113.10/32")
			err = netlink.AddrAdd(loPeer, addr)
		}
		if err != nil {
			listenerReady <- err
			return
		}
		ln, err := net.Listen("tcp4", "203.0.113.10:8080")
		if err != nil {
			listenerReady <- err
			return
		}
		defer ln.Close()
		listenerReady <- nil
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("external-ok"))
		serverDone <- err
	}()
	if err := <-listenerReady; err != nil {
		t.Fatal(err)
	}

	// Install a dual-NIC ECMP default route via wan0 and wan1.
	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: defaultDst,
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: wan0Idx, Gw: wan0GW, Hops: 1},
			{LinkIndex: wan1Idx, Gw: wan1GW, Hops: 1},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Open two GraphNet TUNs on this host: Network A (6.6.6.2/24) and Network B (7.7.7.2/24).
	tunA, err := tunnel.Open(tunnel.Config{Address: netip.MustParsePrefix("6.6.6.2/24"), MTU: 1280})
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) {
			t.Skipf("/dev/net/tun unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer tunA.Close()
	tunB, err := tunnel.Open(tunnel.Config{Address: netip.MustParsePrefix("7.7.7.2/24"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	defer tunB.Close()

	// Also add a custom static route pointing into Network B's TUN.
	linkB, err := netlink.LinkByName(tunB.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, customNetB, _ := net.ParseCIDR("10.99.0.0/24")
	if err := netlink.RouteAdd(&netlink.Route{Dst: customNetB, LinkIndex: linkB.Attrs().Index}); err != nil {
		t.Fatal(err)
	}

	netAID := model.ID("00000000000000000000000000000001")
	netBID := model.ID("00000000000000000000000000000002")
	state := &runtimeState{
		snapshot: model.Snapshot{
			Networks: []model.NetworkConfig{
				{ID: netAID, CIDR: netip.MustParsePrefix("6.6.6.0/24")},
				{ID: netBID, CIDR: netip.MustParsePrefix("7.7.7.0/24")},
			},
		},
		devices: map[model.ID]*runtimeTunnel{
			netAID: newRuntimeTunnel(tunA),
			netBID: newRuntimeTunnel(tunB),
		},
		selfAddress: map[model.ID]netip.Addr{
			netAID: netip.MustParseAddr("6.6.6.2"),
			netBID: netip.MustParseAddr("7.7.7.2"),
		},
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dp := &DataPlane{identity: priv}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	blocked := []struct {
		name string
		dst  string
	}{
		{"other network peer", "7.7.7.1:8080"},
		{"other network self", "7.7.7.2:8080"},
		{"same network peer", "6.6.6.11:8080"},
		{"same network self", "6.6.6.2:8080"},
		{"static route via other TUN", "10.99.0.5:8080"},
		{"host WAN local address", "198.51.100.1:8080"},
		{"loopback", "127.0.0.1:8080"},
	}
	for _, tc := range blocked {
		conn, err := dp.dialSNAT(ctx, state, netip.MustParseAddrPort(tc.dst))
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, forwarding.ErrDestination) {
			t.Fatalf("%s (%s): got err=%v, want ErrDestination", tc.name, tc.dst, err)
		}
	}

	// External destination over dual-NIC ECMP default route must succeed.
	conn, err := dp.dialSNAT(ctx, state, netip.MustParseAddrPort("203.0.113.10:8080"))
	if err != nil {
		t.Fatalf("external ECMP dialSNAT failed: %v", err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "external-ok" {
		t.Fatalf("external ECMP read=%q, err=%v", got, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
