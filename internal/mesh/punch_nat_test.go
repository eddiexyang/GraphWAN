package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"github.com/eddiexyang/graphnet/internal/transport"
)

func TestUDPPunchAcrossPortRestrictedConeAndBlockAllFirewall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, keyA, _ := ed25519.GenerateKey(rand.Reader)
	_, keyB, _ := ed25519.GenerateKey(rand.Reader)

	gotA := make(chan []byte, 4)
	gotB := make(chan []byte, 4)
	mA, err := New(ctx, keyA, "127.0.0.1", 0, func(_ context.Context, _ model.ID, data []byte) error {
		select {
		case gotA <- bytes.Clone(data):
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mA.Close()

	mB, err := New(ctx, keyB, "127.0.0.1", 0, func(_ context.Context, _ model.ID, data []byte) error {
		select {
		case gotB <- bytes.Clone(data):
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mB.Close()

	// A is behind a strict Port-Restricted Cone NAT (3s pinhole TTL).
	// B is behind a block-all conntrack firewall (only accepts replies after B sends to A).
	wanA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wanA.Close()
	lanA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lanA.Close()
	wanB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wanB.Close()
	lanB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lanB.Close()

	localA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(mA.Port())}
	localB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(mB.Port())}
	wanAddrA := wanA.LocalAddr().(*net.UDPAddr)
	wanAddrB := wanB.LocalAddr().(*net.UDPAddr)

	var aMu sync.Mutex
	aAllowed := map[string]time.Time{}
	var bMu sync.Mutex
	bAllowed := map[string]bool{}

	// A <-> wanA <-> wanB <-> B
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, _, err := lanA.ReadFrom(buf)
			if err != nil {
				return
			}
			aMu.Lock()
			aAllowed[wanAddrB.String()] = time.Now().Add(3 * time.Second)
			aMu.Unlock()
			_, _ = wanA.WriteTo(buf[:n], wanAddrB)
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := wanA.ReadFrom(buf)
			if err != nil {
				return
			}
			aMu.Lock()
			exp, ok := aAllowed[from.String()]
			aMu.Unlock()
			if !ok || time.Now().After(exp) {
				continue
			}
			_, _ = lanA.WriteTo(buf[:n], localA)
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, _, err := lanB.ReadFrom(buf)
			if err != nil {
				return
			}
			bMu.Lock()
			bAllowed[wanAddrA.String()] = true
			bMu.Unlock()
			_, _ = wanB.WriteTo(buf[:n], wanAddrA)
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := wanB.ReadFrom(buf)
			if err != nil {
				return
			}
			bMu.Lock()
			ok := bAllowed[from.String()]
			bMu.Unlock()
			if !ok {
				continue
			}
			_, _ = lanB.WriteTo(buf[:n], localB)
		}
	}()

	netID := testutil.ID(1)
	nodeA := testutil.ID(21)
	nodeB := testutil.ID(22)
	edgeID := testutil.ID(31)

	dir := []model.Destination{
		{NodeID: nodeA, Address: netip.MustParseAddr("10.99.0.1"), Client: true, PublicKey: keyA.Public().(ed25519.PublicKey), Index: 1},
		{NodeID: nodeB, Address: netip.MustParseAddr("10.99.0.2"), PublicKey: keyB.Public().(ed25519.PublicKey), Index: 2},
	}
	snapA := func(rev uint64) model.Snapshot {
		return model.Snapshot{
			Schema:     model.SchemaVersion,
			Revision:   rev,
			AgentID:    testutil.ID(11),
			ListenPort: mA.Port(),
			Endpoints: []model.Endpoint{
				{ID: testutil.ID(41), Transport: model.UDP, Source: model.Observed, URL: "udp://" + lanB.LocalAddr().String(), ExpiresAt: time.Now().Add(2 * time.Minute)},
			},
			Networks: []model.NetworkConfig{{
				ID: netID, Name: "net", CIDR: netip.MustParsePrefix("10.99.0.0/24"), MTU: 1280, Cipher: model.AES128GCM,
				Self:      model.Node{ID: nodeA, AgentID: testutil.ID(11), Name: "A", Address: netip.MustParseAddr("10.99.0.1"), Client: true},
				Directory: dir,
				Peers: []model.Peer{{
					Node:      model.Node{ID: nodeB, AgentID: testutil.ID(12), Name: "B", Address: netip.MustParseAddr("10.99.0.2")},
					PublicKey: keyB.Public().(ed25519.PublicKey),
					Endpoints: []model.Endpoint{
						{ID: testutil.ID(42), Transport: model.UDP, Source: model.Manual, URL: "udp://" + lanA.LocalAddr().String()},
					},
					Edge: model.Edge{ID: edgeID, A: nodeA, B: nodeB, Weight: 10, Enabled: true, Transports: []model.Transport{model.UDP}, Methods: model.ConnectionMethods{HolePunch: true}},
				}},
			}},
		}
	}
	snapB := func(rev uint64, withA bool) model.Snapshot {
		var peers []model.Peer
		if withA {
			peers = []model.Peer{{
				Node:      model.Node{ID: nodeA, AgentID: testutil.ID(11), Name: "A", Address: netip.MustParseAddr("10.99.0.1"), Client: true},
				PublicKey: keyA.Public().(ed25519.PublicKey),
				Endpoints: []model.Endpoint{
					{ID: testutil.ID(41), Transport: model.UDP, Source: model.Observed, URL: "udp://" + lanB.LocalAddr().String(), ExpiresAt: time.Now().Add(2 * time.Minute)},
				},
				Edge: model.Edge{ID: edgeID, A: nodeA, B: nodeB, Weight: 10, Enabled: true, Transports: []model.Transport{model.UDP}, Methods: model.ConnectionMethods{HolePunch: true}},
			}}
		}
		return model.Snapshot{
			Schema:     model.SchemaVersion,
			Revision:   rev,
			AgentID:    testutil.ID(12),
			ListenPort: mB.Port(),
			Endpoints: []model.Endpoint{
				{ID: testutil.ID(42), Transport: model.UDP, Source: model.Manual, URL: "udp://" + lanA.LocalAddr().String()},
			},
			Networks: []model.NetworkConfig{{
				ID: netID, Name: "net", CIDR: netip.MustParsePrefix("10.99.0.0/24"), MTU: 1280, Cipher: model.AES128GCM,
				Self:      model.Node{ID: nodeB, AgentID: testutil.ID(12), Name: "B", Address: netip.MustParseAddr("10.99.0.2")},
				Directory: dir,
				Peers:     peers,
			}},
		}
	}

	if err := mA.Apply(snapA(1)); err != nil {
		t.Fatal(err)
	}
	// B initially does not have A's STUN endpoint yet.
	if err := mB.Apply(snapB(1, false)); err != nil {
		t.Fatal(err)
	}

	// Wait past A's first 10s dial timeout so A would previously be in long
	// backoff and let its 3s PR-cone pinhole expire.
	time.Sleep(11 * time.Second)

	// Now B learns A's STUN endpoint and dials via lanB -> wanB -> wanA -> A.
	if err := mB.Apply(snapB(2, true)); err != nil {
		t.Fatal(err)
	}

	payloadA := make([]byte, packet.HeaderSize+16)
	copy(payloadA[packet.HeaderSize:], "from-A")
	payloadB := make([]byte, packet.HeaderSize+16)
	copy(payloadB[packet.HeaderSize:], "from-B")

	deadline := time.Now().Add(6 * time.Second)
	for {
		if err := mA.Send(ctx, netID, nodeB, payloadA); err == nil {
			if err := mB.Send(ctx, netID, nodeA, payloadB); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP punch failed to connect across PR-cone NAT + block-all firewall: A=%+v B=%+v", mA.Report(), mB.Report())
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case msg := <-gotB:
		if !bytes.Equal(msg, payloadA) {
			t.Fatalf("B received %x, want %x", msg, payloadA)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B did not receive packet from A")
	}
	select {
	case msg := <-gotA:
		if !bytes.Equal(msg, payloadB) {
			t.Fatalf("A received %x, want %x", msg, payloadB)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("A did not receive packet from B")
	}
}

func TestTCPPunchIgnoresDirectDialStarvation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create 8 stalling TCP listeners that accept connections and never send
	// GraphNet hellos, saturating all normal Direct dial slots for 12s.
	var stalledEndpoints []model.Endpoint
	for i := range 8 {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				t.Cleanup(func() { c.Close() })
			}
		}()
		stalledEndpoints = append(stalledEndpoints, model.Endpoint{
			ID:        testutil.ID(60 + i),
			Transport: model.TCP,
			Source:    model.Manual,
			URL:       "tcp://" + ln.Addr().String(),
		})
	}

	_, keyA, _ := ed25519.GenerateKey(rand.Reader)
	_, keyB, _ := ed25519.GenerateKey(rand.Reader)
	gotB := make(chan []byte, 4)
	mA, err := New(ctx, keyA, "127.0.0.1", 0, func(context.Context, model.ID, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer mA.Close()
	mB, err := New(ctx, keyB, "127.0.0.1", 0, func(_ context.Context, _ model.ID, data []byte) error {
		select {
		case gotB <- bytes.Clone(data):
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mB.Close()

	netID := testutil.ID(1)
	nodeA := testutil.ID(21)
	nodeB := testutil.ID(22)
	edgeID := testutil.ID(31)

	epA := model.Endpoint{ID: testutil.ID(41), Transport: model.TCP, Source: model.Observed, URL: fmt.Sprintf("tcp://127.0.0.1:%d", mA.Port()), ExpiresAt: time.Now().Add(2 * time.Minute)}
	epB := model.Endpoint{ID: testutil.ID(42), Transport: model.TCP, Source: model.Manual, URL: fmt.Sprintf("tcp://127.0.0.1:%d", mB.Port())}

	dir := []model.Destination{
		{NodeID: nodeA, Address: netip.MustParseAddr("10.99.0.1"), Client: true, PublicKey: keyA.Public().(ed25519.PublicKey), Index: 1},
		{NodeID: nodeB, Address: netip.MustParseAddr("10.99.0.2"), PublicKey: keyB.Public().(ed25519.PublicKey), Index: 2},
	}
	// A has 8 stalling Direct endpoints + 1 Punch endpoint to B.
	aPeersEndpoints := append([]model.Endpoint{}, stalledEndpoints...)
	aPeersEndpoints = append(aPeersEndpoints, epB)
	if err := mA.Apply(model.Snapshot{
		Schema: model.SchemaVersion, Revision: 1, AgentID: testutil.ID(11), ListenPort: mA.Port(),
		Endpoints: []model.Endpoint{epA},
		Networks: []model.NetworkConfig{{
			ID: netID, Name: "net", CIDR: netip.MustParsePrefix("10.99.0.0/24"), MTU: 1280, Cipher: model.AES128GCM,
			Self:      model.Node{ID: nodeA, AgentID: testutil.ID(11), Name: "A", Address: netip.MustParseAddr("10.99.0.1"), Client: true},
			Directory: dir,
			Peers: []model.Peer{{
				Node:      model.Node{ID: nodeB, AgentID: testutil.ID(12), Name: "B", Address: netip.MustParseAddr("10.99.0.2")},
				PublicKey: keyB.Public().(ed25519.PublicKey),
				Endpoints: aPeersEndpoints,
				Edge:      model.Edge{ID: edgeID, A: nodeA, B: nodeB, Weight: 10, Enabled: true, Transports: []model.Transport{model.TCP}, Methods: model.ConnectionMethods{IPv4Direct: true, HolePunch: true}},
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := mB.Apply(model.Snapshot{
		Schema: model.SchemaVersion, Revision: 1, AgentID: testutil.ID(12), ListenPort: mB.Port(),
		Endpoints: []model.Endpoint{epB},
		Networks: []model.NetworkConfig{{
			ID: netID, Name: "net", CIDR: netip.MustParsePrefix("10.99.0.0/24"), MTU: 1280, Cipher: model.AES128GCM,
			Self:      model.Node{ID: nodeB, AgentID: testutil.ID(12), Name: "B", Address: netip.MustParseAddr("10.99.0.2")},
			Directory: dir,
			Peers: []model.Peer{{
				Node:      model.Node{ID: nodeA, AgentID: testutil.ID(11), Name: "A", Address: netip.MustParseAddr("10.99.0.1"), Client: true},
				PublicKey: keyA.Public().(ed25519.PublicKey),
				Endpoints: []model.Endpoint{epA},
				Edge:      model.Edge{ID: edgeID, A: nodeA, B: nodeB, Weight: 10, Enabled: true, Transports: []model.Transport{model.TCP}, Methods: model.ConnectionMethods{HolePunch: true}},
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, packet.HeaderSize+16)
	copy(payload[packet.HeaderSize:], "tcp-punch-ok")
	deadline := time.Now().Add(4 * time.Second)
	for {
		if err := mA.Send(ctx, netID, nodeB, payload); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TCP punch was starved by Direct dials: %+v", mA.Report())
		}
		time.Sleep(25 * time.Millisecond)
	}
	select {
	case msg := <-gotB:
		if !bytes.Equal(msg, payload) {
			t.Fatalf("B received %x, want %x", msg, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B did not receive TCP punch packet")
	}
}

func TestWaitForInstalledPunchWakesImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, keyA, _ := ed25519.GenerateKey(rand.Reader)
	_, keyB, _ := ed25519.GenerateKey(rand.Reader)
	mA, err := New(ctx, keyA, "127.0.0.1", 0, func(context.Context, model.ID, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer mA.Close()
	mB, err := New(ctx, keyB, "127.0.0.1", 0, func(context.Context, model.ID, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer mB.Close()

	netID := testutil.ID(1)
	nodeA := testutil.ID(21)
	nodeB := testutil.ID(22)
	edgeID := testutil.ID(31)
	if err := mA.Apply(model.Snapshot{
		Schema: model.SchemaVersion, Revision: 1, AgentID: testutil.ID(11), ListenPort: mA.Port(),
		Networks: []model.NetworkConfig{{
			ID: netID, Name: "net", CIDR: netip.MustParsePrefix("10.99.0.0/24"), MTU: 1280, Cipher: model.AES128GCM,
			Self: model.Node{ID: nodeA, AgentID: testutil.ID(11), Name: "A", Address: netip.MustParseAddr("10.99.0.1"), Client: true},
			Directory: []model.Destination{
				{NodeID: nodeA, Address: netip.MustParseAddr("10.99.0.1"), Client: true, PublicKey: keyA.Public().(ed25519.PublicKey), Index: 1},
				{NodeID: nodeB, Address: netip.MustParseAddr("10.99.0.2"), PublicKey: keyB.Public().(ed25519.PublicKey), Index: 2},
			},
			Peers: []model.Peer{{
				Node:      model.Node{ID: nodeB, AgentID: testutil.ID(12), Name: "B", Address: netip.MustParseAddr("10.99.0.2")},
				PublicKey: keyB.Public().(ed25519.PublicKey),
				Edge:      model.Edge{ID: edgeID, A: nodeA, B: nodeB, Weight: 10, Enabled: true, Transports: []model.Transport{model.TCP}, Methods: model.ConnectionMethods{HolePunch: true}},
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c1, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	remote := netip.MustParseAddrPort("127.0.0.1:42424")
	var peerIdentity [32]byte
	copy(peerIdentity[:], keyB.Public().(ed25519.PublicKey))

	errCh := make(chan error, 2)
	go func() {
		_, err := transport.NewPunchMux(ctx, c2, keyB.Public().(ed25519.PublicKey), mB.tls, func(ed25519.PublicKey) bool { return true }, false)
		errCh <- err
	}()

	time.AfterFunc(100*time.Millisecond, func() {
		session, err := transport.NewPunchMux(ctx, c1, keyA.Public().(ed25519.PublicKey), mA.tls, func(ed25519.PublicKey) bool { return true }, false)
		errCh <- err
		if err != nil {
			return
		}
		mA.mu.Lock()
		mA.punches[punchKey{remote: remote, identity: peerIdentity, local: netip.MustParseAddrPort("127.0.0.1:10001")}] = session
		if mA.punchNotify != nil {
			close(mA.punchNotify)
			mA.punchNotify = make(chan struct{})
		}
		mA.mu.Unlock()
	})

	start := time.Now()
	session := mA.waitForInstalledPunch(ctx, remote, peerIdentity, 2*time.Second)
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("NewPunchMux: %v", err)
		}
	}
	if session == nil {
		t.Fatal("waitForInstalledPunch returned nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waitForInstalledPunch took %v, expected immediate wake", elapsed)
	}
}
