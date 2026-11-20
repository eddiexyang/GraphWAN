package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	quic "github.com/quic-go/quic-go"
)

// silent fails when anything arrives on conn within a short wait.
func silent(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, 2048)); n > 0 {
		t.Fatalf("%s drew %d bytes", what, n)
	}
}

// A probe of the shared UDP port gets no answer: not garbage, not a guessed
// QUIC connection ID, not a QUIC Initial from an address that did not knock.
// A dialer that knocks connects.
func TestUDPPortAnswersNoProbe(t *testing.T) {
	_, identity, _ := ed25519.GenerateKey(nil)
	udp, err := ListenUDP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	hub, err := udp.EnableQUIC(identity)
	if err != nil {
		t.Fatal(err)
	}
	target := udp.LocalAddr().(*net.UDPAddr).AddrPort()

	prober, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		t.Fatal(err)
	}
	defer prober.Close()
	garbage := make([]byte, 1200)
	for _, first := range []byte{0x00, 0x41, 0x45, 0x47, 0x51, 0x80, 0xc0, 0xff} {
		rand.Read(garbage)
		garbage[0] = first
		prober.Write(garbage)
	}
	short := make([]byte, 64)
	rand.Read(short)
	short[0], short[1] = 0x41, quicIDPrefix
	prober.Write(short)
	knock := knockFor(identity.Public().(ed25519.PublicKey))
	knock[len(knock)-1] ^= 1
	prober.Write(knock)
	silent(t, prober, "a UDP probe")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	_, err = quic.Dial(ctx, stranger, net.UDPAddrFromAddrPort(target), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{quicProtocol}}, &quic.Config{HandshakeIdleTimeout: time.Second})
	var idle *quic.IdleTimeoutError
	var handshake *quic.HandshakeTimeoutError
	if err == nil || !errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &idle) && !errors.As(err, &handshake) {
		t.Fatalf("an Initial without a knock was answered: %v", err)
	}

	dialer, err := ListenUDP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	_, dialIdentity, _ := ed25519.GenerateKey(nil)
	client, err := dialer.EnableQUIC(dialIdentity)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *QUIC, 1)
	go func() {
		link, _ := hub.Accept(context.Background())
		accepted <- link
	}()
	endpoint := model.Endpoint{ID: model.ID("00000000000000000000000000000001"), Transport: model.QUIC, Source: model.Manual, URL: "quic://" + target.String()}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	link, err := client.DialAt(dialCtx, endpoint, 4, identity.Public().(ed25519.PublicKey), netip.Addr{})
	if err != nil {
		t.Fatal("a knocked dial failed:", err)
	}
	defer link.Close()
	if err := link.Send(dialCtx, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case peer := <-accepted:
		if got, err := peer.Receive(dialCtx); err != nil || string(got) != "hello" {
			t.Fatal("stream message lost", err)
		}
		peer.Close()
	case <-dialCtx.Done():
		t.Fatal("no accepted QUIC Link")
	}
}

// A TCP punch session's accepting end says nothing to a stranger: a probe
// learns neither the protocol nor the identity.
func TestPassivePunchAnswersNoProbe(t *testing.T) {
	_, identity, _ := ed25519.GenerateKey(nil)
	certificate, err := PeerServerTLS(identity)
	if err != nil {
		t.Fatal(err)
	}
	agent, probe := net.Pipe()
	defer probe.Close()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := NewPunchMux(ctx, agent, identity.Public().(ed25519.PublicKey), certificate, func(ed25519.PublicKey) bool { return false }, true)
		done <- err
	}()
	hello := make([]byte, 36)
	copy(hello, punchMagic[:])
	rand.Read(hello[4:])
	go probe.Write(hello)
	silent(t, probe, "a punch probe")
	if err := <-done; err == nil {
		t.Fatal("a stranger's punch was accepted")
	}
}
