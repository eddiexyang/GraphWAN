package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"github.com/eWloYW8/GraphWAN/internal/transport"
)

func streamPair(t *testing.T, ctx context.Context) (*Stream, *Stream) {
	t.Helper()
	seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
	seedA[0], seedB[0] = 1, 2
	keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
	a := secure.Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.TCP, Cipher: model.ChaCha20Poly1305, Identity: keyA, PeerIdentity: keyB.Public().(ed25519.PublicKey)}
	b := a
	b.Local, b.Peer, b.Identity, b.PeerIdentity = a.Peer, a.Local, keyB, keyA.Public().(ed25519.PublicKey)
	x, y := net.Pipe()
	accepted := make(chan *Channel, 1)
	fail := make(chan error, 1)
	go func() {
		c, err := Accept(ctx, transport.NewStream(y), model.TCP, func(Hello) (secure.Config, error) { return b, nil })
		if err != nil {
			fail <- err
		} else {
			accepted <- c
		}
	}()
	ca, err := Dial(ctx, transport.NewStream(x), a)
	if err != nil {
		t.Fatal(err)
	}
	var cb *Channel
	select {
	case cb = <-accepted:
	case err := <-fail:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	sa, err := NewStream(ctx, ctx, ca, true)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := NewStream(ctx, ctx, cb, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sa.Close(); sb.Close() })
	return sa, sb
}

func TestStreamBytesAndHalfClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, b := streamPair(t, ctx)
	payload := bytes.Repeat([]byte("application stream bytes"), 100000)
	result := make(chan error, 1)
	go func() {
		raw, err := io.ReadAll(b)
		if err == nil && !bytes.Equal(raw, payload) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = b.Write([]byte("response after EOF"))
		}
		if err == nil {
			err = b.CloseWrite()
		}
		b.Close()
		result <- err
	}()
	if n, err := a.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("after EOF")); err != io.ErrClosedPipe {
		t.Fatal("write half remained open", err)
	}
	raw, err := io.ReadAll(a)
	if err != nil || string(raw) != "response after EOF" {
		t.Fatal(string(raw), err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestStreamCancellationInterruptsBlockedWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a, _ := streamPair(t, ctx)
	done := make(chan error, 1)
	go func() { _, err := a.Write(make([]byte, 10000)); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("stream writer leaked after cancellation")
	}
}

func TestStreamRejectsInvalidRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, b := streamPair(t, ctx)
	go a.channel.Send(ctx, []byte{99})
	if _, err := b.Read(make([]byte, 10)); err == nil {
		t.Fatal("unknown record accepted")
	}
}
