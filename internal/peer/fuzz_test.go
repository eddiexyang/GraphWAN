package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/secure"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"github.com/eddiexyang/graphnet/internal/transport"
)

// A hello comes from anyone who can reach the port.
func FuzzParseHello(f *testing.F) {
	hello, _ := Hello{Network: "00000000000000000000000000000001", Edge: "00000000000000000000000000000002", Initiator: "00000000000000000000000000000003", Responder: "00000000000000000000000000000004", Transport: "udp"}.marshal([]byte("noise"))
	f.Add(hello)
	f.Fuzz(func(t *testing.T, raw []byte) { parseHello(raw) })
}

// An established channel receives whatever its transport delivers: masked
// packets nobody authenticates, forged sealed and data messages. None may
// panic; masked ones too short or without a hop are dropped.
func FuzzChannelDecode(f *testing.F) {
	_, receiver := channelPair(f)
	f.Add([]byte{Masked | 9, 1, 2, 3, 4})
	f.Add(append([]byte{Masked | 1}, make([]byte, 100)...))
	f.Add(append([]byte{sealedKind}, make([]byte, 60)...))
	f.Add(append([]byte{dataKind}, make([]byte, 30)...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 {
			return
		}
		got, _ := receiver.decode(context.Background(), bytes.Clone(raw))
		if raw[0] >= Masked && got != nil && (len(got) < minMasked || got[0]&^Masked == 0) {
			t.Fatal("a malformed masked message passed")
		}
	})
}

// channelPair returns two ends of an established TCP channel.
func channelPair(tb testing.TB) (*Channel, *Channel) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
	seedA[0], seedB[0] = 1, 2
	keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
	a := secure.Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.TCP, Cipher: model.ChaCha20Poly1305, Identity: keyA, PeerIdentity: keyB.Public().(ed25519.PublicKey)}
	b := a
	b.Local, b.Peer, b.Identity, b.PeerIdentity = a.Peer, a.Local, keyB, keyA.Public().(ed25519.PublicKey)
	x, y := net.Pipe()
	accepted := make(chan *Channel, 1)
	go func() {
		channel, _ := Accept(ctx, transport.NewStream(y), model.TCP, func(Hello) (secure.Config, error) { return b, nil })
		accepted <- channel
	}()
	sender, err := Dial(ctx, transport.NewStream(x), a)
	if err != nil {
		tb.Fatal(err)
	}
	receiver := <-accepted
	if receiver == nil {
		tb.Fatal("no channel")
	}
	tb.Cleanup(func() { sender.Close(); receiver.Close() })
	return sender, receiver
}
