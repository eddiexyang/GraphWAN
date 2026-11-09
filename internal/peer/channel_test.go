package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"github.com/eWloYW8/GraphWAN/internal/transport"
)

// The receiver exposes only the original single-message transport API.
type legacyChannelTransport struct{ transport.Conn }

type framedChannelTransport struct {
	*transport.Stream
	framed atomic.Int32
}

func (c *framedChannelTransport) SendFramedBatch(ctx context.Context, data []byte) error {
	c.framed.Add(1)
	return c.Stream.SendFramedBatch(ctx, data)
}

func TestPacketChannelBatchWithLegacyReceiver(t *testing.T) {
	for _, cipher := range []model.CipherSuite{model.AES128GCM, model.AES256GCM, model.ChaCha20Poly1305, model.XChaCha20Poly1305} {
		for _, contiguous := range []bool{false, true} {
			name := string(cipher) + "/legacy"
			if contiguous {
				name = string(cipher) + "/contiguous"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
				seedA[0], seedB[0] = 1, 2
				keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
				a := secure.Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.TCP, Cipher: cipher, Identity: keyA, PeerIdentity: keyB.Public().(ed25519.PublicKey)}
				b := a
				b.Local, b.Peer, b.Identity, b.PeerIdentity = a.Peer, a.Local, keyB, keyA.Public().(ed25519.PublicKey)
				x, y := net.Pipe()
				defer x.Close()
				defer y.Close()
				framed := &framedChannelTransport{Stream: transport.NewStream(x)}
				var outgoing transport.Conn = framed
				if !contiguous {
					outgoing = legacyChannelTransport{Conn: framed}
				}
				type result struct {
					channel *Channel
					err     error
				}
				accepted := make(chan result, 1)
				go func() {
					channel, err := Accept(ctx, legacyChannelTransport{Conn: transport.NewStream(y)}, model.TCP, func(Hello) (secure.Config, error) { return b, nil })
					accepted <- result{channel, err}
				}()
				sender, err := Dial(ctx, outgoing, a)
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				incoming := <-accepted
				if incoming.err != nil {
					t.Fatal(incoming.err)
				}
				defer incoming.channel.Close()
				framed.framed.Store(0)
				for _, count := range []int{1, 32, 128} {
					payloads := make([][]byte, count)
					originals := make([][]byte, count)
					for i := range payloads {
						size := 1337
						if i == 0 {
							size = 9 // Control messages share the packet channel.
						} else if i == count-1 {
							size = secure.MaxPlaintext
						}
						payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
						originals[i] = bytes.Clone(payloads[i])
					}
					done := make(chan error, 1)
					go func() { done <- sender.SendBatch(ctx, payloads) }()
					for _, want := range originals {
						got, err := incoming.channel.Receive(ctx)
						if err != nil || !bytes.Equal(got, want) {
							t.Fatal("legacy receiver lost an independently authenticated message", len(got), err)
						}
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					for i, want := range originals {
						if !bytes.Equal(payloads[i], want) {
							t.Fatal("batch send changed caller-owned plaintext")
						}
					}
				}
				wantCalls := int32(0)
				if contiguous {
					wantCalls = 3
				}
				if framed.framed.Load() != wantCalls {
					t.Fatal("incorrect framed transport selection", framed.framed.Load())
				}
			})
		}
	}
}

type recordingTransport struct {
	*transport.Stream
	sent bytes.Buffer
}

func (c *recordingTransport) SendFramedBatch(ctx context.Context, data []byte) error {
	c.sent.Write(data)
	return c.Stream.SendFramedBatch(ctx, data)
}

// A sealed payload's header, or a prefixed payload's prefix, is encrypted and
// the rest travels as it is; the receiver gets the payload back, alone or
// among data messages in a batch.
func TestSealedPayloadIsEncryptedOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
	seedA[0], seedB[0] = 1, 2
	keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
	a := secure.Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.TCP, Cipher: model.AES128GCM, Identity: keyA, PeerIdentity: keyB.Public().(ed25519.PublicKey)}
	b := a
	b.Local, b.Peer, b.Identity, b.PeerIdentity = a.Peer, a.Local, keyB, keyA.Public().(ed25519.PublicKey)
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	recording := &recordingTransport{Stream: transport.NewStream(x)}
	accepted := make(chan *Channel, 1)
	go func() {
		channel, err := Accept(ctx, transport.NewStream(y), model.TCP, func(Hello) (secure.Config, error) { return b, nil })
		if err != nil {
			t.Error(err)
		}
		accepted <- channel
	}()
	sender, err := Dial(ctx, recording, a)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver := <-accepted
	if receiver == nil {
		t.FailNow()
	}
	defer receiver.Close()
	header := append([]byte{SealedPayload}, bytes.Repeat([]byte("H"), SealedHeader-1)...)
	sealed := append(bytes.Clone(header), bytes.Repeat([]byte("already sealed"), 500)...)
	data := bytes.Repeat([]byte("D"), 1000)
	readable := append([]byte{SealedPrefix, 40}, bytes.Repeat([]byte("R"), 38)...)
	packet := append(bytes.Clone(readable), bytes.Repeat([]byte("sealed packet"), 100)...)
	for _, batch := range [][][]byte{{sealed}, {packet}, {data, sealed, packet, data, sealed}} {
		recording.sent.Reset()
		done := make(chan error, 1)
		go func() { done <- sender.SendBatch(ctx, batch) }()
		var got [][]byte
		for len(got) < len(batch) {
			messages, err := receiver.ReceiveBatch(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range messages {
				got = append(got, bytes.Clone(m))
			}
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		for i := range batch {
			if !bytes.Equal(got[i], batch[i]) {
				t.Fatalf("message %d of %d changed", i, len(batch))
			}
		}
		wire := recording.sent.Bytes()
		if bytes.Contains(wire, header) || bytes.Contains(wire, readable[2:]) || bytes.Contains(wire, data[:64]) {
			t.Fatal("the channel sent bytes it should have encrypted")
		}
		for _, m := range batch {
			if rest := m[prefix(m):]; len(rest) > 0 && !bytes.Contains(wire, rest) {
				t.Fatal("the channel encrypted bytes already sealed")
			}
		}
	}
}
