package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"testing"
	"time"
)

// STUN replies arrive on the shared data socket from anyone.
func FuzzSTUN(f *testing.F) {
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decodeSTUN(raw)
		parseSTUNResponse(raw, true)
		parseSTUNResponse(raw, false)
	})
}

// Whatever arrives on the shared port, the QUIC gate decides without
// panicking, and admits no Initial without a knock.
func FuzzQUICGate(f *testing.F) {
	_, identity, _ := ed25519.GenerateKey(nil)
	q := &QUICHub{knocks: map[netip.AddrPort]time.Time{}}
	q.ids = quicIDs{key: quicKey(identity.Seed(), "id")}
	q.knockKey = quicKey(identity.Public().(ed25519.PublicKey), "GraphNet QUIC knock v1")
	remote := netip.MustParseAddrPort("192.0.2.1:9")
	f.Add(knockFor(identity.Public().(ed25519.PublicKey)))
	f.Add(append([]byte{0xc0, 0, 0, 0, 1, 8}, make([]byte, 1200)...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		now := time.Now()
		clear(q.knocks)
		if q.admit(raw, remote, now) && len(raw) > 5 && raw[0]&0x80 != 0 && raw[0]&0x30 == 0 && (int(raw[5]) != quicIDSize || !q.ids.verify(raw[6:6+quicIDSize])) {
			t.Fatal("an Initial passed without a knock")
		}
		q.knock(raw, remote, now)
	})
}

// A stream peer chooses every length prefix and byte.
func FuzzStreamReceive(f *testing.F) {
	f.Add([]byte{0, 0, 0, 3, 'a', 'b', 'c'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, b := net.Pipe()
		defer a.Close()
		go func() { a.Write(raw); a.Close() }()
		s := NewStream(b)
		defer s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for {
			message, err := s.Receive(ctx)
			if err != nil {
				return
			}
			if len(message) == 0 || len(message) > MaxMessage || !bytes.Contains(raw, message) {
				t.Fatal("stream returned a message it was not sent")
			}
		}
	})
}
