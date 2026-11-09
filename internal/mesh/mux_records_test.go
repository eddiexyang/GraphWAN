package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func e2eSessions(t testing.TB) (*secure.Session, *secure.Session) {
	t.Helper()
	apub, akey, _ := ed25519.GenerateKey(rand.Reader)
	bpub, bkey, _ := ed25519.GenerateKey(rand.Reader)
	a, err := secure.NewEndToEndHandshake(secure.E2EConfig{Network: testutil.ID(1), Local: testutil.ID(2), Peer: testutil.ID(3), Cipher: model.AES128GCM, Identity: akey, PeerIdentity: bpub, Initiator: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := secure.NewEndToEndHandshake(secure.E2EConfig{Network: testutil.ID(1), Local: testutil.ID(3), Peer: testutil.ID(2), Cipher: model.AES128GCM, Identity: bkey, PeerIdentity: apub})
	if err != nil {
		t.Fatal(err)
	}
	var as, bs *secure.Session
	for from, to := a, b; as == nil || bs == nil; from, to = to, from {
		message, s, err := from.Write()
		if err != nil {
			t.Fatal(err)
		}
		if s != nil {
			as = s
		}
		if s, err = to.Read(message); err != nil {
			t.Fatal(err)
		}
		if s != nil {
			bs = s
		}
	}
	return as, bs
}

// sealedHops opens a session's hop from a to b, as the ingress and egress
// see it after the chain's request.
func sealedHops(t *testing.T, p *muxPair) (*muxStream, *muxStream) {
	t.Helper()
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	s, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	peer := p.accept(t)
	if _, err := io.ReadFull(peer, make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	return s, peer
}

func sealedEnds(t *testing.T, s, peer *muxStream) (*streamproxy.End, *streamproxy.End, *streamproxy.Records) {
	t.Helper()
	as, bs := e2eSessions(t)
	ingress, err := streamproxy.StartIngress(context.Background(), func(context.Context, uint32, uint64, uint64) (streamproxy.Hop, uint64, error) {
		return s, 0, nil
	}, &streamproxy.Counters{}, streamproxy.NewRecords(as, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ingress.Abort)
	records := streamproxy.NewRecords(bs, 1)
	egress := streamproxy.NewEgress(context.Background(), peer, func(uint32) {}, &streamproxy.Counters{}, records)
	t.Cleanup(egress.Abort)
	return ingress, egress, records
}

// The ends of a sealed session exchange their bytes as records, which the
// hop between them carries with the records' length and tag.
func TestMuxCarriesSealedRecords(t *testing.T) {
	p := newMuxPair(t)
	s, peer := sealedHops(t, p)
	ingress, egress, _ := sealedEnds(t, s, peer)
	payload := make([]byte, 4<<20)
	rand.Read(payload)
	reply := []byte("sealed reply")
	go func() {
		ingress.Write(payload)
		ingress.CloseWrite()
	}()
	got, err := io.ReadAll(egress)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("upstream bytes changed", err, len(got))
	}
	go func() {
		egress.Write(reply)
		egress.CloseWrite()
	}()
	if got, err := io.ReadAll(ingress); err != nil || !bytes.Equal(got, reply) {
		t.Fatal("downstream bytes changed", err)
	}
	_, tx := s.Bytes()
	added := tx - 7 - uint64(len(payload))
	least := uint64(streamproxy.RecordOverhead) * uint64((len(payload)+muxMaxData-streamproxy.RecordOverhead-1)/(muxMaxData-streamproxy.RecordOverhead))
	if added%streamproxy.RecordOverhead != 0 || added < least {
		t.Fatalf("hop carried %d bytes for %d", tx-7, len(payload))
	}
}

// The hop carries only ciphertext: what a relay reads never holds the
// session's bytes.
func TestMuxSealedHopHoldsNoPlaintext(t *testing.T) {
	p := newMuxPair(t)
	s, peer := sealedHops(t, p)
	ingress, _, _ := sealedEnds(t, s, peer)
	// The egress End is not reading: this test reads its hop as a relay does.
	payload := bytes.Repeat([]byte("plaintext!"), 100<<10)
	go func() {
		ingress.Write(payload)
		ingress.CloseWrite()
	}()
	raw := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("plaintext!plaintext!")) {
		t.Fatal("the hop carried plaintext")
	}
}

// A record changed on the way resets the connection at both ends.
func TestMuxChangedRecordResetsSession(t *testing.T) {
	p := newMuxPair(t)
	s, peer := sealedHops(t, p)
	as, bs := e2eSessions(t)
	egress := streamproxy.NewEgress(context.Background(), peer, func(uint32) {}, &streamproxy.Counters{}, streamproxy.NewRecords(bs, 1))
	defer egress.Abort()
	s.Begin(0)
	sender := streamproxy.NewRecords(as, 1)
	seal := func(plaintext string) []byte {
		record := make([]byte, streamproxy.RecordHeader+len(plaintext), streamproxy.RecordOverhead+len(plaintext))
		copy(record[streamproxy.RecordHeader:], plaintext)
		sealed, err := sender.Seal(record)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	first, second := seal("first"), seal("second")
	second[len(second)-1] ^= 1
	s.Write(first)
	s.Write(second)
	// The reset may discard the record before the changed one, as a TCP
	// reset discards what was not read.
	got, err := io.ReadAll(egress)
	if err == nil || string(got) != "first" && len(got) != 0 {
		t.Fatalf("read %q, %v", got, err)
	}
	waitFor(t, "the reset at the ingress hop", s.Aborted)
}
