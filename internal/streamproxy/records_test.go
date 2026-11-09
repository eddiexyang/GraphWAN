package streamproxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// e2eSessions returns the two ends of an end-to-end session.
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

func sealRecord(t *testing.T, r *Records, plaintext []byte) []byte {
	t.Helper()
	record := make([]byte, RecordHeader+len(plaintext), RecordOverhead+len(plaintext))
	copy(record[RecordHeader:], plaintext)
	sealed, err := r.Seal(record)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// Records arrive in any split and open in order; a record left out, sent
// again or changed does not open.
func TestRecordsOpenInOrderOnly(t *testing.T) {
	as, bs := e2eSessions(t)
	sender := NewRecords(as, 5)
	messages := [][]byte{[]byte("first"), bytes.Repeat([]byte("x"), 9000), []byte("third")}
	var stream []byte
	var records [][]byte
	for _, m := range messages {
		record := sealRecord(t, sender, m)
		if len(record) != len(m)+RecordOverhead || bytes.Contains(record, m) {
			t.Fatal("record is not sealed")
		}
		records = append(records, record)
		stream = append(stream, record...)
	}
	open := func(stream []byte, chunk int) ([][]byte, error) {
		r := NewRecords(bs, 5)
		var out [][]byte
		read := func(p []byte) (int, error) {
			n := copy(p, stream[:min(len(stream), chunk)])
			stream = stream[n:]
			return n, nil
		}
		for len(stream) > 0 {
			ok, err := r.fill(read)
			if err != nil {
				return out, err
			}
			if ok {
				out = append(out, bytes.Clone(r.plain))
				r.plain = nil
			}
		}
		if r.partial() {
			return out, errRecord
		}
		return out, nil
	}
	for _, chunk := range []int{1, 7, 1 << 20} {
		out, err := open(bytes.Clone(stream), chunk)
		if err != nil || len(out) != len(messages) {
			t.Fatalf("split %d: %d records, %v", chunk, len(out), err)
		}
		for i := range out {
			if !bytes.Equal(out[i], messages[i]) {
				t.Fatalf("split %d: record %d changed", chunk, i)
			}
		}
	}
	tampered := bytes.Clone(stream)
	tampered[len(records[0])+100] ^= 1
	skipped := append(bytes.Clone(records[0]), records[2]...)
	repeated := append(bytes.Clone(records[0]), records[0]...)
	for name, s := range map[string][]byte{"changed": tampered, "skipped": skipped, "repeated": repeated, "cut": stream[:len(stream)-1]} {
		if _, err := open(s, 1<<20); err != errRecord {
			t.Fatalf("%s stream: %v", name, err)
		}
	}
	// Another channel of the session does not open them.
	rest := bytes.Clone(records[0])
	read := func(p []byte) (int, error) { n := copy(p, rest); rest = rest[n:]; return n, nil }
	if _, err := NewRecords(bs, 6).fill(read); err != errRecord {
		t.Fatal("another channel opened a record", err)
	}
}
