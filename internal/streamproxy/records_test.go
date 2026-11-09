package streamproxy

import (
	"bytes"
	"errors"
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
			before := r.opened
			ok, err := r.fill(read, -1)
			if err != nil {
				return out, err
			}
			if ok && r.opened != before+1 {
				return out, errors.New("a blocking fill opened more than one record")
			}
			if ok {
				out = append(out, bytes.Clone(r.plain()))
				r.consume(len(r.plain()))
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
	if _, err := NewRecords(bs, 6).fill(read, -1); err != errRecord {
		t.Fatal("another channel opened a record", err)
	}
}

// Records already received open after one another into one window, without
// a read past what is there.
func TestRecordsOpenIntoOneWindow(t *testing.T) {
	as, bs := e2eSessions(t)
	sender, receiver := NewRecords(as, 1), NewRecords(bs, 1)
	var stream, want []byte
	for i := range 2 * window / 5000 {
		m := bytes.Repeat([]byte{byte(i)}, 5000)
		want = append(want, m...)
		stream = append(stream, sealRecord(t, sender, m)...)
	}
	read := func(p []byte) (int, error) {
		if len(stream) == 0 {
			t.Fatal("read past the records received")
		}
		n := copy(p, stream)
		stream = stream[n:]
		return n, nil
	}
	if _, err := receiver.fill(read, -1); err != nil || len(receiver.plain()) != 5000 {
		t.Fatal("first record", err)
	}
	if _, err := receiver.fill(read, len(stream)); err != nil {
		t.Fatal(err)
	}
	got := bytes.Clone(receiver.plain())
	if len(got) < window || len(got) > window+5000 || !bytes.Equal(got, want[:len(got)]) {
		t.Fatalf("window holds %d bytes", len(got))
	}
	// Reading part of the window leaves room for more records.
	receiver.consume(len(got) / 2)
	if _, err := receiver.fill(read, len(stream)); err != nil {
		t.Fatal(err)
	}
	got = append(got[:len(got)/2], receiver.plain()...)
	receiver.consume(len(receiver.plain()))
	for len(stream) > 0 {
		if _, err := receiver.fill(read, len(stream)); err != nil {
			t.Fatal(err)
		}
		got = append(got, receiver.plain()...)
		receiver.consume(len(receiver.plain()))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("records changed")
	}
}
