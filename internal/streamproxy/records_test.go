package streamproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
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

// A record that arrived whole in a buffer opens there, without a copy or an
// allocation; a record split between buffers opens in the window after it,
// and the bytes keep their order.
func TestRecordsOpenWholeInPlace(t *testing.T) {
	as, bs := e2eSessions(t)
	sender, receiver := NewRecords(as, 1), NewRecords(bs, 1)
	arrive := func(record []byte) *packetbuf.Buffer {
		b := packetbuf.Get(len(record))
		copy(b.Data, record)
		return b
	}
	first, second, third := []byte("whole one"), bytes.Repeat([]byte("split"), 300), []byte("whole again")
	whole := arrive(sealRecord(t, sender, first))
	opened, err := receiver.whole(whole.Data, whole)
	if err != nil || !opened || receiver.available() != len(first) {
		t.Fatal("a whole record did not open", err)
	}
	if c := receiver.chunks[0]; &c.plain[0] != &whole.Data[RecordHeader] {
		t.Fatal("a whole record opened outside its buffer")
	}
	// The second record arrives in two buffers.
	split := sealRecord(t, sender, second)
	head := arrive(split[:100])
	if opened, err := receiver.whole(head.Data, head); err != nil || opened {
		t.Fatal("part of a record opened", err)
	}
	tail := split[100:]
	read := func(p []byte) (int, error) {
		if receiver.pending != nil {
			return receiver.readPending(p), nil
		}
		n := copy(p, tail)
		tail = tail[n:]
		return n, nil
	}
	got := make([]byte, len(first))
	if receiver.read(got) != len(first) || !bytes.Equal(got, first) {
		t.Fatal("the whole record's bytes changed")
	}
	if opened, err := receiver.fill(read, -1); err != nil || !opened {
		t.Fatal("the split record did not open", err)
	}
	// The window holds bytes: a whole record waits behind them.
	last := arrive(sealRecord(t, sender, third))
	if opened, err := receiver.whole(last.Data, last); err != nil || opened {
		t.Fatal("a record opened ahead of the window", err)
	}
	got = make([]byte, len(second))
	if receiver.read(got) != len(second) || !bytes.Equal(got, second) {
		t.Fatal("the split record's bytes changed")
	}
	if opened, err := receiver.fill(read, len(third)+RecordOverhead); err != nil || !opened {
		t.Fatal("the waiting record did not open", err)
	}
	got = make([]byte, len(third))
	if receiver.read(got) != len(third) || !bytes.Equal(got, third) {
		t.Fatal("the last record's bytes changed")
	}

	plain := make([]byte, 1000)
	records := make([]*packetbuf.Buffer, 0, 200)
	for range 200 {
		records = append(records, arrive(sealRecord(t, sender, plain)))
	}
	allocs := testing.AllocsPerRun(100, func() {
		b := records[0]
		records = records[1:]
		if opened, err := receiver.whole(b.Data, b); err != nil || !opened {
			t.Fatal("a whole record did not open", err)
		}
		receiver.read(plain)
	})
	// The one allocation left is the AEAD nonce in secure.counterCipher, which
	// every Link and end-to-end message has (PROGRESS.md W3).
	if allocs > 1 {
		t.Fatalf("opening a whole record allocates %v times", allocs)
	}
}

// An end opens no more than a window of records ahead of its reader, however
// many whole records its hop holds: the rest waits there, under its window.
func TestRecordsOpenedAheadAreBounded(t *testing.T) {
	as, bs := e2eSessions(t)
	sender := NewRecords(as, 1)
	hop := &chunkHop{done: make(chan struct{})}
	plain := make([]byte, 9000)
	for range 2 * window / len(plain) {
		record := sealRecord(t, sender, plain)
		b := packetbuf.Get(len(record))
		copy(b.Data, record)
		hop.chunks = append(hop.chunks, b)
	}
	e := newEnd(context.Background(), nil, NewRecords(bs, 1))
	defer e.Abort()
	e.mu.Lock()
	e.useLocked(hop, 0, 0)
	e.mu.Unlock()
	if _, err := e.ReadWindow(); err != nil {
		t.Fatal(err)
	}
	if opened := e.records.available(); opened < window || opened > window+len(plain) {
		t.Fatalf("opened %d bytes ahead, window %d", opened, window)
	}
	if len(hop.chunks) == 0 {
		t.Fatal("every record was opened")
	}
}

// chunkHop holds received chunks as a mux stream's hop does.
type chunkHop struct {
	mu     sync.Mutex
	chunks []*packetbuf.Buffer
	done   chan struct{}
}

func (h *chunkHop) TakeChunk() ([]byte, *packetbuf.Buffer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.chunks) == 0 {
		return nil, nil, io.EOF
	}
	b := h.chunks[0]
	h.chunks = h.chunks[1:]
	return b.Data, b, nil
}

func (h *chunkHop) Buffered() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, b := range h.chunks {
		n += len(b.Data)
	}
	return n
}

func (h *chunkHop) Read(p []byte) (int, error) {
	data, owner, err := h.TakeChunk()
	if err != nil {
		return 0, err
	}
	defer owner.Release()
	return copy(p, data), nil
}

func (h *chunkHop) Write(p []byte) (int, error)         { return len(p), nil }
func (h *chunkHop) ReadFrom(r io.Reader) (int64, error) { return io.Copy(io.Discard, r) }
func (h *chunkHop) Close() error                        { return nil }
func (h *chunkHop) CloseWrite() error                   { return nil }
func (h *chunkHop) Begin(uint64)                        {}
func (h *chunkHop) DeliverLocal()                       {}
func (h *chunkHop) SetDelivered(uint64)                 {}
func (h *chunkHop) PeerDelivered() uint64               { return 0 }
func (h *chunkHop) OnDelivered(func())                  {}
func (h *chunkHop) PeerEnded() bool                     { return false }
func (h *chunkHop) Done() <-chan struct{}               { return h.done }
func (h *chunkHop) SetRetention(*Keep)                  {}
func (h *chunkHop) Leftover() []byte                    { return nil }
func (h *chunkHop) Ended() bool                         { return false }
func (h *chunkHop) Aborted() bool                       { return false }
func (h *chunkHop) Abort()                              {}
func (h *chunkHop) AbortSession()                       {}
