package streamproxy

import (
	"encoding/binary"
	"errors"
	"math"
	"sync"

	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/secure"
)

// A session between two Agents that share an end-to-end session carries its
// bytes as records sealed by its ends; relays and Links carry the records
// without opening them. A record is a 2-byte length and that many bytes of
// ciphertext, whose tag ends it. Its nonce is the session's channel and the
// record's index in its direction, so no record can be dropped, repeated or
// reordered without failing to open. The session's offsets count record
// bytes: an end resends identical ciphertext after a reroute.
const (
	RecordHeader   = 2
	RecordOverhead = RecordHeader + secure.TagSize
	// MaxRecord bounds a record's ciphertext, what its length can say.
	MaxRecord = math.MaxUint16
)

var errRecord = errors.New("TCP session record failed to open")

// Records seals one direction of a session and opens the other: both ends
// hold one for the same channel, whose session keys differ by direction.
//
// A received record that arrived whole in one buffer, as the ingress sends
// each in a frame of its own, opens in place there and joins chunks. Others
// open in place in one window buffer, each right after the plaintext before
// it, so the opened bytes are contiguous: buf[start:end], then the record
// being received. The window holds bytes only while chunks is empty, so the
// opened bytes are chunks, then the window.
type Records struct {
	session *secure.Session
	channel uint32
	// sealed counts records sealed, by the one sender of the direction.
	sealed uint32
	opened uint32
	chunks []openedChunk // from next
	next   int
	queued int // plaintext bytes in chunks
	buf    []byte
	start  int
	end    int
	// The record being received: its length and the bytes read of it.
	head  [RecordHeader]byte
	heads int
	have  int
	// pending is a received chunk that was not a whole record, waiting to be
	// read into the window once chunks are read.
	pending []byte
	owner   *packetbuf.Buffer
}

// openedChunk is a record's plaintext in the buffer it arrived in, which
// owner holds, or nil.
type openedChunk struct {
	plain []byte
	owner *packetbuf.Buffer
}

// window bounds the opened bytes held at once; records already received
// join them up to it, so the local connection takes large writes. The buffer
// returns to a pool once all it holds was read, so an idle connection keeps
// none.
const window = 512 << 10

// windows holds window buffers, with room for one more record after them.
var windows = sync.Pool{New: func() any { b := make([]byte, window+MaxRecord); return &b }}

// NewRecords returns the records of a channel of session.
func NewRecords(session *secure.Session, channel uint32) *Records {
	return &Records{session: session, channel: channel}
}

// Seal seals record in place: record holds RecordHeader spare bytes and then
// the plaintext, and has secure.TagSize bytes of spare capacity. It returns the
// sealed record.
func (r *Records) Seal(record []byte) ([]byte, error) {
	size := len(record) - RecordHeader + secure.TagSize
	if len(record) <= RecordHeader || size > MaxRecord || cap(record)-len(record) < secure.TagSize {
		return nil, errors.New("invalid TCP session record")
	}
	if r.sealed == math.MaxUint32 {
		return nil, secure.ErrRekey
	}
	binary.BigEndian.PutUint16(record, uint16(size))
	r.session.SealChannel(r.channel, r.sealed, record[RecordHeader:])
	r.sealed++
	return record[:RecordHeader+size], nil
}

// available is how many opened bytes are not yet read.
func (r *Records) available() int { return r.queued + r.end - r.start }

// plain is the opened bytes of the window not yet read.
func (r *Records) plain() []byte { return r.buf[r.start:r.end] }

// read copies opened bytes to p and drops them.
func (r *Records) read(p []byte) int {
	n := 0
	for n < len(p) && r.next < len(r.chunks) {
		c := &r.chunks[r.next]
		copied := copy(p[n:], c.plain)
		n += copied
		r.queued -= copied
		if c.plain = c.plain[copied:]; len(c.plain) == 0 {
			c.owner.Release()
			*c = openedChunk{}
			r.next++
		}
	}
	if r.next == len(r.chunks) {
		r.chunks, r.next = r.chunks[:0], 0
		copied := copy(p[n:], r.plain())
		n += copied
		r.consume(copied)
	}
	return n
}

// consume drops n opened bytes of the window, which were read.
func (r *Records) consume(n int) {
	r.start += n
	if r.start == r.end && !r.partial() {
		r.start, r.end = 0, 0
		if r.buf != nil {
			buf := r.buf
			r.buf = nil
			windows.Put(&buf)
		}
	}
}

// whole opens data, a received chunk whose owner passes to r, in place when
// it is one whole record and the window holds nothing: its plaintext joins
// chunks. Otherwise data waits to be read into the window once the opened
// bytes are read, and whole reports false.
func (r *Records) whole(data []byte, owner *packetbuf.Buffer) (bool, error) {
	if r.end > r.start || r.partial() || r.pending != nil || len(data) <= RecordOverhead || int(binary.BigEndian.Uint16(data)) != len(data)-RecordHeader {
		r.pending, r.owner = data, owner
		return false, nil
	}
	if r.opened == math.MaxUint32 {
		owner.Release()
		return false, errRecord
	}
	plain, err := r.session.OpenChannel(r.channel, r.opened, data[RecordHeader:])
	if err != nil {
		owner.Release()
		return false, errRecord
	}
	r.opened++
	r.chunks = append(r.chunks, openedChunk{plain, owner})
	r.queued += len(plain)
	return true, nil
}

// readPending reads p from the pending chunk, before the chain's next bytes.
func (r *Records) readPending(p []byte) int {
	n := copy(p, r.pending)
	if r.pending = r.pending[n:]; len(r.pending) == 0 {
		r.owner.Release()
		r.pending, r.owner = nil, nil
	}
	return n
}

// fill reads records from read and opens them. Without budget (below 0) it
// reads until one record opened; with a budget, it reads no more than that,
// which read has without waiting. It returns whether a record opened.
func (r *Records) fill(read func([]byte) (int, error), budget int) (bool, error) {
	opened := false
	take := func(p []byte) (int, error) {
		if budget >= 0 {
			p = p[:min(len(p), budget)]
			if len(p) == 0 {
				return 0, nil
			}
		}
		n, err := read(p)
		if budget >= 0 {
			budget -= n
		}
		return n, err
	}
	for {
		if budget < 0 && opened || budget == 0 || r.end-r.start >= window {
			return opened, nil
		}
		for r.heads < RecordHeader {
			n, err := take(r.head[r.heads:])
			r.heads += n
			if err != nil || n == 0 {
				return opened, err
			}
		}
		size := int(binary.BigEndian.Uint16(r.head[:]))
		if size <= secure.TagSize {
			return opened, errRecord
		}
		if r.buf == nil {
			r.buf = *windows.Get().(*[]byte)
		}
		if r.have == 0 && len(r.buf)-r.end < size {
			// Room for the record after the opened bytes, which move to the
			// front: less than window is open, and a record is at most
			// MaxRecord.
			n := copy(r.buf, r.buf[r.start:r.end])
			r.start, r.end = 0, n
		}
		body := r.buf[r.end : r.end+size]
		for r.have < size {
			n, err := take(body[r.have:])
			r.have += n
			if err != nil || n == 0 {
				return opened, err
			}
		}
		if r.opened == math.MaxUint32 {
			return opened, errRecord
		}
		plain, err := r.session.OpenChannel(r.channel, r.opened, body)
		if err != nil {
			return opened, errRecord
		}
		r.opened++
		r.end += len(plain)
		r.heads, r.have = 0, 0
		opened = true
	}
}

// partial reports a record received in part.
func (r *Records) partial() bool { return r.heads > 0 }
