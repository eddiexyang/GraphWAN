package streamproxy

import (
	"encoding/binary"
	"errors"
	"math"

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
type Records struct {
	session *secure.Session
	channel uint32
	// sealed counts records sealed, by the one sender of the direction.
	sealed uint32
	// The record being received: its length and the bytes read of it.
	opened uint32
	head   [RecordHeader]byte
	heads  int
	body   []byte
	have   int
	plain  []byte // opened bytes not yet read
}

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

// fill reads the record in progress from read into the record's own buffer.
// It returns true once a record is open in r.plain.
func (r *Records) fill(read func([]byte) (int, error)) (bool, error) {
	for r.heads < RecordHeader {
		n, err := read(r.head[r.heads:])
		r.heads += n
		if err != nil || n == 0 {
			return false, err
		}
	}
	size := int(binary.BigEndian.Uint16(r.head[:]))
	if size <= secure.TagSize {
		return false, errRecord
	}
	if cap(r.body) < size {
		r.body = make([]byte, size)
	}
	r.body = r.body[:size]
	for r.have < size {
		n, err := read(r.body[r.have:])
		r.have += n
		if err != nil || n == 0 {
			return false, err
		}
	}
	if r.opened == math.MaxUint32 {
		return false, errRecord
	}
	plain, err := r.session.OpenChannel(r.channel, r.opened, r.body)
	if err != nil {
		return false, errRecord
	}
	r.opened++
	r.plain, r.heads, r.have = plain, 0, 0
	return true, nil
}

// partial reports a record received in part.
func (r *Records) partial() bool { return r.heads > 0 }
