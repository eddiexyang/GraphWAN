package streamproxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// A resumable connection is a session between its ingress, which terminates the
// client's TCP, and its egress, which connects to the server. The bytes travel
// on a chain of hops through the graph; each hop keeps its own loss recovery and
// flow control. When a route changes or a hop fails, the ingress builds a new
// chain along the current routes and both ends resume on it from the other
// end's delivered offset, keeping the bytes the other end has not confirmed.
//
// Each direction of a chain is a sequence of records. A hop's write half closes
// when the chain stops carrying that direction, which is not the end of the
// session's byte stream: that is a fin record.
const (
	recordData   = 1 // 8-byte offset, then the bytes at that offset
	recordFin    = 2 // 8 bytes: the offset where the direction ends
	recordReport = 3 // 8 bytes: delivered offset of the opposite direction
	recordAbort  = 4 // the connection was reset
	recordNotify = 5 // toward the ingress: a hop's route changed

	recordHeader = 3
	maxRecord    = 64<<10 - 1
	maxData      = maxRecord - 8
)

// Response statuses for a chain's request.
const (
	StatusOK = 0
	// StatusRefused: the target or next hop is unavailable.
	StatusRefused = 1
	// StatusLegacy: a hop toward the destination does not support sessions.
	// The ingress opens the connection without one.
	StatusLegacy = 2
	// StatusUnknown: the egress has no such session.
	StatusUnknown = 3
)

var ErrLegacy = errors.New("a hop does not support resumable TCP")
var ErrUnknownSession = errors.New("egress has no such TCP session")
var errAborted = errors.New("TCP connection reset by peer")

type SessionID [16]byte

func NewSessionID() SessionID {
	var id SessionID
	rand.Read(id[:])
	return id
}

func (id SessionID) MarshalText() ([]byte, error) {
	return []byte(base64.RawURLEncoding.EncodeToString(id[:])), nil
}

func (id *SessionID) UnmarshalText(text []byte) error {
	raw, err := base64.RawURLEncoding.DecodeString(string(text))
	if err != nil || len(raw) != len(id) {
		return errors.New("invalid TCP session ID")
	}
	copy(id[:], raw)
	return nil
}

// ResponseError maps a chain response status to an error.
func ResponseError(status byte) error {
	switch status {
	case StatusOK:
		return nil
	case StatusLegacy:
		return ErrLegacy
	case StatusUnknown:
		return ErrUnknownSession
	default:
		return errors.New("TCP stream target refused")
	}
}

// Records carry their offsets, so a direction can start anywhere the other end
// still needs: a chain resumes where bytes are retained, not where it was asked.

// recordWriter serializes records from several goroutines onto one hop. The
// header and payload are separate writes, so a payload is not copied here.
type recordWriter struct {
	mu  sync.Mutex
	hop Conn
}

func (w *recordWriter) write(kind byte, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeRecord(w.hop, kind, payload)
}

func writeRecord(w io.Writer, kind byte, payload []byte) error {
	var header [recordHeader]byte
	header[0] = kind
	binary.BigEndian.PutUint16(header[1:], uint16(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeOffset(w *recordWriter, kind byte, offset uint64) error {
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], offset)
	return w.write(kind, payload[:])
}

// writeData writes data at offset as one record.
func (w *recordWriter) writeData(offset uint64, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var header [recordHeader + 8]byte
	header[0] = recordData
	binary.BigEndian.PutUint16(header[1:3], uint16(8+len(data)))
	binary.BigEndian.PutUint64(header[3:], offset)
	if err := writeAll(w.hop, header[:]); err != nil {
		return err
	}
	return writeAll(w.hop, data)
}

// readRecord reads one record into buf, which holds maxRecord bytes. io.EOF
// reports the chain's direction ended between records.
func readRecord(r io.Reader, buf []byte) (byte, []byte, error) {
	var header [recordHeader]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			err = errors.New("truncated TCP session record")
		}
		return 0, nil, err
	}
	size := int(binary.BigEndian.Uint16(header[1:]))
	payload := buf[:size]
	if _, err := io.ReadFull(r, payload); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = errors.New("truncated TCP session record")
		}
		return 0, nil, err
	}
	kind := header[0]
	switch {
	case kind == recordData && size > 8,
		(kind == recordAbort || kind == recordNotify) && size == 0,
		(kind == recordReport || kind == recordFin) && size == 8:
		return kind, payload, nil
	}
	return 0, nil, fmt.Errorf("invalid TCP session record %d of %d bytes", kind, size)
}
