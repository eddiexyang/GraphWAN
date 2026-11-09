package secure

import (
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/flynn/noise"
)

const (
	ReplayWindow = 1024
	// A fresh handshake must replace the session before either limit is reached.
	MaxMessages   = uint64(1) << 32
	MaxSessionAge = time.Hour
	// Plaintext includes a message type and, for data, a complete overlay
	// frame, which a sealed packet's envelope precedes with two more bytes.
	MaxPlaintext = packet.MaxFrame + 3
	Overhead     = 8 + 16
)

var ErrReplay = errors.New("replayed or stale encrypted packet")
var ErrRekey = errors.New("session requires a fresh handshake")

type Session struct {
	id          string
	binding     []byte
	sendAD      []byte
	receiveAD   []byte
	created     time.Time
	sendMu      sync.Mutex
	receiveMu   sync.Mutex
	send        noise.Cipher
	receive     noise.Cipher
	sequence    uint64
	highest     uint64
	seen        [ReplayWindow]uint64
	batchAD     [4][]byte
	sealAD      [2][]byte
	batchNonces [128]uint64
}

func newSession(id string, binding []byte, send, receive noise.Cipher) *Session {
	return &Session{id: id, binding: binding, sendAD: append(append([]byte{}, binding...), make([]byte, 8)...), receiveAD: append(append([]byte{}, binding...), make([]byte, 8)...), created: time.Now(), send: send, receive: receive}
}
func (s *Session) ID() string         { return s.id }
func (s *Session) Created() time.Time { return s.created }
func (s *Session) NeedsRekey() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sequence >= MaxMessages-1 || time.Since(s.created) >= MaxSessionAge
}

// Seal uses a fresh monotonic nonce even when a transport send subsequently
// fails. Nonces, keys and replay windows are never persisted or reused.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	return s.SealAppend(nil, plaintext)
}

// SealAppend appends one encrypted message to dst. The caller owns dst and must
// not overlap it with plaintext. Nonces and associated data remain session-owned.
func (s *Session) SealAppend(dst, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("invalid encrypted message size")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sequence >= MaxMessages-1 || time.Since(s.created) >= MaxSessionAge {
		return nil, ErrRekey
	}
	s.sequence++
	offset := len(dst)
	dst = append(dst, make([]byte, 8)...)
	binary.BigEndian.PutUint64(dst[offset:], s.sequence)
	copy(s.sendAD[len(s.binding):], dst[offset:])
	return s.send.Encrypt(dst, s.sequence, s.sendAD, plaintext), nil
}

// SealBatchAppend appends an independently authenticated message to each dst
// entry. Destinations (including their spare capacity) and plaintexts must not
// overlap. A batch reserves unique nonces under one lock; output order and wire
// format are identical to sequential SealAppend calls.
func (s *Session) SealBatchAppend(dst, plaintexts [][]byte) error {
	if len(plaintexts) == 0 || len(plaintexts) > 128 || len(dst) != len(plaintexts) {
		return errors.New("invalid encrypted batch size")
	}
	bytes := 0
	for _, plaintext := range plaintexts {
		if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
			return errors.New("invalid encrypted message size")
		}
		bytes += len(plaintext)
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sequence >= MaxMessages-1 || uint64(len(plaintexts)) > MaxMessages-1-s.sequence || time.Since(s.created) >= MaxSessionAge {
		return ErrRekey
	}
	first := s.sequence + 1
	s.sequence += uint64(len(plaintexts))
	seal := func(worker, start, end int) {
		if s.sealAD[worker] == nil {
			s.sealAD[worker] = make([]byte, len(s.binding)+8)
			copy(s.sealAD[worker], s.binding)
		}
		ad := s.sealAD[worker]
		for i := start; i < end; i++ {
			nonce := first + uint64(i)
			offset := len(dst[i])
			out := append(dst[i], make([]byte, 8)...)
			binary.BigEndian.PutUint64(out[offset:], nonce)
			binary.BigEndian.PutUint64(ad[len(s.binding):], nonce)
			dst[i] = s.send.Encrypt(out, nonce, ad, plaintexts[i])
		}
	}
	if len(plaintexts) >= 8 && bytes >= 32*1024 && runtime.GOMAXPROCS(0) > 1 {
		var wg sync.WaitGroup
		wg.Add(1)
		mid := len(plaintexts) / 2
		go func() { defer wg.Done(); seal(1, mid, len(plaintexts)) }()
		seal(0, 0, mid)
		wg.Wait()
	} else {
		seal(0, 0, len(plaintexts))
	}
	return nil
}

// TagSize is what SealChannel adds to a message.
const TagSize = 16

// An end-to-end session carries independent ordered channels, such as its TCP
// connections. A channel message's nonce is the channel in its high 32 bits
// and the message's index within the channel in its low 32 bits: no nonce
// travels, and a reordered, repeated or missing message fails to open.
// Channel 0 is the session's packets: Seal and SealPacket take its nonces
// from one sequence.
func channelNonce(channel, index uint32) uint64 { return uint64(channel)<<32 | uint64(index) }

// SealChannel seals plaintext in place; it needs TagSize bytes of spare
// capacity and returns the sealed message.
func (s *Session) SealChannel(channel, index uint32, plaintext []byte) []byte {
	return s.send.Encrypt(plaintext[:0], channelNonce(channel, index), s.binding, plaintext)
}

// OpenChannel opens a SealChannel message in place.
func (s *Session) OpenChannel(channel, index uint32, sealed []byte) ([]byte, error) {
	if len(sealed) < TagSize {
		return nil, errors.New("invalid channel message size")
	}
	return s.receive.Decrypt(sealed[:0], channelNonce(channel, index), s.binding, sealed)
}

// PacketSequence is the packet's sequence that SealPacket writes after the
// ciphertext: its nonce in channel 0.
const PacketSequence = 4

// SealPacket seals body in place, authenticating ad with it, and appends the
// packet's sequence, then label, then the tag; body needs
// PacketSequence+len(label)+TagSize spare capacity. label, such as the
// session's identity, travels in the clear.
func (s *Session) SealPacket(ad, body, label []byte) ([]byte, error) {
	if cap(body)-len(body) < PacketSequence+len(label)+TagSize {
		return nil, errors.New("invalid end-to-end packet")
	}
	s.sendMu.Lock()
	if s.sequence >= MaxMessages-1 || time.Since(s.created) >= MaxSessionAge {
		s.sendMu.Unlock()
		return nil, ErrRekey
	}
	s.sequence++
	nonce := s.sequence
	s.sendMu.Unlock()
	n := len(body)
	sealed := s.send.Encrypt(body[:0], nonce, ad, body)
	var tag [TagSize]byte
	copy(tag[:], sealed[n:])
	sealed = binary.BigEndian.AppendUint32(sealed[:n], uint32(nonce))
	sealed = append(sealed, label...)
	return append(sealed, tag[:]...), nil
}

// Sequence reports how many channel 0 nonces the session used.
func (s *Session) Sequence() uint64 {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sequence
}

// OpenPacket opens a SealPacket body whose label has labelSize bytes in
// place. Like Open, it accepts bounded out-of-order delivery and refuses a
// sequence it already opened.
func (s *Session) OpenPacket(ad, sealed []byte, labelSize int) ([]byte, error) {
	n := len(sealed) - PacketSequence - labelSize - TagSize
	if labelSize < 0 || n < 0 {
		return nil, errors.New("invalid end-to-end packet")
	}
	if time.Since(s.created) >= MaxSessionAge {
		return nil, ErrRekey
	}
	nonce := uint64(binary.BigEndian.Uint32(sealed[n:]))
	if nonce == 0 {
		return nil, ErrReplay
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if s.seen[nonce%ReplayWindow] == nonce || s.highest >= ReplayWindow && nonce <= s.highest-ReplayWindow {
		return nil, ErrReplay
	}
	// The tag moves next to the ciphertext, over the sequence and label.
	copy(sealed[n:], sealed[len(sealed)-TagSize:])
	plaintext, err := s.receive.Decrypt(sealed[:0], nonce, ad, sealed[:n+TagSize])
	if err != nil {
		return nil, err
	}
	s.seen[nonce%ReplayWindow] = nonce
	s.highest = max(s.highest, nonce)
	return plaintext, nil
}

// Open accepts bounded out-of-order delivery. Replay state advances only after
// authentication succeeds, so forged high nonces cannot evict valid packets.
func (s *Session) Open(frame []byte) ([]byte, error) { return s.open(nil, frame) }

// OpenInPlace consumes an exclusively owned encrypted frame. The returned
// plaintext aliases frame; it must not be used as ciphertext again.
func (s *Session) OpenInPlace(frame []byte) ([]byte, error) {
	if len(frame) <= Overhead {
		return nil, errors.New("invalid encrypted frame size")
	}
	return s.open(frame[8:8], frame)
}
func (s *Session) open(dst, frame []byte) ([]byte, error) {
	if len(frame) <= Overhead || len(frame) > MaxPlaintext+Overhead {
		return nil, errors.New("invalid encrypted frame size")
	}
	if time.Since(s.created) >= MaxSessionAge {
		return nil, ErrRekey
	}
	nonce := binary.BigEndian.Uint64(frame[:8])
	if nonce == 0 || nonce >= MaxMessages {
		return nil, ErrReplay
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if s.seen[nonce%ReplayWindow] == nonce || s.highest >= ReplayWindow && nonce <= s.highest-ReplayWindow {
		return nil, ErrReplay
	}
	copy(s.receiveAD[len(s.binding):], frame[:8])
	plaintext, err := s.receive.Decrypt(dst, nonce, s.receiveAD, frame[8:])
	if err != nil {
		return nil, err
	}
	s.seen[nonce%ReplayWindow] = nonce
	s.highest = max(s.highest, nonce)
	return plaintext, nil
}

// OpenBatchInPlace consumes distinct, exclusively owned ciphertext buffers and
// replaces successful entries with plaintext. Authentication can run in parallel,
// but replay-window commits are serialized in original receive order. A forged
// high nonce or a duplicate within the batch can never advance/evade the window.
func (s *Session) OpenBatchInPlace(frames [][]byte) []error {
	errs := make([]error, len(frames))
	if len(frames) > len(s.batchNonces) {
		for i := range errs {
			errs[i] = errors.New("encrypted batch too large")
		}
		return errs
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if time.Since(s.created) >= MaxSessionAge {
		for i := range errs {
			errs[i] = ErrRekey
		}
		return errs
	}
	bytes := 0
	for i, frame := range frames {
		if len(frame) <= Overhead || len(frame) > MaxPlaintext+Overhead {
			errs[i] = errors.New("invalid encrypted frame size")
			continue
		}
		nonce := binary.BigEndian.Uint64(frame[:8])
		s.batchNonces[i] = nonce
		if nonce == 0 || nonce >= MaxMessages || s.seen[nonce%ReplayWindow] == nonce || s.highest >= ReplayWindow && nonce <= s.highest-ReplayWindow {
			errs[i] = ErrReplay
			continue
		}
		bytes += len(frame)
	}
	decrypt := func(worker, start, end int) {
		if s.batchAD[worker] == nil {
			s.batchAD[worker] = make([]byte, len(s.binding)+8)
			copy(s.batchAD[worker], s.binding)
		}
		ad := s.batchAD[worker]
		for i := start; i < end; i++ {
			if errs[i] != nil {
				continue
			}
			frame := frames[i]
			copy(ad[len(s.binding):], frame[:8])
			frames[i], errs[i] = s.receive.Decrypt(frame[8:8], s.batchNonces[i], ad, frame[8:])
		}
	}
	// ARM64 currently uses the generic Poly1305 path. Smaller batches there
	// justify parallel workers; vectorized amd64 crypto needs a larger payload
	// to amortize scheduling. Small/control batches always stay synchronous.
	parallelBytes := 64 * 1024
	if runtime.GOARCH == "arm64" {
		parallelBytes = 8 * 1024
	}
	if len(frames) >= 8 && bytes >= parallelBytes && runtime.GOMAXPROCS(0) > 1 {
		workers := min(4, runtime.GOMAXPROCS(0), max(2, len(frames)/8))
		var next atomic.Int32
		work := func(worker int) {
			// Small chunks let faster cores take more work on heterogeneous CPUs.
			for {
				start := int(next.Add(4)) - 4
				if start >= len(frames) {
					return
				}
				decrypt(worker, start, min(start+4, len(frames)))
			}
		}
		var wg sync.WaitGroup
		for worker := 1; worker < workers; worker++ {
			wg.Add(1)
			go func() { defer wg.Done(); work(worker) }()
		}
		work(0)
		wg.Wait()
	} else {
		decrypt(0, 0, len(frames))
	}
	for i, nonce := range s.batchNonces[:len(frames)] {
		if errs[i] == nil {
			if s.seen[nonce%ReplayWindow] == nonce || s.highest >= ReplayWindow && nonce <= s.highest-ReplayWindow {
				errs[i] = ErrReplay
			} else {
				s.seen[nonce%ReplayWindow] = nonce
				s.highest = max(s.highest, nonce)
			}
		}
		if errs[i] != nil {
			frames[i] = nil
		}
	}
	return errs
}
