package peer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/transport"
)

const streamData = 1
const streamEOF = 2
const streamEOFAck = 3
const streamCloseTimeout = 3 * time.Second

// Stream carries application bytes after Noise and candidate admission. Its
// records contain bytes or a write-half close, never inner TCP/IP packets.
// One reader and one writer may run concurrently. The transport owns reliability.
type Stream struct {
	channel         *Channel
	ctx             context.Context
	cancel          context.CancelFunc
	stop            func() bool
	once            sync.Once
	writeMu         sync.Mutex
	writeBuffer     []byte
	writeClosed     atomic.Bool
	readClosed      atomic.Bool
	eofAcknowledged atomic.Bool
	rx, tx          atomic.Uint64
	pending         []byte
	records         [][]byte
}

func (s *Stream) Done() <-chan struct{}  { return s.ctx.Done() }
func (s *Stream) Bytes() (rx, tx uint64) { return s.rx.Load(), s.tx.Load() }
func (s *Stream) LocalAddr() net.Addr    { return s.channel.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr   { return s.channel.RemoteAddr() }

func NewStream(parent, establishment context.Context, channel *Channel, initiator bool) (*Stream, error) {
	if reliable, ok := channel.conn.(interface {
		Reliable(context.Context, bool) (transport.Conn, error)
	}); ok {
		conn, err := reliable.Reliable(establishment, initiator)
		if err != nil {
			channel.Close()
			return nil, err
		}
		channel.conn, channel.unreliable = conn, false
	}
	if channel.unreliable {
		channel.Close()
		return nil, errors.New("byte streams require a reliable transport")
	}
	if native, ok := channel.conn.(interface{ UseKernelWriteBacklog() error }); ok {
		if err := native.UseKernelWriteBacklog(); err != nil {
			channel.Close()
			return nil, err
		}
	}
	// Byte streams retain the gather-write path measured with the native
	// kernel-backlog candidate; datagram channels use contiguous records.
	channel.byteStream = true
	ctx, cancel := context.WithCancel(parent)
	s := &Stream{channel: channel, ctx: ctx, cancel: cancel}
	s.stop = context.AfterFunc(ctx, func() { channel.Close() })
	return s, nil
}

func (s *Stream) Read(p []byte) (int, error) { return s.ReadContext(s.ctx, p) }
func (s *Stream) ReadContext(ctx context.Context, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.readClosed.Load() {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		if len(s.pending) > 0 {
			copied := copy(p[n:], s.pending)
			n += copied
			s.rx.Add(uint64(copied))
			s.pending = s.pending[copied:]
			// Consume only records already received. A partially filled read
			// returns promptly instead of waiting for more application bytes.
			if n == len(p) || len(s.pending) == 0 && len(s.records) == 0 {
				return n, nil
			}
			continue
		}
		raw, err := s.nextRecord(ctx)
		if err != nil {
			s.Close()
			return n, err
		}
		data, err := s.decodeRecord(raw)
		if err != nil {
			if err != io.EOF {
				s.Close()
			}
			return n, err
		}
		if data == nil {
			if n > 0 && len(s.records) == 0 {
				return n, nil
			}
			continue
		}
		s.pending = data
	}
	return n, nil
}

func (s *Stream) decodeRecord(raw []byte) ([]byte, error) {
	if len(raw) == 1 && raw[0] == streamEOF {
		ctx, cancel := context.WithTimeout(s.ctx, streamCloseTimeout)
		err := s.channel.Send(ctx, []byte{streamEOFAck})
		cancel()
		if err != nil {
			return nil, err
		}
		s.readClosed.Store(true)
		return nil, io.EOF
	}
	if len(raw) == 1 && raw[0] == streamEOFAck {
		if !s.writeClosed.Load() {
			return nil, errors.New("unexpected stream EOF acknowledgment")
		}
		s.eofAcknowledged.Store(true)
		return nil, nil
	}
	if len(raw) < 2 || raw[0] != streamData {
		return nil, errors.New("invalid byte stream record")
	}
	return raw[1:], nil
}

// ReadWindow waits for one data batch, then reports only bytes already decoded.
// A TCP endpoint can read exactly these bytes into its owned send storage
// without waiting to fill a buffer or consuming a directional close record.
func (s *Stream) ReadWindow() (int, error) {
	if s.readClosed.Load() {
		return 0, io.EOF
	}
	for len(s.pending) == 0 {
		raw, err := s.nextRecord(s.ctx)
		if err == nil {
			s.pending, err = s.decodeRecord(raw)
		}
		if err != nil {
			if err != io.EOF {
				s.Close()
			}
			return 0, err
		}
	}
	n := len(s.pending)
	for _, raw := range s.records {
		if len(raw) < 2 || raw[0] != streamData {
			break
		}
		n += len(raw) - 1
	}
	return n, nil
}

func (s *Stream) nextRecord(ctx context.Context) ([]byte, error) {
	if len(s.records) == 0 {
		var err error
		// No subsequent receive occurs until pending and every record from
		// this batch have been consumed, preserving transport view lifetime.
		s.records, err = s.channel.ReceiveBorrowedBatch(ctx)
		if err != nil {
			return nil, err
		}
	}
	raw := s.records[0]
	s.records[0] = nil
	s.records = s.records[1:]
	return raw, nil
}
func (s *Stream) Write(p []byte) (int, error) { return s.WriteContext(s.ctx, p) }
func (s *Stream) WriteContext(ctx context.Context, p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	n := 0
	for len(p) > 0 {
		// Batch only bytes already supplied by this Write. Each record keeps
		// its existing size, encryption and nonce; socket writes are amortized
		// without waiting for another application write or delaying an EOF.
		const maxRecords = 32
		size := min(len(p), maxRecords*(secure.MaxPlaintext-1))
		count := (size + secure.MaxPlaintext - 2) / (secure.MaxPlaintext - 1)
		if cap(s.writeBuffer) < size+count {
			s.writeBuffer = make([]byte, size+count)
		}
		var records [maxRecords][]byte
		offset, consumed := 0, 0
		for i := range count {
			length := min(size-consumed, secure.MaxPlaintext-1)
			raw := s.writeBuffer[offset : offset+length+1]
			raw[0] = streamData
			copy(raw[1:], p[consumed:consumed+length])
			records[i] = raw
			offset += length + 1
			consumed += length
		}
		if err := s.channel.SendBatch(ctx, records[:count]); err != nil {
			s.Close()
			return n, err
		}
		n += size
		s.tx.Add(uint64(size))
		p = p[size:]
	}
	return n, nil
}
func (s *Stream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed.Load() {
		return nil
	}
	s.writeClosed.Store(true)
	if err := s.channel.Send(s.ctx, []byte{streamEOF}); err != nil {
		s.Close()
		return err
	}
	return nil
}
func (s *Stream) Close() error {
	var err error
	s.once.Do(func() {
		// QUIC and gRPC connection cancellation can discard buffered writes.
		// At normal EOF, wait for proof that our entire byte direction arrived.
		if s.readClosed.Load() && s.writeClosed.Load() && !s.eofAcknowledged.Load() && s.ctx.Err() == nil {
			ctx, cancel := context.WithTimeout(s.ctx, streamCloseTimeout)
			raw, receiveErr := s.nextRecord(ctx)
			cancel()
			if receiveErr == nil && len(raw) == 1 && raw[0] == streamEOFAck {
				s.eofAcknowledged.Store(true)
			}
		}
		s.cancel()
		s.stop()
		err = s.channel.Close()
	})
	return err
}

// During setup, cancellation closes the connection even while another
// goroutine is blocked in transport I/O. Established streams use parent lifetime.
func (s *Stream) During(ctx context.Context, operation func() error) error {
	stop := context.AfterFunc(ctx, func() { s.Close() })
	err := operation()
	if !stop() && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
