package peer

import (
	"io"

	"github.com/eWloYW8/GraphWAN/internal/secure"
)

type streamWriterOnly struct{ io.Writer }

// recordBuilder lays out existing records directly as the access endpoint
// releases bytes. It never performs network I/O while the endpoint is locked.
type recordBuilder struct {
	buffer  []byte
	records [32][]byte
	count   int
	offset  int
	bytes   int
	limit   int
}

func (b *recordBuilder) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 && b.bytes < b.limit {
		if b.count == 0 || len(b.records[b.count-1]) == secure.MaxPlaintext {
			b.buffer[b.offset] = streamData
			b.records[b.count] = b.buffer[b.offset : b.offset+1]
			b.count++
			b.offset++
		}
		frame := b.records[b.count-1]
		length := min(len(data), b.limit-b.bytes, secure.MaxPlaintext-len(frame))
		copy(b.buffer[b.offset:b.offset+length], data[:length])
		b.records[b.count-1] = frame[:len(frame)+length]
		b.offset += length
		b.bytes += length
		written += length
		data = data[length:]
	}
	if len(data) > 0 {
		return written, io.ErrShortWrite
	}
	return written, nil
}

// ReadFrom bypasses the relay's intermediate slice when the access endpoint
// can deliver to an immediate writer. Framing, encryption and EOF stay on the
// same stream implementation; other readers retain the ordinary copy path.
func (s *Stream) ReadFrom(src io.Reader) (int64, error) {
	reader, ok := src.(interface{ ReadInto(io.Writer) (int, error) })
	if !ok {
		return io.CopyBuffer(streamWriterOnly{s}, src, make([]byte, 64*1024))
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	limit := min(64*1024, 32*(secure.MaxPlaintext-1))
	if cap(s.writeBuffer) < limit+32 {
		s.writeBuffer = make([]byte, limit+32)
	}
	var total int64
	builder := recordBuilder{buffer: s.writeBuffer[:limit+32], limit: limit}
	for {
		clear(builder.records[:builder.count])
		builder.count, builder.offset, builder.bytes = 0, 0, 0
		n, readErr := reader.ReadInto(&builder)
		if n > 0 {
			if err := s.channel.SendBatch(s.ctx, builder.records[:builder.count]); err != nil {
				s.Close()
				return total, err
			}
			total += int64(n)
			s.tx.Add(uint64(n))
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
}
