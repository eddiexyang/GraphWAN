package transport

import (
	"context"
	"net"
	"sync"

	quic "github.com/quic-go/quic-go"
)

// Reliable switches a dedicated QUIC connection from the datagram handshake
// carrier to one bidirectional stream. Noise records still protect every byte.
func (q *QUIC) Reliable(ctx context.Context, initiator bool) (Conn, error) {
	var stream *quic.Stream
	var err error
	if initiator {
		stream, err = q.conn.OpenStreamSync(ctx)
	} else {
		stream, err = q.conn.AcceptStream(ctx)
	}
	if err != nil {
		return nil, err
	}
	return NewStream(&quicStreamConn{Stream: stream, owner: q}), nil
}

type quicStreamConn struct {
	*quic.Stream
	owner *QUIC
	once  sync.Once
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.owner.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.owner.RemoteAddr() }
func (c *quicStreamConn) Close() error {
	c.once.Do(func() { c.CancelRead(0); c.CancelWrite(0); c.owner.Close() })
	return nil
}
