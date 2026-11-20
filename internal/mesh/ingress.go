package mesh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"net"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/transport"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(raw []byte) (int, error) { return c.reader.Read(raw) }

func (c *bufferedConn) UseKernelWriteBacklog() error {
	return transport.UseKernelTCPBacklog(c.Conn)
}

// ReceiveWindow reports the kernel's receive buffer of the connection.
func (c *bufferedConn) ReceiveWindow() (int, bool) {
	return transport.TCPReceiveWindow(c.Conn)
}

// Only the read side has buffered admission bytes. Gather writes can use the
// underlying connection without flattening ciphertext or bypassing its writer.
func (c *bufferedConn) WriteBuffers(parts net.Buffers) (int64, error) {
	return parts.WriteTo(c.Conn)
}

func (m *Mesh) classify(conn net.Conn) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		conn.Close()
		return
	}
	select {
	case m.sniffSlots <- struct{}{}:
	default:
		m.mu.Unlock()
		conn.Close()
		return
	}
	m.pending[conn] = true
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer func() { m.mu.Lock(); delete(m.pending, conn); m.mu.Unlock() }()
		release := sync.OnceFunc(func() { <-m.sniffSlots })
		transferred := false
		defer func() {
			if !transferred {
				conn.Close()
				release()
			}
		}()
		ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReaderSize(conn, 4096)
		first, err := reader.Peek(1)
		if err != nil {
			return
		}
		var current net.Conn = &bufferedConn{Conn: conn, reader: reader}
		switch first[0] {
		case 'H': // Mutually authenticated, multiplexed TCP hole-punch session.
			session, err := transport.NewPunchMux(ctx, current, m.identity.Public().(ed25519.PublicKey), m.tls, m.allowsTCPPunch, true)
			if err != nil {
				return
			}
			if !stop() {
				session.Close()
				return
			}
			transferred = m.installPunch(session)
			if transferred {
				release()
			} else {
				session.Close()
			}
		case 0: // A length-framed GraphNet message is bounded to 16 KiB.
			conn.SetReadDeadline(time.Time{})
			if !stop() {
				return
			}
			transferred = true
			release()
			m.accept(transport.NewStream(current), model.TCP)
		}
	}()
}
