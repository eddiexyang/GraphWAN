package streamproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

const (
	// Retention bounds the bytes an end keeps until the other end confirms
	// them; reading the local socket stops while it is full.
	Retention = 32 << 20
	// A delivered offset is reported after this many bytes, or reportDelay
	// after progress that has not reached it.
	reportEvery = 256 << 10
	reportDelay = 20 * time.Millisecond
	// An end without any working chain this long gives the connection up.
	orphanLifetime = 2 * time.Minute
	// After the connection ends, a chain's other direction is awaited this long.
	chainLinger = 30 * time.Second
	readChunk   = 64 << 10
)

// chain is one path of a session. Its write half carries the direction this
// end sends while writing; its read half the direction it receives, from rpos.
type chain struct {
	epoch      uint32
	next       model.ID
	hop        Conn
	out        recordWriter
	wpos       uint64
	rpos       uint64
	writing    bool
	superseded bool
	finSent    bool
	reported   uint64
	readDone   bool
	writeDone  bool
	failed     bool
	closed     chan struct{} // closed when the chain is released
}

// endpoint is what an ingress and an egress share: the bytes it sends, kept
// from the other end's delivered offset, and the bytes it receives, merged in
// order from every chain.
type endpoint struct {
	ctx    context.Context
	cancel context.CancelFunc
	local  Conn

	mu   sync.Mutex
	cond *sync.Cond

	// Sent direction: chunks hold [base, end).
	chunks [][]byte
	base   uint64
	end    uint64
	eof    bool   // the local read side ended at end
	acked  uint64 // delivered by the other end, end+1 once it has the fin

	// Received direction, merged at next. deliverMu orders local writes.
	deliverMu sync.Mutex
	next      uint64
	finAt     uint64
	finSeen   bool
	finDone   bool

	chains      []*chain
	reportTimer *time.Timer
	reportFlag  bool
	orphan      time.Time
	done        bool
	err         error
	abortPeer   bool // the writing chain carries an abort record

	onChainFailed func(*chain) // called with mu held
	onNotify      func(*chain)
	wg            sync.WaitGroup
	finished      chan struct{}
}

func newEndpoint(parent context.Context, local Conn) *endpoint {
	ctx, cancel := context.WithCancel(parent)
	// The orphan clock runs until the first chain arrives.
	e := &endpoint{ctx: ctx, cancel: cancel, local: local, finished: make(chan struct{}), orphan: time.Now()}
	e.cond = sync.NewCond(&e.mu)
	context.AfterFunc(ctx, func() {
		e.mu.Lock()
		e.failLocked(ctx.Err(), false)
		e.mu.Unlock()
	})
	return e
}

// run serves the connection until it finishes, then waits for its chains.
func (e *endpoint) run() error {
	e.wg.Add(2)
	go e.readLocal()
	go e.watchOrphan()
	<-e.finished
	e.cancel()
	e.wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

func (e *endpoint) readLocal() {
	defer e.wg.Done()
	var buf []byte
	for {
		e.mu.Lock()
		for !e.done && e.end-e.base >= Retention {
			e.cond.Wait()
		}
		if e.done {
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		if buf == nil {
			buf = make([]byte, readChunk)
		}
		n, err := e.local.Read(buf)
		e.mu.Lock()
		if n > 0 && !e.done {
			// Retained bytes hold their storage until acknowledged: a small
			// read gets its own, and the read buffer is reused.
			chunk := buf[:n:n]
			if n < readChunk/4 {
				chunk = append([]byte(nil), buf[:n]...)
			} else {
				buf = nil
			}
			e.chunks = append(e.chunks, chunk)
			e.end += uint64(n)
			e.cond.Broadcast()
		}
		switch {
		case err == io.EOF:
			if !e.done {
				e.eof = true
				e.cond.Broadcast()
			}
			e.mu.Unlock()
			return
		case err != nil:
			e.failLocked(err, true)
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
	}
}

func (e *endpoint) watchOrphan() {
	defer e.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.finished:
			return
		case <-ticker.C:
		}
		e.mu.Lock()
		if !e.orphan.IsZero() && time.Since(e.orphan) > orphanLifetime {
			e.failLocked(errors.New("TCP session has no path"), false)
		}
		e.mu.Unlock()
	}
}

// addChainLocked serves a new chain. A writing chain takes over this end's
// direction from every older one, which closes its write half.
func (e *endpoint) addChainLocked(c *chain) {
	c.out.hop = c.hop
	c.closed = make(chan struct{})
	if c.writing {
		for _, old := range e.chains {
			if old.writing {
				old.superseded = true
			}
		}
	}
	e.chains = append(e.chains, c)
	e.orphan = time.Time{}
	e.cond.Broadcast()
	e.wg.Add(2)
	go e.write(c)
	go e.read(c)
}

func (e *endpoint) deliveredLocked() uint64 {
	if e.finDone {
		return e.next + 1
	}
	return e.next
}

func (e *endpoint) reportDueLocked(c *chain) bool {
	delivered := e.deliveredLocked()
	return delivered > c.reported && (e.finDone || e.reportFlag || delivered-c.reported >= reportEvery)
}

func (e *endpoint) scheduleReportLocked() {
	if e.reportTimer != nil || e.done {
		return
	}
	e.reportTimer = time.AfterFunc(reportDelay, func() {
		e.mu.Lock()
		e.reportTimer = nil
		e.reportFlag = true
		e.cond.Broadcast()
		e.mu.Unlock()
	})
}

func (e *endpoint) write(c *chain) {
	defer e.wg.Done()
	for {
		e.mu.Lock()
		for !c.failed && !e.done && c.writing && !c.superseded &&
			c.wpos >= e.end && !(e.eof && !c.finSent) && !e.reportDueLocked(c) {
			e.cond.Wait()
		}
		if c.failed {
			e.mu.Unlock()
			return
		}
		if e.done || !c.writing || c.superseded {
			// The last report, or the abort, precedes the closed write half.
			var final func() error
			switch {
			case e.abortPeer && c.writing && !c.superseded:
				final = func() error { return c.out.write(recordAbort, nil) }
			case c.writing && e.deliveredLocked() > c.reported:
				delivered := e.deliveredLocked()
				final = func() error { return writeOffset(&c.out, recordReport, delivered) }
			}
			e.mu.Unlock()
			if final != nil {
				final()
			}
			c.hop.CloseWrite()
			e.mu.Lock()
			c.writeDone = true
			e.closeChainLocked(c)
			e.mu.Unlock()
			return
		}
		var report uint64
		if e.reportDueLocked(c) {
			report = e.deliveredLocked()
			e.reportFlag = false
		}
		start := max(c.wpos, e.base)
		data := e.sliceLocked(start, maxData)
		fin := e.eof && !c.finSent && start+uint64(len(data)) == e.end
		end := e.end
		e.mu.Unlock()
		var err error
		if report != 0 {
			err = writeOffset(&c.out, recordReport, report)
		}
		if err == nil && len(data) > 0 {
			err = c.out.writeData(start, data)
		}
		if err == nil && fin {
			err = writeOffset(&c.out, recordFin, end)
		}
		e.mu.Lock()
		if err != nil {
			e.chainFailedLocked(c)
			e.mu.Unlock()
			return
		}
		c.reported = max(c.reported, report)
		c.wpos = start + uint64(len(data))
		c.finSent = c.finSent || fin
		e.mu.Unlock()
	}
}

// sliceLocked returns retained bytes from offset, at least base, up to limit,
// without copying.
func (e *endpoint) sliceLocked(offset uint64, limit int) []byte {
	position := e.base
	for _, chunk := range e.chunks {
		if offset < position+uint64(len(chunk)) {
			data := chunk[offset-position:]
			return data[:min(len(data), limit)]
		}
		position += uint64(len(chunk))
	}
	return nil
}

func (e *endpoint) read(c *chain) {
	defer e.wg.Done()
	// However reading stops, the chain is released: its read half ended, it
	// failed, or the connection ended without needing it.
	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		switch {
		case c.readDone || c.failed:
		case e.done:
			c.readDone = true
			c.hop.Close()
			e.closeChainLocked(c)
		default:
			e.chainFailedLocked(c)
		}
	}()
	buf := make([]byte, maxRecord)
	for {
		kind, payload, err := readRecord(c.hop, buf)
		if err != nil {
			if err == io.EOF {
				e.mu.Lock()
				c.readDone = true
				e.closeChainLocked(c)
				e.mu.Unlock()
			}
			return
		}
		switch kind {
		case recordData:
			if err := e.deliver(c, binary.BigEndian.Uint64(payload), payload[8:]); err != nil {
				return
			}
		case recordFin:
			e.mu.Lock()
			if !e.finSeen {
				e.finSeen, e.finAt = true, binary.BigEndian.Uint64(payload)
			}
			e.mu.Unlock()
			e.deliverMu.Lock()
			e.mu.Lock()
			e.deliverFinLocked()
			e.mu.Unlock()
			e.deliverMu.Unlock()
		case recordReport:
			e.mu.Lock()
			if acked := binary.BigEndian.Uint64(payload); acked > e.acked && acked <= e.end+1 {
				e.acked = acked
				e.releaseLocked()
				e.checkDoneLocked()
				e.cond.Broadcast()
			}
			e.mu.Unlock()
		case recordAbort:
			e.mu.Lock()
			e.failLocked(errAborted, false)
			e.mu.Unlock()
		case recordNotify:
			if e.onNotify != nil {
				e.onNotify(c)
			}
		}
	}
}

// deliver writes the part of a chain's data the local socket does not have.
// A chain ahead of the merged offset waits for another to fill the gap, which
// holds back that chain's hop.
func (e *endpoint) deliver(c *chain, start uint64, data []byte) error {
	e.mu.Lock()
	c.rpos = start + uint64(len(data))
	for !e.done && start > e.next {
		e.cond.Wait()
	}
	e.mu.Unlock()
	e.deliverMu.Lock()
	defer e.deliverMu.Unlock()
	e.mu.Lock()
	if e.done {
		e.mu.Unlock()
		return context.Canceled
	}
	if start+uint64(len(data)) <= e.next {
		e.mu.Unlock()
		return nil
	}
	data = data[e.next-start:]
	e.mu.Unlock()
	_, err := e.local.Write(data)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.failLocked(err, true)
		return err
	}
	e.next += uint64(len(data))
	e.scheduleReportLocked()
	e.cond.Broadcast()
	e.deliverFinLocked()
	return nil
}

// deliverFinLocked closes the local write side once the merged stream reaches
// the fin. Callers hold deliverMu, so no data write is in progress.
func (e *endpoint) deliverFinLocked() {
	if e.done || !e.finSeen || e.finDone || e.next != e.finAt {
		return
	}
	e.finDone = true
	if err := e.local.CloseWrite(); err != nil {
		e.failLocked(err, true)
		return
	}
	e.cond.Broadcast()
	e.checkDoneLocked()
}

func (e *endpoint) releaseLocked() {
	limit := min(e.acked, e.end)
	for len(e.chunks) > 0 && e.base+uint64(len(e.chunks[0])) <= limit {
		e.base += uint64(len(e.chunks[0]))
		e.chunks[0] = nil
		e.chunks = e.chunks[1:]
	}
	if len(e.chunks) > 0 && limit > e.base {
		e.chunks[0] = e.chunks[0][limit-e.base:]
		e.base = limit
	}
}

// checkDoneLocked finishes the connection when the other end delivered this
// end's fin and this end delivered the other's.
func (e *endpoint) checkDoneLocked() {
	if !e.done && e.eof && e.acked == e.end+1 && e.finDone {
		e.finishLocked(nil)
	}
}

// failLocked resets the local connection. abortPeer also resets the other end.
func (e *endpoint) failLocked(err error, abortPeer bool) {
	if e.done {
		return
	}
	e.abortPeer = abortPeer
	if a, ok := e.local.(interface{ Abort() }); ok {
		a.Abort()
	}
	e.finishLocked(err)
}

func (e *endpoint) finishLocked(err error) {
	e.done, e.err = true, err
	e.local.Close()
	if e.reportTimer != nil {
		e.reportTimer.Stop()
		e.reportTimer = nil
	}
	e.cond.Broadcast()
	// Writers send their last record and close their write halves. Readers end
	// when the other end closes its own, or when the hop closes after a linger.
	for _, c := range e.chains {
		hop := c.hop
		time.AfterFunc(chainLinger, func() { hop.Close() })
	}
	e.closeFinishedLocked()
}

func (e *endpoint) closeChainLocked(c *chain) {
	if c.readDone && c.writeDone {
		c.hop.Close()
		e.removeChainLocked(c)
	}
}

func (e *endpoint) removeChainLocked(c *chain) {
	for i, other := range e.chains {
		if other == c {
			e.chains = append(e.chains[:i], e.chains[i+1:]...)
			close(c.closed)
			break
		}
	}
	if !e.done && e.orphan.IsZero() && e.writingLocked() == nil {
		e.orphan = time.Now()
	}
	e.closeFinishedLocked()
}

// writingLocked returns the chain carrying this end's direction.
func (e *endpoint) writingLocked() *chain {
	for _, c := range e.chains {
		if c.writing && !c.superseded && !c.failed {
			return c
		}
	}
	return nil
}

func (e *endpoint) chainFailedLocked(c *chain) {
	if c.failed {
		return
	}
	c.failed = true
	if a, ok := c.hop.(interface{ Abort() }); ok {
		a.Abort()
	}
	c.hop.Close()
	c.readDone, c.writeDone = true, true
	e.cond.Broadcast()
	e.removeChainLocked(c)
	if !e.done && e.onChainFailed != nil {
		e.onChainFailed(c)
	}
}

func (e *endpoint) closeFinishedLocked() {
	if !e.done || len(e.chains) > 0 {
		return
	}
	select {
	case <-e.finished:
	default:
		close(e.finished)
	}
}
