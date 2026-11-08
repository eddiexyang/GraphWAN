package streamproxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A resumable connection is a session between its ingress, which terminates
// the client's TCP, and its egress, which connects to the server: the only two
// Agents holding its tuple. Its bytes travel on a chain of streams along the
// current routes; relays copy them and keep no session state. Each end keeps
// what it sent until the other end delivered it (E, carried in the stream
// acknowledgements). When a route changes or a hop fails, the chain is reset
// and the ingress opens one of the next generation along the current routes,
// resending from E; the egress takes the newest generation and discards what
// it already has.
const (
	// Retention bounds what an end keeps unconfirmed; reading its socket waits
	// while it is full.
	Retention = 32 << 20
	// AgentRetention bounds what all of an Agent's ends keep together;
	// reading any of their sockets waits while it is full. Bytes already sent
	// are always kept.
	AgentRetention = 256 << 20
	// An end without a working chain this long resets the connection.
	orphanLifetime = 2 * time.Minute
	rebuildMin     = 200 * time.Millisecond
	rebuildMax     = 2 * time.Second
)

// Response statuses for a chain's request.
const (
	StatusOK = 0
	// StatusRefused: the target or next hop is unavailable.
	StatusRefused = 1
	// StatusLegacy: a hop toward the destination does not support sessions.
	StatusLegacy = 2
	// StatusUnknown: the egress has no such session.
	StatusUnknown = 3
)

var ErrLegacy = errors.New("a hop does not support resumable TCP")
var ErrUnknownSession = errors.New("egress has no such TCP session")
var errNoPath = errors.New("TCP session has no path")

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

// Hop is a stream carrying a session's chain.
type Hop interface {
	Conn
	io.ReaderFrom
	// Begin starts session accounting: send is the session offset of the next
	// byte written.
	Begin(send uint64)
	// DeliverLocal reports what this hop's reader consumed as delivered;
	// SetDelivered reports a relay's far end instead.
	DeliverLocal()
	SetDelivered(e uint64)
	// PeerDelivered is how far the far end delivered what this hop sends.
	PeerDelivered() uint64
	OnDelivered(notify func())
	// PeerEnded reports that the far end delivered all this hop sent, its end
	// included. Done is closed once the hop failed or finished.
	PeerEnded() bool
	Done() <-chan struct{}
	// SetRetention keeps every byte sent from now on in k. Leftover returns
	// what a ReadFrom read but did not send.
	SetRetention(k *Keep)
	Leftover() []byte
	// Ended reports, after io.EOF, that the direction ended; Aborted that the
	// peer reset the connection.
	Ended() bool
	Aborted() bool
	Abort()
	AbortSession()
}

// Keep holds the bytes an end sent from the other end's delivered offset.
type Keep struct {
	mu     sync.Mutex
	chunks [][]byte
	base   uint64
	end    uint64
	closed bool
	wake   chan struct{}
	budget *retained // the Agent's total, or nil
}

func NewKeep() *Keep { return &Keep{wake: make(chan struct{})} }

// Add appends data, which must not change afterwards.
func (k *Keep) Add(data []byte) {
	if len(data) == 0 {
		return
	}
	k.mu.Lock()
	if !k.closed {
		k.chunks = append(k.chunks, data)
		k.end += uint64(len(data))
		k.budget.add(len(data))
	}
	k.mu.Unlock()
}

// Wait returns once fewer than Retention bytes are kept, and the Agent's ends
// keep fewer than AgentRetention together.
func (k *Keep) Wait(ctx context.Context) error {
	for {
		k.mu.Lock()
		if k.closed {
			k.mu.Unlock()
			return nil
		}
		wake := k.wake
		own := k.end-k.base >= Retention
		k.mu.Unlock()
		shared, full := k.budget.full()
		if !own && !full {
			return nil
		}
		select {
		case <-wake:
		case <-shared:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// retained totals the bytes an Agent's ends keep.
type retained struct {
	mu    sync.Mutex
	bytes uint64
	wake  chan struct{}
}

// agentRetention is AgentRetention; tests lower it.
var agentRetention uint64 = AgentRetention

func (r *retained) add(n int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.bytes += uint64(n)
	r.mu.Unlock()
}

func (r *retained) release(n uint64) {
	if r == nil || n == 0 {
		return
	}
	r.mu.Lock()
	r.bytes -= n
	if r.wake != nil {
		close(r.wake)
		r.wake = nil
	}
	r.mu.Unlock()
}

// full reports whether the total reached agentRetention, and a channel
// closed when it next falls.
func (r *retained) full() (<-chan struct{}, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bytes < agentRetention {
		return nil, false
	}
	if r.wake == nil {
		r.wake = make(chan struct{})
	}
	return r.wake, true
}

func (r *retained) total() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytes
}

// Release drops what the other end delivered.
func (k *Keep) Release(delivered uint64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	limit := min(delivered, k.end)
	if limit <= k.base {
		return
	}
	released := limit - k.base
	for len(k.chunks) > 0 && k.base+uint64(len(k.chunks[0])) <= limit {
		k.base += uint64(len(k.chunks[0]))
		k.chunks[0] = nil
		k.chunks = k.chunks[1:]
	}
	if len(k.chunks) > 0 && limit > k.base {
		k.chunks[0] = k.chunks[0][limit-k.base:]
		k.base = limit
	}
	k.budget.release(released)
	close(k.wake)
	k.wake = make(chan struct{})
}

// from returns the kept bytes from offset on, without copying.
func (k *Keep) from(offset uint64) ([][]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if offset < k.base || offset > k.end {
		return nil, false
	}
	var out [][]byte
	position := k.base
	for _, chunk := range k.chunks {
		if offset < position+uint64(len(chunk)) {
			out = append(out, chunk[max(offset, position)-position:])
		}
		position += uint64(len(chunk))
	}
	return out, true
}

func (k *Keep) bounds() (base, end uint64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.base, k.end
}

func (k *Keep) close() {
	k.mu.Lock()
	if !k.closed {
		k.closed = true
		k.budget.release(k.end - k.base)
		k.chunks = nil
		k.base = k.end
		close(k.wake)
	}
	k.mu.Unlock()
}

// Counters totals session events for an Agent's report.
type Counters struct {
	HopFailures    atomic.Uint64 // chains an end saw fail or reset
	Rebuilds       atomic.Uint64 // chains the ingress opened after one failed
	ReplayRequests atomic.Uint64 // replay requests the egress sent
	retained       retained      // bytes the ends keep, against AgentRetention
}

// Retained reports the bytes the Agent's ends keep now.
func (c *Counters) Retained() uint64 { return c.retained.total() }

// OpenChain opens a chain of generation gen whose downstream bytes start at
// down and upstream bytes at up.
type OpenChain func(ctx context.Context, gen uint32, down, up uint64) (Hop, error)

// End is a session's ingress or egress: the connection Relay copies with the
// local one. Its writes go to the current chain and are kept until delivered;
// its reads come from the current chain, without what was already delivered.
type End struct {
	ctx       context.Context
	cancel    context.CancelFunc
	open      OpenChain        // ingress
	askReplay func(gen uint32) // egress
	counters  *Counters
	keep      *Keep

	mu       sync.Mutex
	cond     *sync.Cond
	hop      Hop
	gen      uint32
	in       uint64 // session offset where the hop's received bytes start
	inRead   uint64 // received bytes read from the hop
	read     uint64 // received bytes delivered to the local connection
	eof      bool   // the local connection ended its writes
	ended    bool   // the received direction ended
	leftover []byte
	busy     bool
	orphan   time.Time
	done     bool
	closed   bool
	err      error
}

func newEnd(parent context.Context, counters *Counters) *End {
	ctx, cancel := context.WithCancel(parent)
	e := &End{ctx: ctx, cancel: cancel, keep: NewKeep(), counters: counters}
	if counters != nil {
		e.keep.budget = &counters.retained
	}
	e.cond = sync.NewCond(&e.mu)
	go e.watchOrphan()
	return e
}

// StartIngress opens the first chain before the access connection is
// accepted, as a connected stream would be.
func StartIngress(ctx context.Context, open OpenChain, counters *Counters) (*End, error) {
	hop, err := open(ctx, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	e := newEnd(context.Background(), counters)
	e.open = open
	hop.Begin(0)
	e.mu.Lock()
	e.useLocked(hop, 0, 0)
	e.mu.Unlock()
	return e, nil
}

// NewEgress serves a session's first chain, answered already.
func NewEgress(parent context.Context, hop Hop, askReplay func(gen uint32), counters *Counters) *End {
	e := newEnd(parent, counters)
	e.askReplay = askReplay
	hop.Begin(0)
	e.mu.Lock()
	e.useLocked(hop, 0, 0)
	e.mu.Unlock()
	return e
}

// useLocked makes hop the session's chain; its received bytes start at in.
// Callers began it at its sent offset and resent the kept bytes from there.
func (e *End) useLocked(hop Hop, out, in uint64) {
	hop.DeliverLocal()
	hop.SetRetention(e.keep)
	hop.OnDelivered(func() {
		e.keep.Release(hop.PeerDelivered())
		e.mu.Lock()
		e.cond.Broadcast()
		e.mu.Unlock()
	})
	e.hop, e.in, e.inRead = hop, in, 0
	e.orphan = time.Time{}
	e.cond.Broadcast()
}

// resend begins a new chain at out and writes the kept bytes it lacks. It
// runs without the lock: the writes wait for the hop's acknowledgements.
func (e *End) resend(hop Hop, out uint64) error {
	hop.Begin(out)
	chunks, ok := e.keep.from(out)
	if !ok {
		return ErrUnknownSession
	}
	for _, chunk := range chunks {
		if _, err := hop.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

// Accept takes an egress's newer chain: its downstream bytes start at down,
// and it carries the upstream bytes from up, which this end kept.
func (e *End) Accept(hop Hop, gen uint32, down, up uint64) error {
	e.mu.Lock()
	if e.done || gen <= e.gen {
		e.mu.Unlock()
		return ErrUnknownSession
	}
	if old := e.hop; old != nil {
		old.Abort()
	}
	e.hop, e.gen = nil, gen
	if e.orphan.IsZero() {
		e.orphan = time.Now()
	}
	e.mu.Unlock()
	if err := e.resend(hop, up); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done || e.gen != gen {
		return ErrUnknownSession
	}
	e.useLocked(hop, up, down)
	if e.eof {
		hop.CloseWrite()
	}
	return nil
}

// Reroute moves the session to a chain along the current routes.
func (e *End) Reroute() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hop != nil {
		e.failLocked(e.hop)
	}
}

// RequestReplay handles the egress's report that generation gen failed.
func (e *End) RequestReplay(gen uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if gen == e.gen && e.hop != nil {
		e.failLocked(e.hop)
	}
}

// Done is closed when the session ended.
func (e *End) Done() <-chan struct{} { return e.ctx.Done() }

// Gen returns the current generation.
func (e *End) Gen() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gen
}

// failLocked drops a failed chain: the ingress builds the next one, the
// egress asks the ingress for it.
func (e *End) failLocked(hop Hop) {
	if e.done || hop != e.hop {
		return
	}
	e.counters.HopFailures.Add(1)
	hop.Abort()
	e.hop = nil
	if e.orphan.IsZero() {
		e.orphan = time.Now()
	}
	e.cond.Broadcast()
	if e.busy {
		return
	}
	e.busy = true
	if e.open != nil {
		go e.rebuild()
	} else {
		go e.waitReplay(e.gen)
	}
}

func (e *End) rebuild() {
	delay := rebuildMin
	for {
		e.mu.Lock()
		if e.done {
			e.busy = false
			e.mu.Unlock()
			return
		}
		gen := e.gen + 1
		down, _ := e.keep.bounds()
		up := e.read
		e.mu.Unlock()
		hop, err := e.open(e.ctx, gen, down, up)
		if err == nil {
			err = e.resend(hop, down)
		}
		e.mu.Lock()
		switch {
		case err == nil && !e.done:
			e.counters.Rebuilds.Add(1)
			e.gen = gen
			e.useLocked(hop, down, up)
			if e.eof {
				hop.CloseWrite()
			}
			e.busy = false
			e.mu.Unlock()
			return
		case hop != nil:
			hop.Abort()
		}
		if errors.Is(err, ErrUnknownSession) || errors.Is(err, ErrLegacy) || errors.Is(err, errNoPath) {
			e.finishLocked(err)
			e.busy = false
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		select {
		case <-e.ctx.Done():
		case <-time.After(delay):
		}
		delay = min(2*delay, rebuildMax)
	}
}

func (e *End) waitReplay(gen uint32) {
	delay := rebuildMin
	for {
		e.mu.Lock()
		waiting := !e.done && e.gen == gen && e.hop == nil
		if !waiting {
			e.busy = false
		}
		e.mu.Unlock()
		if !waiting {
			return
		}
		e.askReplay(gen)
		e.counters.ReplayRequests.Add(1)
		select {
		case <-e.ctx.Done():
		case <-time.After(delay):
		}
		delay = min(2*delay, rebuildMax)
	}
}

func (e *End) watchOrphan() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
		}
		e.mu.Lock()
		if !e.done && !e.orphan.IsZero() && time.Since(e.orphan) > orphanLifetime {
			e.finishLocked(errNoPath)
		}
		e.mu.Unlock()
	}
}

// current waits for a chain; it returns nil once the session ended.
func (e *End) current() Hop {
	e.mu.Lock()
	defer e.mu.Unlock()
	for !e.done && e.hop == nil {
		e.cond.Wait()
	}
	if e.done {
		return nil
	}
	return e.hop
}

func (e *End) errLocked() error {
	if e.err != nil {
		return e.err
	}
	return net.ErrClosed
}

func (e *End) finishLocked(err error) {
	if e.done {
		return
	}
	e.done, e.err = true, err
	if e.hop != nil && err != nil {
		e.hop.AbortSession()
	}
	e.keep.close()
	e.cond.Broadcast()
	e.cancel()
}

// ReadFrom sends the local connection's bytes on the current chain. A chain
// that fails leaves what it read but did not send for the next one.
func (e *End) ReadFrom(src io.Reader) (int64, error) {
	local := &localSource{conn: src}
	var total int64
	for {
		hop := e.current()
		if hop == nil {
			e.mu.Lock()
			defer e.mu.Unlock()
			return total, e.errLocked()
		}
		e.mu.Lock()
		leftover := e.leftover
		e.leftover = nil
		e.mu.Unlock()
		if len(leftover) > 0 {
			if _, err := hop.Write(leftover); err != nil {
				e.mu.Lock()
				e.leftover = append(leftover, e.leftover...)
				e.failLocked(hop)
				e.mu.Unlock()
				continue
			}
		}
		n, err := hop.ReadFrom(local)
		total += n
		if left := hop.Leftover(); len(left) > 0 {
			e.mu.Lock()
			e.leftover = append(e.leftover, left...)
			e.mu.Unlock()
		}
		if err == nil {
			return total, nil
		}
		if local.err != nil {
			return total, local.err
		}
		e.mu.Lock()
		e.failLocked(hop)
		e.mu.Unlock()
	}
}

func (e *End) Write(p []byte) (int, error) {
	n, err := e.ReadFrom(&onceReader{p: p})
	return int(n), err
}

// CloseWrite ends this end's direction, on every chain from now on.
func (e *End) CloseWrite() error {
	e.mu.Lock()
	e.eof = true
	hop := e.hop
	e.mu.Unlock()
	if hop != nil {
		hop.CloseWrite()
	}
	return nil
}

// input returns the current chain and how many of its next bytes this end
// already delivered.
func (e *End) input() (Hop, uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for !e.done && !e.ended && e.hop == nil {
		e.cond.Wait()
	}
	if e.ended {
		return nil, 0, io.EOF
	}
	if e.done {
		return nil, 0, e.errLocked()
	}
	skip := uint64(0)
	if position := e.in + e.inRead; e.read > position {
		skip = e.read - position
	}
	return e.hop, skip, nil
}

// ReadWindow reports bytes Read can return without waiting.
func (e *End) ReadWindow() (int, error) {
	for {
		hop, skip, err := e.input()
		if err != nil {
			return 0, err
		}
		if skip > 0 && e.discard(hop, skip) != nil {
			continue
		}
		window, ok := hop.(interface{ ReadWindow() (int, error) })
		if !ok {
			return 64 << 10, nil
		}
		n, err := window.ReadWindow()
		if err == nil {
			return n, nil
		}
		if err := e.received(hop, 0, err); err != nil {
			return 0, err
		}
	}
}

func (e *End) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		hop, skip, err := e.input()
		if err != nil {
			return 0, err
		}
		if skip > 0 && e.discard(hop, skip) != nil {
			continue
		}
		n, err := hop.Read(p)
		if err := e.received(hop, n, err); err != nil || n > 0 {
			return n, err
		}
	}
}

// discard reads bytes of a newer chain that this end already delivered.
func (e *End) discard(hop Hop, n uint64) error {
	buf := make([]byte, min(n, 64<<10))
	for n > 0 {
		read, err := hop.Read(buf[:min(n, uint64(len(buf)))])
		n -= uint64(read)
		e.mu.Lock()
		e.inRead += uint64(read)
		e.mu.Unlock()
		if err != nil {
			e.received(hop, 0, err)
			return err
		}
	}
	return nil
}

// received accounts a read from hop. It returns io.EOF when the direction
// ended and the reset when the connection was; a failed chain returns nil, so
// the caller reads the next one.
func (e *End) received(hop Hop, n int, err error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if hop == e.hop {
		e.inRead += uint64(n)
		e.read += uint64(n)
	}
	switch {
	case err == nil:
		return nil
	case err == io.EOF && hop.Ended():
		e.ended = true
		return io.EOF
	case hop.Aborted():
		e.finishLocked(errAborted)
		return errAborted
	}
	e.failLocked(hop)
	return nil
}

// Close ends the session once the other end delivered all this end sent;
// until then a failed chain is still rebuilt.
func (e *End) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()
	go func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for !e.done {
			_, end := e.keep.bounds()
			if e.eof && e.ended && e.hop != nil && e.hop.PeerDelivered() > end {
				break
			}
			e.cond.Wait()
		}
		if e.hop != nil {
			e.hop.Close()
		}
		e.finishLocked(nil)
	}()
	return nil
}

// Abort resets the connection: every chain resets it at the other end.
func (e *End) Abort() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.finishLocked(errAborted)
}

var errAborted = errors.New("TCP connection reset by peer")

// localSource reads the local connection for a hop's ReadFrom, keeping its
// error apart from the hop's.
type localSource struct {
	conn io.Reader
	err  error
}

func (l *localSource) Read(p []byte) (int, error) {
	n, err := l.conn.Read(p)
	if err != nil && err != io.EOF {
		l.err = err
	}
	return n, err
}

// ReadInto lets a stream take the access stack's bytes into its frames.
func (l *localSource) ReadInto(dst io.Writer) (int, error) {
	reader, ok := l.conn.(interface{ ReadInto(io.Writer) (int, error) })
	if !ok {
		buf := make([]byte, 64<<10)
		n, err := l.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		return n, err
	}
	n, err := reader.ReadInto(dst)
	if err != nil && err != io.EOF {
		l.err = err
	}
	return n, err
}

type onceReader struct{ p []byte }

func (r *onceReader) Read(p []byte) (int, error) {
	if len(r.p) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.p)
	r.p = r.p[n:]
	return n, nil
}

// RelayHops copies a chain between two hops at a relay, which keeps no
// session state: it passes on what the far ends delivered, and a reset of the
// connection resets it on both hops.
func RelayHops(ctx context.Context, up, down Hop) error {
	settled := make(chan struct{}, 1)
	pass := func(to, from Hop) func() {
		return func() {
			to.SetDelivered(from.PeerDelivered())
			select {
			case settled <- struct{}{}:
			default:
			}
		}
	}
	down.OnDelivered(pass(up, down))
	up.OnDelivered(pass(down, up))
	stop := context.AfterFunc(ctx, func() { up.Abort(); down.Abort() })
	defer stop()
	fail := func() {
		if up.Aborted() || down.Aborted() {
			up.AbortSession()
			down.AbortSession()
			return
		}
		up.Abort()
		down.Abort()
	}
	errs := make(chan error, 2)
	copyTo := func(dst, src Hop) {
		_, err := io.CopyBuffer(dst, src, make([]byte, 64*1024))
		if err == nil {
			err = dst.CloseWrite()
		}
		if err != nil {
			fail()
		}
		errs <- err
	}
	go copyTo(down, up)
	go copyTo(up, down)
	err := errors.Join(<-errs, <-errs)
	// The ends finish the connection once they learn that the other end
	// delivered everything; the hops carry that after both directions ended.
wait:
	for err == nil && !(up.PeerEnded() && down.PeerEnded()) {
		select {
		case <-settled:
		case <-up.Done():
			break wait
		case <-down.Done():
			break wait
		case <-ctx.Done():
			break wait
		}
	}
	up.SetDelivered(down.PeerDelivered())
	down.SetDelivered(up.PeerDelivered())
	up.Close()
	down.Close()
	return err
}
