package link

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
)

// pipeChannel is one end of an in-memory Channel pair that records every
// message it sends.
type pipeChannel struct {
	in, out chan []byte
	done    chan struct{}
	once    *sync.Once
	mu      sync.Mutex
	sent    [][]byte
}

func pipePair() (*pipeChannel, *pipeChannel) {
	ab, ba, done, once := make(chan []byte, 64), make(chan []byte, 64), make(chan struct{}), &sync.Once{}
	return &pipeChannel{in: ba, out: ab, done: done, once: once}, &pipeChannel{in: ab, out: ba, done: done, once: once}
}
func (c *pipeChannel) ID() string           { return "pipe" }
func (c *pipeChannel) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *pipeChannel) NeedsRekey() bool     { return false }
func (c *pipeChannel) Created() time.Time   { return time.Now() }
func (c *pipeChannel) Close() error         { c.once.Do(func() { close(c.done) }); return nil }
func (c *pipeChannel) Send(ctx context.Context, b []byte) error {
	b = bytes.Clone(b)
	c.mu.Lock()
	c.sent = append(c.sent, b)
	c.mu.Unlock()
	select {
	case c.out <- b:
		return nil
	case <-c.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *pipeChannel) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.in:
		return b, nil
	case <-c.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dataSent returns the data messages this end has sent, by kind.
func (c *pipeChannel) dataSent() (full, compact [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.sent {
		switch b[0] {
		case dataMessage:
			full = append(full, b)
		case compactDataMessage:
			compact = append(compact, b)
		}
	}
	return full, compact
}

const (
	compactNetwork = model.ID("11111111111111111111111111111111")
	compactSource  = model.ID("22222222222222222222222222222222")
	compactDest    = model.ID("33333333333333333333333333333333")
)

// compactTest rebuilds the fixed test addresses unless the payload is marked
// unroutable with a leading 0xff, and indexes the source as 1 and the
// destination as 2; routable false knows no indexes.
type compactTest struct{ unroutable bool }

var compactTestHeader = compactTest{}

func (c compactTest) Expand(header []byte, network [16]byte, hop uint8, payload []byte) bool {
	if c.unroutable || payload[0] == 0xff {
		return false
	}
	frame, _ := (packet.Packet{Header: packet.Header{Network: compactNetwork, Source: compactSource, Destination: compactDest, HopLimit: hop}, Payload: payload}).MarshalBinary()
	if [16]byte(frame[8:24]) != network {
		return false
	}
	copy(header, frame[:packet.HeaderSize])
	return true
}

func (c compactTest) Index(network, node [16]byte) (uint16, bool) {
	for i, id := range []model.ID{compactSource, compactDest} {
		if !c.unroutable && node == wire(id) && network == wire(compactNetwork) {
			return uint16(i + 1), true
		}
	}
	return 0, false
}

func (c compactTest) Node(network [16]byte, index uint16) ([16]byte, bool) {
	if c.unroutable || network != wire(compactNetwork) || index < 1 || index > 2 {
		return [16]byte{}, false
	}
	return wire([]model.ID{compactSource, compactDest}[index-1]), true
}

func wire(id model.ID) (out [16]byte) {
	frame, _ := (packet.Packet{Header: packet.Header{Network: id, Source: id, Destination: id, HopLimit: 1}, Payload: []byte{0}}).MarshalBinary()
	return [16]byte(frame[8:24])
}

func compactTestFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	frame, err := (packet.Packet{Header: packet.Header{Network: compactNetwork, Source: compactSource, Destination: compactDest, HopLimit: 9, Epoch: 7, Flow: 5, Sequence: 3}, Payload: payload}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func newCompactTestLink(t *testing.T, channel Channel, options Options) *Link {
	t.Helper()
	info := Info{NetworkID: compactNetwork, EdgeID: compactSource, PeerID: compactDest, CandidateID: "candidate", Transport: model.TCP}
	l, err := New(context.Background(), channel, info, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func receiveFrame(t *testing.T, l *Link) []byte {
	t.Helper()
	select {
	case frame := <-l.Packets():
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("frame not delivered")
		return nil
	}
}

// Rebuilt frames keep every routing field; Epoch, Flow and Sequence, which
// receivers ignore, are zero.
func wantRebuilt(sent []byte) []byte {
	want := bytes.Clone(sent)
	clear(want[56:packet.HeaderSize])
	return want
}

func TestCompactFraming(t *testing.T) {
	payload := []byte{0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	frame := compactTestFrame(t, payload)

	t.Run("both", func(t *testing.T) {
		dialerEnd, acceptorEnd := pipePair()
		dialer := newCompactTestLink(t, dialerEnd, Options{Compact: compactTestHeader})
		acceptor := newCompactTestLink(t, acceptorEnd, Options{Compact: compactTestHeader})
		if err := acceptor.Send(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		if got := receiveFrame(t, dialer); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("dialer received %x", got)
		}
		if err := dialer.Send(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		if got := receiveFrame(t, acceptor); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("acceptor received %x", got)
		}
		for name, end := range map[string]*pipeChannel{"dialer": dialerEnd, "acceptor": acceptorEnd} {
			full, compact := end.dataSent()
			if len(full) != 0 || len(compact) != 1 || !bytes.Equal(compact[0], append([]byte{compactDataMessage, 9}, payload...)) {
				t.Fatalf("%s sent full=%x compact=%x", name, full, compact)
			}
		}
		if dialer.tx.Load() != uint64(len(frame)) || acceptor.rx.Load() != uint64(len(frame)) {
			t.Fatal("compact frames not counted as their full size")
		}
	})

	t.Run("unroutable", func(t *testing.T) {
		local, remote := pipePair()
		l := newCompactTestLink(t, local, Options{Compact: compactTestHeader})
		remote.Send(context.Background(), append([]byte{compactDataMessage, 9, 0xff}, payload...))
		remote.Send(context.Background(), append([]byte{compactDataMessage, 9}, payload...))
		if got := receiveFrame(t, l); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("received %x", got)
		}
		if l.dropped.Load() != 1 {
			t.Fatalf("dropped = %d", l.dropped.Load())
		}
	})
}

// Owned frames from the router are compacted in place, without a copy.
func TestCompactOwnedFramesInPlace(t *testing.T) {
	l := &Link{ctx: context.Background(), info: Info{Transport: model.UDP}, dataReady: make(chan struct{}, 1)}
	l.dataGeneration.Store(1)
	l.options.Compact = compactTestHeader
	payload := []byte{0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	frame := compactTestFrame(t, payload)
	headroom := packetbuf.GetHeadroom(len(frame), 1)
	copy(headroom.Data, frame)
	plain := packetbuf.Wrap(bytes.Clone(frame))
	storage := []*byte{&headroom.Data[packet.HeaderSize], &plain.Data[packet.HeaderSize]}
	if err := l.SendOwnedBatch(context.Background(), []*packetbuf.Buffer{headroom, plain}); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{compactDataMessage, 9}, payload...)
	for i := range 2 {
		queued := l.takeData()
		if !bytes.Equal(queued.raw, want) || &queued.raw[2] != storage[i] {
			t.Fatalf("frame %d queued as %x", i, queued.raw)
		}
		queued.buffer.Release()
	}
	if l.dataBytes != 0 {
		t.Fatal("compact frames leaked byte budget")
	}
}

// A TCP-backed Link counts the TCP packets it is given, which access TCP
// termination must keep at zero; other packets and datagram Links are not
// counted.
func TestTCPBackedLinkRefusesTCPPackets(t *testing.T) {
	tcp := make([]byte, 20)
	tcp[0], tcp[9] = 0x45, 6
	udp := bytes.Clone(tcp)
	udp[9] = 17
	for transport, want := range map[model.Transport]uint64{model.TCP: 1, model.UDP: 0} {
		l := &Link{ctx: context.Background(), info: Info{Transport: transport}, dataReady: make(chan struct{}, 1)}
		l.dataGeneration.Store(1)
		err := l.SendBatch(context.Background(), [][]byte{compactTestFrame(t, tcp), compactTestFrame(t, udp)})
		if want == 1 && !errors.Is(err, ErrTCPOverTCP) || want == 0 && err != nil {
			t.Fatalf("%s Link: %v", transport, err)
		}
		if got := l.tcpPackets.Load(); got != want {
			t.Fatalf("%s Link refused %d TCP packets, want %d", transport, got, want)
		}
		if queued := uint64(l.dataCount); queued != 2-want {
			t.Fatalf("%s Link queued %d packets", transport, queued)
		}
	}
}

// A sealed packet's frame travels masked, owned or copied, with its Nodes as
// their indexes, which no inner address implies. One whose Nodes have no index
// is dropped, as is a masked message that does not parse, without closing the
// Link.
func TestSealedFrames(t *testing.T) {
	ip := packet.UDP(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:2"), []byte("sealed payload"))
	frame := compactTestFrame(t, append(ip, bytes.Repeat([]byte{7}, packet.Trailer)...))
	packet.SetSealed(frame, true)
	dialerEnd, acceptorEnd := pipePair()
	dialer := newCompactTestLink(t, dialerEnd, Options{Compact: compactTestHeader})
	acceptor := newCompactTestLink(t, acceptorEnd, Options{Compact: compactTestHeader})
	owned := packetbuf.GetHeadroom(len(frame), 3)
	copy(owned.Data, frame)
	if err := acceptor.SendOwnedBatch(context.Background(), []*packetbuf.Buffer{owned}); err != nil {
		t.Fatal(err)
	}
	if err := acceptor.Send(context.Background(), frame); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got := receiveFrame(t, dialer); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("received %x", got)
		}
	}
	acceptorEnd.mu.Lock()
	masked := 0
	for _, m := range acceptorEnd.sent {
		if m[0] < 0x80 {
			continue
		}
		masked++
		if m[0] != 0x80|9 || !bytes.Equal(m[1:maskedHeader], []byte{0, 1, 0, 2}) || !bytes.Equal(m[maskedHeader:], frame[packet.HeaderSize:]) {
			t.Fatalf("masked frame %x", m[:maskedHeader])
		}
	}
	acceptorEnd.mu.Unlock()
	if masked != 2 {
		t.Fatalf("%d masked frames", masked)
	}

	unknown := newCompactTestLink(t, acceptorEnd, Options{Compact: compactTest{unroutable: true}})
	if err := unknown.Send(context.Background(), frame); err != nil {
		t.Fatal(err)
	}
	if unknown.dropped.Load() != 1 {
		t.Fatal("frame without indexes was not dropped")
	}

	local, remote := pipePair()
	l := newCompactTestLink(t, local, Options{Compact: compactTestHeader})
	good := append([]byte{0x80 | 9, 0, 1, 0, 2}, frame[packet.HeaderSize:]...)
	for _, bad := range [][]byte{{0x80 | 9}, append([]byte{0x80, 0, 1, 0, 2}, frame[packet.HeaderSize:]...), append([]byte{0x80 | 9, 0, 3, 0, 2}, frame[packet.HeaderSize:]...)} {
		remote.Send(context.Background(), bad)
	}
	remote.Send(context.Background(), good)
	if got := receiveFrame(t, l); !bytes.Equal(got, wantRebuilt(frame)) {
		t.Fatalf("received %x", got)
	}
	if l.dropped.Load() != 3 {
		t.Fatalf("dropped = %d", l.dropped.Load())
	}
}
