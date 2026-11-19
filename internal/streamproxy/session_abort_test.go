package streamproxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
)

type abortTestHop struct {
	chunkHop
	peerAborted bool
	finished    chan bool
	done        chan struct{}
	once        sync.Once
}

func newAbortTestHop(peerAborted bool) *abortTestHop {
	return &abortTestHop{
		peerAborted: peerAborted,
		finished:    make(chan bool, 1),
		done:        make(chan struct{}),
	}
}

func (h *abortTestHop) Done() <-chan struct{} { return h.done }
func (h *abortTestHop) Aborted() bool         { return h.peerAborted }
func (h *abortTestHop) Abort()                { h.stop(false) }
func (h *abortTestHop) AbortSession()         { h.stop(true) }
func (h *abortTestHop) stop(reset bool) {
	h.once.Do(func() {
		h.finished <- reset
		close(h.done)
	})
}
func (h *abortTestHop) ReadFrom(io.Reader) (int64, error) {
	return 0, io.ErrClosedPipe
}

func TestReadFromEndsOnPeerSessionReset(t *testing.T) {
	counters := &Counters{}
	hop := newAbortTestHop(true)
	replayed := make(chan struct{}, 1)
	e := NewEgress(t.Context(), hop, func(uint32) {
		select {
		case replayed <- struct{}{}:
		default:
		}
	}, counters, nil)
	defer e.Abort()

	_, err := e.ReadFrom(&onceReader{p: []byte("payload")})
	if !errors.Is(err, errAborted) {
		t.Fatalf("ReadFrom error = %v, want %v", err, errAborted)
	}
	select {
	case <-e.Done():
	default:
		t.Fatal("peer reset on ReadFrom left the egress open")
	}
	select {
	case <-replayed:
		t.Fatal("peer reset on ReadFrom requested replay instead of ending")
	default:
	}
	counters.retained.mu.Lock()
	ends := counters.retained.ends
	counters.retained.mu.Unlock()
	if ends != 0 {
		t.Fatalf("retained ends = %d, want 0", ends)
	}
}

func TestCloseBeforeBothDirectionsEndedAbortsSession(t *testing.T) {
	counters := &Counters{}
	hop := newAbortTestHop(false)
	end, err := StartIngress(t.Context(), func(_ context.Context, _ uint32, _, _ uint64) (Hop, uint64, error) {
		return hop, 0, nil
	}, counters, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := end.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-end.Done():
	default:
		t.Fatal("Close before both directions ended left the session open")
	}
	select {
	case reset := <-hop.finished:
		if !reset {
			t.Fatal("Close before both directions ended sent hop abort, want session reset")
		}
	default:
		t.Fatal("Close before both directions ended did not abort hop")
	}
	counters.retained.mu.Lock()
	ends := counters.retained.ends
	counters.retained.mu.Unlock()
	if ends != 0 {
		t.Fatalf("retained ends = %d, want 0", ends)
	}
}
