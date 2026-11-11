package streamproxy

import (
	"context"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
)

// An end holds at most its send buffer: writers wait while it is full and go
// on once the far end delivered bytes.
func TestKeepHoldsASendBuffer(t *testing.T) {
	k := NewKeep()
	k.limit = 8
	b := packetbuf.Get(8)
	k.Add(b.Data, b, 0)
	b.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waited := make(chan error, 1)
	go func() {
		_, err := k.Wait(ctx, 1)
		waited <- err
	}()
	select {
	case <-waited:
		t.Fatal("a writer went on while the send buffer was full")
	case <-time.After(50 * time.Millisecond):
	}
	k.Release(1)
	if err := <-waited; err != nil {
		t.Fatal(err)
	}
	k.close()
}

// An Agent's ends keep one send buffer together: an end takes what is left
// of it, and once it is full only an end below its equal share keeps more.
func TestKeepsShareOneSendBuffer(t *testing.T) {
	budget := &retained{limit: 8}
	keep := func() *Keep {
		k := NewKeep()
		k.limit, k.budget = 8, budget
		budget.join()
		return k
	}
	add := func(k *Keep, n int) {
		b := packetbuf.Get(n)
		k.Add(b.Data, b, 0)
		b.Release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, second := keep(), keep()
	if room, err := first.Wait(ctx, 1); err != nil || room != 8 {
		t.Fatalf("an end alone may keep %d bytes, want the whole buffer", room)
	}
	add(first, 8)
	// The buffer is full, and the second end still has its share.
	if room, err := second.Wait(ctx, 1); err != nil || room != 4 {
		t.Fatalf("the second end may keep %d bytes, want its share of 4", room)
	}
	add(second, 4)
	waited := make(chan int, 1)
	go func() {
		room, _ := second.Wait(ctx, 1)
		waited <- room
	}()
	select {
	case room := <-waited:
		t.Fatalf("an end at its share kept %d more bytes of a full buffer", room)
	case <-time.After(50 * time.Millisecond):
	}
	first.Release(8)
	if room := <-waited; room != 4 {
		t.Fatalf("after the first end released, the second may keep %d bytes, want 4", room)
	}
	first.close()
	second.close()
	if budget.total() != 0 || budget.ends != 0 {
		t.Fatalf("closed ends left %d bytes and %d ends", budget.total(), budget.ends)
	}
}
