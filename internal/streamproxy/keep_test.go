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
