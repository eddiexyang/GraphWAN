package mesh

import (
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// Registration delivers link-state readiness while holding the group lock, and
// Mesh.Apply takes group locks while holding the Mesh lock. Handler lookup must
// therefore never wait for the Mesh lock.
func TestLinkStateCallbacksDoNotTakeMeshLock(t *testing.T) {
	m := &Mesh{}
	ready := make(chan struct{}, 1)
	received := make(chan struct{}, 1)
	m.EnableLinkState(LinkStateHandler{
		Ready:   func(model.ID, model.ID) { ready <- struct{}{} },
		Receive: func(model.ID, model.ID, []byte) { received <- struct{}{} },
	})
	g := &group{mesh: m}
	g.policy.Store(&policy{})

	m.mu.Lock()
	defer m.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.LinkStateReady(nil)
		g.ReceiveLinkState(nil, nil)
	}()
	for _, ch := range []<-chan struct{}{done, ready, received} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("link-state callback blocked on the Mesh lock")
		}
	}
}
