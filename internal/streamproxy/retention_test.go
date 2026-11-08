package streamproxy

import (
	"context"
	"testing"
	"time"
)

// An Agent's ends share AgentRetention: when they keep that much together,
// every end stops reading, and resumes once bytes are delivered.
func TestAgentRetention(t *testing.T) {
	previous := agentRetention
	agentRetention = 1 << 20
	defer func() { agentRetention = previous }()
	var counters Counters
	a, b := NewKeep(), NewKeep()
	a.budget, b.budget = &counters.retained, &counters.retained
	a.Add(make([]byte, 1<<20), nil, 0)
	if counters.Retained() != 1<<20 {
		t.Fatalf("retained %d", counters.Retained())
	}
	waited := make(chan error, 1)
	go func() { waited <- b.Wait(context.Background()) }()
	select {
	case <-waited:
		t.Fatal("an end read past the Agent's retention")
	case <-time.After(100 * time.Millisecond):
	}
	a.Release(1 << 19)
	select {
	case err := <-waited:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("delivered bytes did not resume reading")
	}
	a.close()
	if counters.Retained() != 0 {
		t.Fatalf("closed end still counted: %d", counters.Retained())
	}
}
