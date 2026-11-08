package packetbuf

import "testing"

// Storage returns to the pool only when its last owner releases it.
func TestBufferOwners(t *testing.T) {
	b := Get(9000)
	b.Retain()
	b.Retain()
	b.Release()
	b.Release()
	if b.Data == nil {
		t.Fatal("released while an owner remained")
	}
	b.Release()
	if b.Data != nil {
		t.Fatal("last owner did not release")
	}
	if again := Get(9000); again.refs.Load() != 0 {
		t.Fatal("a reused buffer kept its old owners")
	}
}
