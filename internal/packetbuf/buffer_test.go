package packetbuf

import (
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/packet"
)

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

// Bytes dropped from the front become headroom for PrependByte.
func TestAdvanceKeepsHeadroom(t *testing.T) {
	b := Get(100)
	start := &b.Data[0]
	b.Data[0] = 7
	b.Advance(1)
	if !b.PrependByte(9) || &b.Data[0] != start || b.Data[0] != 9 || len(b.Data) != 100 {
		t.Fatal("advanced bytes were not reused")
	}
	b.Release()
}

// A full-size frame with its message byte and crypto overhead fits the frame
// class, which wastes far less than the 16 KiB class.
func TestFrameClass(t *testing.T) {
	b := Get(packet.MaxFrame + 1 + 24)
	if len(b.storage) != FrameSize {
		t.Fatalf("frame of %d bytes uses %d bytes of storage", len(b.Data), len(b.storage))
	}
	b.Release()
}
