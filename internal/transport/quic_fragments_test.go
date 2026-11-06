package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func quicFragments(id uint64, raw []byte) [][]byte {
	var fragments [][]byte
	for offset := 0; offset < len(raw); offset += quicFragmentPayload {
		size := min(quicFragmentPayload, len(raw)-offset)
		fragment := make([]byte, quicFragmentHeader+size)
		fragment[0] = 1
		binary.BigEndian.PutUint64(fragment[1:9], id)
		binary.BigEndian.PutUint16(fragment[9:11], uint16(len(raw)))
		binary.BigEndian.PutUint16(fragment[11:13], uint16(offset))
		copy(fragment[quicFragmentHeader:], raw[offset:offset+size])
		fragments = append(fragments, fragment)
	}
	return fragments
}

// After a burst of lost fragments fills the table with incomplete messages,
// later fragmented messages still complete.
func TestQUICReassemblyRecoversFromLostFragments(t *testing.T) {
	var r quicReassembler
	now := time.Now()
	raw := bytes.Repeat([]byte{7}, quicFragmentPayload+100)
	for id := uint64(1); id <= 2*quicReassemblies; id++ {
		if r.receive(quicFragments(id, raw)[0], now) != nil {
			t.Fatal("incomplete message delivered")
		}
		now = now.Add(time.Millisecond)
	}
	for id := uint64(1000); id < 1010; id++ {
		fragments := quicFragments(id, raw)
		r.receive(fragments[0], now)
		if got := r.receive(fragments[1], now); !bytes.Equal(got, raw) {
			t.Fatalf("message %d after lost fragments was not reassembled", id)
		}
	}
}
