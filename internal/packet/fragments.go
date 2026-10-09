package packet

import (
	"encoding/binary"
	"sync"
	"time"
)

type fragmentKey struct {
	source, destination [16]byte
	id                  uint32
	protocol            byte
}
type fragmentEntry struct {
	known, tcp bool
	expires    time.Time
	pending    [][]byte
}

// FragmentClassifier handles IPv6 fragment headers followed by more extension
// headers. Only the initial fragment can identify their eventual transport.
// It preserves complete original UDP packets and feeds complete TCP fragment
// sets into local reassembly, including when the initial fragment arrives last.
type FragmentClassifier struct {
	mu      sync.Mutex
	entries map[fragmentKey]*fragmentEntry
	bytes   int
}

func extensionFragment(raw []byte) (key fragmentKey, initial, found bool) {
	if len(raw) < 40 || raw[0]>>4 != 6 {
		return
	}
	next, offset := raw[6], 40
	for i := 0; i < 16; i++ {
		if offset+2 > len(raw) {
			return
		}
		switch next {
		case 0, 43, 60:
			next, offset = raw[offset], offset+(int(raw[offset+1])+1)*8
		case 51:
			next, offset = raw[offset], offset+(int(raw[offset+1])+2)*4
		case 44:
			if offset+8 > len(raw) {
				return
			}
			p := raw[offset]
			if p != 0 && p != 43 && p != 60 && p != 51 {
				return
			}
			key = fragmentKey{source: [16]byte(raw[8:24]), destination: [16]byte(raw[24:40]), id: binary.BigEndian.Uint32(raw[offset+4 : offset+8]), protocol: p}
			return key, binary.BigEndian.Uint16(raw[offset+2:offset+4])&0xfff8 == 0, true
		default:
			return
		}
	}
	return
}

func HasExtensionFragment(raw []byte) bool { _, _, found := extensionFragment(raw); return found }

// Classify borrows the current packet and owns any held packets returned with
// it. Admission must precede this call. An empty output waits for classification
// or drops on bounded cache overflow; unknown TCP fragments never escape to peers.
func (c *FragmentClassifier) Classify(raw []byte) (tcp bool, packets [][]byte) {
	key, initial, found := extensionFragment(raw)
	if !found {
		return IsTCP(raw), [][]byte{raw}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.entries == nil {
		c.entries = map[fragmentKey]*fragmentEntry{}
	}
	for key, entry := range c.entries {
		if now.After(entry.expires) {
			for _, p := range entry.pending {
				c.bytes -= len(p)
			}
			delete(c.entries, key)
		}
	}
	entry := c.entries[key]
	if entry == nil {
		if len(c.entries) >= 128 {
			return false, nil
		}
		entry = &fragmentEntry{expires: now.Add(10 * time.Second)}
		c.entries[key] = entry
	}
	if initial {
		entry.known, entry.tcp = true, IsTCP(raw)
		packets = append([][]byte{raw}, entry.pending...)
		for _, p := range entry.pending {
			c.bytes -= len(p)
		}
		entry.pending = nil
		return entry.tcp, packets
	}
	if entry.known {
		return entry.tcp, [][]byte{raw}
	}
	if len(entry.pending) >= 128 || c.bytes+len(raw) > 256*1024 {
		return false, nil
	}
	entry.pending = append(entry.pending, append([]byte(nil), raw...))
	c.bytes += len(raw)
	return false, nil
}
