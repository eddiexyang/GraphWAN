package link

import (
	"testing"

	"github.com/eddiexyang/graphnet/internal/packet"
)

// A masked packet is authenticated by nobody on the way: whatever arrives,
// the Link either drops it or rebuilds a frame that parses.
func FuzzUnmasked(f *testing.F) {
	l := &Link{options: Options{Compact: compactTestHeader}}
	l.networkWire = wire(compactNetwork)
	f.Add(append([]byte{0x80 | 9, 0, 1, 0, 2}, make([]byte, 60)...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 || raw[0] < 0x80 {
			return
		}
		buffer := l.unmasked(raw, false)
		if buffer == nil {
			return
		}
		if _, err := packet.ParseView(buffer.Data); err != nil {
			t.Fatalf("rebuilt an unparsable frame: %v", err)
		}
	})
}
