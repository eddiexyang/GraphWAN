package mesh

import (
	"testing"
)

// A neighbor chooses every byte of the stream frames it sends.
func FuzzReceiveStream(f *testing.F) {
	p := newMuxPair(f)
	_, lb, _ := p.connect(f, true)
	// Streams the fuzzer opens are aborted at once, as a full handler would.
	receiver := newMux(&group{ctx: p.ctx}, false, func(s *muxStream) { s.Abort() })
	f.Add([]byte{streamMessageKind, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'x'})
	f.Add([]byte{sealedStreamKind, 1, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 {
			return
		}
		receiver.ReceiveStream(lb, append([]byte(nil), raw...), nil)
	})
}
