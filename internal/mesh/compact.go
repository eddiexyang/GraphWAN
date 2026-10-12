package mesh

import "github.com/eWloYW8/GraphWAN/internal/link"

// EnableCompact is called before this Mesh is published to the dataplane.
// expand rebuilds packet headers from the active forwarding table.
func (m *Mesh) EnableCompact(expand link.CompactHeader) {
	m.mu.Lock()
	m.compact = expand
	m.mu.Unlock()
}

func (m *Mesh) compactHeader() link.CompactHeader {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	return m.compact
}
