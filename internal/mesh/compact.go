package mesh

import "github.com/eddiexyang/graphnet/internal/link"

// EnableCompact is called before this Mesh is published to the dataplane.
// compact rebuilds packet headers from the active forwarding table.
func (m *Mesh) EnableCompact(compact link.Compactor) {
	m.mu.Lock()
	m.compact = compact
	m.mu.Unlock()
}

func (m *Mesh) compactor() link.Compactor {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	return m.compact
}
