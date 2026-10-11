package linkstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
)

// Reserve the envelope and the Link message byte; each JSON map entry needs
// at most 56 bytes for a 32-character ID and a maximal uint64 sequence.
const inventoryEntries = (packet.MaxFrame - 512) / 64

// The digest is constant while the database is unchanged. On a mismatch,
// inventories exchange origin sequences; only newer LSAs are transferred.
// Neither a digest nor an inventory renews an origin's lease.
type syncMessage struct {
	Kind      string              `json:"kind"`
	Network   model.ID            `json:"network"`
	Digest    string              `json:"digest,omitempty"`
	Sequences map[model.ID]uint64 `json:"sequences,omitempty"`
	Reply     bool                `json:"reply,omitempty"`
	After     model.ID            `json:"after,omitempty"`
	Through   model.ID            `json:"through,omitempty"`
}

func (l LSA) maxAge() time.Duration {
	if l.Sync {
		return MaxAge
	}
	return LegacyMaxAge
}

// Only the configured connected component participates in negotiation. An
// isolated node cannot prevent its unrelated component from using sync.
func (n *network) supportsSync() bool {
	for _, peer := range n.syncMembers {
		en, ok := n.db[peer]
		if !ok || !en.lsa.Sync {
			return false
		}
	}
	return true
}

func componentMembers(config model.NetworkConfig) []model.ID {
	adjacent := map[model.ID][]model.ID{}
	for _, edge := range config.Topology {
		adjacent[edge.A] = append(adjacent[edge.A], edge.B)
		adjacent[edge.B] = append(adjacent[edge.B], edge.A)
	}
	seen := map[model.ID]bool{config.Self.ID: true}
	queue := []model.ID{config.Self.ID}
	var members []model.ID
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for _, peer := range adjacent[node] {
			if seen[peer] {
				continue
			}
			seen[peer] = true
			members = append(members, peer)
			queue = append(queue, peer)
		}
	}
	return members
}

// Inventories cover sorted ID ranges, including absent IDs within each range.
// Bounded chunks fit the peer frame even for a MaxNodes-sized database.
func (n *network) inventory(now time.Time, reply bool) [][]byte {
	sequences := n.sequences(now)
	ids := make([]model.ID, 0, len(sequences))
	for id := range sequences {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out [][]byte
	var after model.ID
	for {
		count := min(inventoryEntries, len(ids))
		m := syncMessage{Kind: "inventory", Network: n.config.ID, Reply: reply, After: after, Sequences: map[model.ID]uint64{}}
		for _, id := range ids[:count] {
			m.Sequences[id] = sequences[id]
		}
		if count < len(ids) {
			m.Through = ids[count-1]
		}
		raw, _ := json.Marshal(m)
		out = append(out, raw)
		if count == len(ids) {
			return out
		}
		after, ids = m.Through, ids[count:]
	}
}

func (n *network) records(now time.Time) map[model.ID]LSA {
	out := make(map[model.ID]LSA, len(n.db)+1)
	if n.self != nil {
		own := *n.self
		own.AgeMS = max(0, now.Sub(n.sent).Milliseconds())
		if own.AgeMS < own.maxAge().Milliseconds() {
			out[own.Origin] = own
		}
	}
	for id, en := range n.db {
		lsa := en.lsa
		lsa.AgeMS = max(0, now.Sub(en.arrived).Milliseconds())
		if lsa.AgeMS < lsa.maxAge().Milliseconds() {
			out[id] = lsa
		}
	}
	return out
}

func (n *network) sequences(now time.Time) map[model.ID]uint64 {
	out := make(map[model.ID]uint64, len(n.db)+1)
	for id, lsa := range n.records(now) {
		out[id] = lsa.Sequence
	}
	return out
}

func (n *network) digest(now time.Time) string {
	// encoding/json sorts map keys, so arrival order cannot change the digest.
	raw, _ := json.Marshal(n.sequences(now))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func (e *Engine) receiveSync(networkID, peer model.ID, raw []byte) error {
	var m syncMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	e.mu.Lock()
	n := e.networks[networkID]
	if n == nil || m.Network != networkID || !n.neighbors[peer] {
		e.mu.Unlock()
		return errors.New("link-state sync from an unknown neighbour")
	}
	now := e.cb.Now()
	var out [][]byte
	var advertisements int
	switch m.Kind {
	case "digest":
		decoded, err := hex.DecodeString(m.Digest)
		if err != nil || len(decoded) != 16 {
			e.mu.Unlock()
			return errors.New("invalid link-state digest")
		}
		if m.Digest != n.digest(now) {
			out = n.inventory(now, false)
		}
	case "inventory":
		if len(m.Sequences) > inventoryEntries || len(m.Sequences) > len(n.config.Directory)+1 || m.After != "" && m.After.Validate() != nil || m.Through != "" && (m.Through.Validate() != nil || m.Through <= m.After) {
			e.mu.Unlock()
			return errors.New("oversized link-state inventory")
		}
		for id := range m.Sequences {
			if !n.known(id) || id <= m.After || m.Through != "" && id > m.Through {
				e.mu.Unlock()
				return errors.New("unknown link-state inventory origin")
			}
		}
		for id, record := range n.records(now) {
			if id > m.After && (m.Through == "" || id <= m.Through) && record.Sequence > m.Sequences[id] {
				encoded, _ := json.Marshal(record)
				out = append(out, encoded)
				advertisements++
			}
		}
		if !m.Reply && m.Through == "" {
			out = append(out, n.inventory(now, true)...)
		}
	default:
		e.mu.Unlock()
		return errors.New("unknown link-state sync message")
	}
	e.mu.Unlock()
	e.stats.Sent.Add(uint64(advertisements))
	for _, message := range out {
		e.cb.Send(networkID, peer, message)
	}
	return nil
}
