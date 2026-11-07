package forwarding

import (
	"net/netip"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// A UDP flow to a prefix with several advertisers keeps the exit it started
// with while that exit stays reachable, even when another becomes cheaper.
// TCP keeps its exit through the stream's egress instead.
const (
	stickyIdle     = 2 * time.Minute
	maxStickyFlows = 65536
)

type stickyKey struct {
	network model.ID
	flow    uint64
}

type stickyEntry struct {
	exit model.ID
	used time.Time
}

type stickyFlows struct {
	mu    sync.Mutex
	flows map[stickyKey]stickyEntry
	swept time.Time
}

func (f *stickyFlows) exit(n *network, ip netip.Addr, flow uint64) *node {
	hash := func() uint64 { return flow }
	if n.byAddress[ip] != nil || len(n.advertisers(ip)) < 2 {
		return n.exit(ip, hash)
	}
	exits := n.advertisers(ip)
	now := time.Now()
	key := stickyKey{n.id, flow}
	f.mu.Lock()
	defer f.mu.Unlock()
	if entry, ok := f.flows[key]; ok && now.Sub(entry.used) < stickyIdle {
		for _, e := range exits {
			if e.node.id == entry.exit {
				if _, reachable := n.exitCost(e); reachable {
					f.flows[key] = stickyEntry{entry.exit, now}
					return e.node
				}
			}
		}
	}
	chosen := n.exit(ip, hash)
	if now.Sub(f.swept) >= stickyIdle {
		for k, entry := range f.flows {
			if now.Sub(entry.used) >= stickyIdle {
				delete(f.flows, k)
			}
		}
		f.swept = now
	}
	if _, known := f.flows[key]; chosen != nil && (known || len(f.flows) < maxStickyFlows) {
		if f.flows == nil {
			f.flows = map[stickyKey]stickyEntry{}
		}
		f.flows[key] = stickyEntry{chosen.id, now}
	}
	return chosen
}
