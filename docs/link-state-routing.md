# Data-plane link-state routing (design)

Status: proposal on branch `feat/linkstate`.

## Problem

Agents forward with the routes the controller computes (`routing.LiveRoutes`).
An edge counts as up only while both of its Agents are connected to the
controller and reported a common healthy link in the last 45 s
(`routing.Availability`, since c41fbbf). That is the right view for the
controller, but the data plane follows it blindly:

- A controller restart starts with no reports. The first Agents to reconnect
  receive routes that omit every edge whose other end has not reported yet;
  part of the overlay is unreachable until all reports arrive.
- An Agent that cannot reach the controller has all of its edges withdrawn
  network-wide, although its links forward normally.

## Principle

The controller distributes desired state: topology, keys, addresses,
weights. Link liveness and path selection belong to the data plane. Losing the
controller then only stops configuration changes; forwarding keeps converging.

## Topology in the snapshot

`NetworkConfig` gains `Topology`: the network's effective edges (ID, A, B,
weight, enabled) and the excluded (revoked) nodes, as `routing.Compile`
already sees them. Agents keep `Routes` (the static compile) for older peers
and as the starting table.

## Link-state advertisements

Per network, each Agent originates

```
LSA { network, origin node, config revision, sequence, edges: [edge ID -> up] }
```

An edge is up locally when the Edge has a healthy Link (the same condition the
Agent reports to the controller today).

- Originated on every local change (rate-limited to one per 100 ms) and
  refreshed every 10 s. The sequence is at least the origination time in
  nanoseconds, and an Agent that hears an older LSA of its own continues above
  it, so restarts need no persisted state.
- Flooded hop by hop on the existing authenticated peer Links as a new Link
  message kind. Like stream support, the capability is offered in the Link
  introduction and confirmed in band, so Agents without it never see the kind.
- A receiver accepts an LSA with a higher sequence than it holds for that
  origin, records the arrival time, and floods it to its other neighbours.
- An LSA expires 40 s after arrival unless refreshed. A restarted or isolated
  origin therefore ages out without any controller.
- A new adjacency exchanges the full database once.
- LSAs are not signed. Transit Agents are already trusted hop forwarders in
  GraphWAN's model; LSAs are authenticated per hop by the peer session, like
  data.

Convergence target: under 30 s. A Link fails at most 7 s after its peer stops
answering when idle (2 s idle probe plus 5 s timeout; 6 s with traffic), and
flooding plus SPF add about 0.1 s. A lost LSA is repaired by the next refresh,
so the worst case stays near 17 s.

## Route computation

An edge is usable when it exists and is enabled in the local topology, neither
end is excluded, and both endpoints' current LSAs report it up (two-way check).
If an endpoint has never advertised (an Agent without this capability), its
neighbour's report alone decides that edge, so mixed versions keep working.

On any database change an Agent schedules SPF after 50 ms, runs the existing
`shortest()` over the usable edges and installs the result through the same
path as `ApplyRoutes`. Agents with this capability ignore controller `routes`
messages; the controller keeps sending them to older Agents.

LSAs carry the sender's config revision. While a new revision spreads, Agents
compute over their own topology and ignore edges they do not know; the
existing overlay hop limit bounds transient loops.

## Configuration while the controller is unreachable

Phase 1 keeps configuration delivery as it is: an Agent that cannot reach the
controller keeps its last topology and keeps forwarding.

Phase 2 (separate change): Agents flood the newest snapshot revision to
neighbours, so configuration also converges without a direct controller
connection, under the same per-hop trust as LSAs.

## Observability

Agent:

- Every 5 s the Agent writes its routing view to `<data-dir>/linkstate.json`;
  `graphwan agent status --data-dir <dir> [--lsdb|--routes|--events|--json]`
  prints it without a local control port:
  - LSDB: origin, sequence, age, revision, reported edges;
  - edges: each end's report (up, down, none) and the two-way result;
  - routes: destination, next hop, cost;
  - recent events: LSAs received, originated or expired, route installs;
  - counters: LSAs sent, received, duplicate, rejected, expired; SPF runs;
    route apply errors.
- The Agent report to the controller carries `link_state`: config revision,
  each origin's sequence per network, a route table hash and the counters.
  The controller only observes it; a view of Agents whose report differs from
  the others is the next step in the UI.

Path checks use the existing TTL/ICMP Time Exceeded support (traceroute).

## Convergence (simulation, `scratchpad/lsa_sim.py`)

50 nodes, 94 links, one-way latency 10-200 ms, SPF delay 50 ms:

| Event | After detection | Total with 4-5 s detection | Total with 0.8-1 s detection |
|---|---|---|---|
| Link failure | p50 50 ms, max 552 ms | p50 4.5 s | p50 1.0 s |
| Link recovery | p50 113 ms, max 486 ms | p50 0.18 s | p50 0.18 s |
| Node failure | 1.5-2.4 s | p50 6.2 s | p50 2.3 s |
| Config flood | - | p50 1.3 s, max 1.6 s | - |

Failure detection dominates; the protocol itself converges in sub-second for
link events.

## Testing

- Unit: LSDB acceptance/aging/sequence wrap, two-way check, legacy fallback,
  SPF over usable edges.
- Agent integration (in-memory transports): three and five Agent graphs;
  controller stopped and restarted mid-run with no loss of reachability;
  an Agent cut off from the controller keeps all its edges; link failure
  reroutes; mixed old/new Agents.
