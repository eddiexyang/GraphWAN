import { effectiveEdges } from './groups'
import { linkRTT, edgeView, type AgentStatus, type Network, type State } from './model'

export type PathView = {
  // Every node and edge of the paths, which ECMP may split into several.
  nodes: string[]
  edges: string[]
  // Each path's nodes, when the path is the routes the Agents installed.
  paths?: string[][]
  weight: number
  rtt_ms?: number
  state: 'Active' | 'Unavailable' | 'Unknown'
  reason?: string
}

// Match internal/routing/routing.go: weight, then first-hop ID, then node ID.
// Recompute the next hop at each intermediate node, as the forwarding plane does.
export function activePath(
  network: Network,
  source: string,
  destination: string,
  state: State,
  statuses: AgentStatus[],
  live: boolean,
): PathView {
  const excluded = new Set(
    network.nodes
      .filter((n) => state.agents.find((a) => a.id === n.agent_id)?.revoked)
      .map((n) => n.id),
  )
  const saved = state.networks.find((n) => n.id === network.id)
  const routingKey = (n: Network) =>
    JSON.stringify([
      n.nodes.map((node) => [node.id, node.agent_id, node.address]).sort(),
      effectiveEdges(n)
        .map((e) => [e.id, e.a, e.b, e.enabled, e.weight, e.transports])
        .sort(),
    ])
  const useLive = live && !!saved && routingKey(saved) === routingKey(network)
  const available = (a: string, b: string, edgeID: string) => {
    const endpoint = (id: string) =>
      statuses.find((s) => s.agent_id === network.nodes.find((n) => n.id === id)?.agent_id)
    const healthy = (s: AgentStatus | undefined) =>
      !!s?.connected &&
      Date.now() - Date.parse(s.last_seen) <= 45000 &&
      !s.config_error &&
      !s.runtime_error
    const left = endpoint(a),
      right = endpoint(b)
    if (
      network.nodes.find((n) => n.id === a)?.wireguard ||
      network.nodes.find((n) => n.id === b)?.wireguard
    ) {
      const gateway = network.nodes.find((n) => n.id === a)?.wireguard ? right : left
      return (
        healthy(gateway) &&
        !!gateway?.links?.some(
          (l) =>
            l.network_id === network.id &&
            l.edge_id === edgeID &&
            l.transport === 'wireguard' &&
            l.healthy,
        )
      )
    }
    return (
      healthy(left) &&
      healthy(right) &&
      (left?.links ?? []).some(
        (l) =>
          l.network_id === network.id &&
          l.edge_id === edgeID &&
          l.healthy &&
          (right?.links ?? []).some(
            (r) =>
              r.network_id === network.id &&
              r.edge_id === edgeID &&
              r.healthy &&
              r.link_id === l.link_id &&
              r.transport === l.transport,
          ),
      )
    )
  }
  const edges = effectiveEdges(network).filter(
    (e) =>
      e.enabled &&
      !excluded.has(e.a) &&
      !excluded.has(e.b) &&
      (!useLive || available(e.a, e.b, e.id)),
  )
  const result: PathView = { nodes: [source], edges: [], weight: 0, state: 'Unknown' }
  // Drafts have not passed the controller's validation. A negative undirected
  // edge would make Dijkstra revisit the same nodes indefinitely.
  if (edges.some((e) => !Number.isInteger(e.weight) || e.weight < 1 || e.weight > 4294967295))
    return { ...result, reason: 'Routing weights must be integers between 1 and 4294967295.' }
  if (
    !network.nodes.some((n) => n.id === source) ||
    !network.nodes.some((n) => n.id === destination) ||
    excluded.has(source) ||
    excluded.has(destination)
  )
    return { ...result, state: 'Unavailable', reason: 'Endpoint is unavailable.' }
  if (useLive && !network.nodes.find((n) => n.id === source)?.wireguard)
    return installedPath(network, source, destination, statuses, live)
  let current = source
  while (current !== destination) {
    const best = new Map<string, { cost: number; first: string }>([
      [current, { cost: 0, first: '' }],
    ])
    const queue = [{ node: current, cost: 0, first: '' }]
    while (queue.length) {
      queue.sort(
        (a, b) => a.cost - b.cost || a.first.localeCompare(b.first) || a.node.localeCompare(b.node),
      )
      const entry = queue.shift()!
      const known = best.get(entry.node)!
      if (entry.cost !== known.cost || entry.first !== known.first) continue
      for (const edge of edges) {
        const next = edge.a === entry.node ? edge.b : edge.b === entry.node ? edge.a : undefined
        if (!next) continue
        const candidate = {
          cost: entry.cost + edge.weight,
          first: entry.node === current ? next : entry.first,
        }
        const old = best.get(next)
        if (
          !old ||
          candidate.cost < old.cost ||
          (candidate.cost === old.cost && candidate.first < old.first)
        ) {
          best.set(next, candidate)
          queue.push({ node: next, ...candidate })
        }
      }
    }
    const next = best.get(destination)?.first
    const edge = edges.find(
      (e) => (e.a === current && e.b === next) || (e.b === current && e.a === next),
    )
    if (!next || !edge || result.nodes.includes(next))
      return {
        ...result,
        state: 'Unavailable',
        reason: useLive ? 'No available route.' : 'No configured route.',
      }
    result.edges.push(edge.id)
    result.nodes.push(next)
    result.weight += edge.weight
    current = next
  }
  if (!live) return { ...result, reason: 'Live telemetry is unavailable.' }
  if (!useLive)
    return { ...result, reason: 'Unsaved routing changes; showing the configured draft path.' }
  for (const id of result.nodes) {
    const node = network.nodes.find((n) => n.id === id)!
    if (node.wireguard) continue
    const status = statuses.find((s) => s.agent_id === node.agent_id)
    if (!status?.connected)
      return { ...result, state: 'Unavailable', reason: `${node.name} is offline.` }
    if (status.applied_revision !== state.revision || status.config_error || status.runtime_error)
      return { ...result, reason: `${node.name} has not confirmed the current configuration.` }
  }
  let rtt = 0
  let measured = true
  for (const id of result.edges) {
    const edge = effectiveEdges(network).find((e) => e.id === id)!
    const view = edgeView(network, edge, statuses, {}, live)
    if (view.state !== 'Connected')
      return {
        ...result,
        state: 'Unavailable',
        reason: 'A configured hop has no healthy active link.',
      }
    const sample = linkRTT(view.active)
    if (sample === undefined) measured = false
    else rtt += sample
  }
  return {
    ...result,
    state: 'Active',
    rtt_ms: measured ? rtt : undefined,
  }
}

// The most equal-cost paths shown between two nodes.
const maxPaths = 64

// installedPath follows the routes the Agents installed, hop by hop as
// forwarding does: every equal-cost next hop under ECMP, the lowest otherwise.
// It shows what the network uses, not a path computed here; where a node has
// not reported its routes, it says so instead.
function installedPath(
  network: Network,
  source: string,
  destination: string,
  statuses: AgentStatus[],
  live: boolean,
): PathView {
  const name = (id: string) => network.nodes.find((n) => n.id === id)?.name ?? id
  const status = (id: string) =>
    statuses.find((s) => s.agent_id === network.nodes.find((n) => n.id === id)?.agent_id)
  const all = effectiveEdges(network)
  const edgeBetween = (a: string, b: string) =>
    all.find((e) => (e.a === a && e.b === b) || (e.a === b && e.b === a))
  const ecmp = network.equal_cost_paths === 'ecmp'
  const paths: string[][] = []
  let problem: Pick<PathView, 'state' | 'reason'> | undefined
  let partial: string[] = [source]
  const walk = (path: string[]) => {
    const node = path[path.length - 1]
    if (problem || paths.length >= maxPaths) return
    if (node === destination) {
      paths.push(path)
      return
    }
    partial = path
    const s = status(node)
    if (network.nodes.find((n) => n.id === node)?.wireguard) {
      problem = {
        state: 'Unknown',
        reason: `${name(node)} is a WireGuard node and routes nothing.`,
      }
      return
    }
    if (!s?.connected) {
      problem = { state: 'Unavailable', reason: `${name(node)} is offline.` }
      return
    }
    const routes = s.link_state?.routes?.[network.id]
    if (!routes) {
      problem = { state: 'Unknown', reason: `${name(node)} has not reported its routes.` }
      return
    }
    const route = routes.find((r) => r.destination === destination)
    if (!route) {
      problem = { state: 'Unavailable', reason: `${name(node)} has no route.` }
      return
    }
    for (const next of ecmp ? [route.next_hop, ...(route.alternates ?? [])] : [route.next_hop]) {
      if (path.includes(next)) {
        problem = { state: 'Unavailable', reason: `The routes loop at ${name(next)}.` }
        return
      }
      if (!edgeBetween(node, next)) {
        problem = {
          state: 'Unavailable',
          reason: `${name(node)} routes to ${name(next)} without an edge.`,
        }
        return
      }
      walk([...path, next])
    }
  }
  walk([source])
  const shown = problem ? [partial] : paths
  const nodes = [...new Set(shown.flat())]
  const edges = [
    ...new Set(shown.flatMap((p) => p.slice(1).map((id, i) => edgeBetween(p[i], id)!.id))),
  ]
  const weight = shown[0]
    .slice(1)
    .reduce((sum, id, i) => sum + edgeBetween(shown[0][i], id)!.weight, 0)
  const result: PathView = { nodes, edges, paths: shown, weight, state: 'Active' }
  if (problem) return { ...result, ...problem }
  if (paths.length >= maxPaths)
    return { ...result, reason: `Showing the first ${maxPaths} equal-cost paths.` }
  if (paths.length > 1) return { ...result, reason: `${paths.length} equal-cost paths (ECMP).` }
  let rtt = 0
  for (const id of edges) {
    const sample = linkRTT(
      edgeView(
        network,
        all.find((e) => e.id === id)!,
        statuses,
        {},
        live,
      ).active,
    )
    if (sample === undefined) return result
    rtt += sample
  }
  return { ...result, rtt_ms: rtt }
}
