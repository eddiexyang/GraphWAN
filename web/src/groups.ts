import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import {
  edgeView,
  linkRTT,
  rate,
  type Network,
  type Edge,
  type AgentStatus,
  type Rates,
} from './model'
// Unset fields inherit from the owner, so later shared changes still reach the pair.
export type EdgeOverride = {
  a: string
  b: string
  weight?: number
  enabled?: boolean
  transports?: Edge['transports']
  methods?: Edge['methods']
  preferred_candidate?: string
}
export type FullMeshGroup = {
  id: string
  name: string
  weight?: number
  members: string[]
  transports: Edge['transports']
  methods: Edge['methods']
  overrides?: EdgeOverride[]
}
// Exactly one of node and source_group is set.
export type GroupLink = {
  id: string
  node?: string
  source_group?: string
  group: string
  weight: number
  enabled: boolean
  transports: Edge['transports']
  methods: Edge['methods']
  overrides?: EdgeOverride[]
}
export type EdgeOwner = FullMeshGroup | GroupLink
export const linkSource = (link: GroupLink) => link.source_group ?? link.node!
export const samePair = (o: { a: string; b: string }, a: string, b: string) =>
  (o.a === a && o.b === b) || (o.a === b && o.b === a)
function overridden(owner: EdgeOwner, edge: Edge): Edge {
  const o = owner.overrides?.find((o) => samePair(o, edge.a, edge.b))
  if (!o) return edge
  const { a: _a, b: _b, ...patch } = o
  return { ...edge, ...patch }
}
// Fields equal to the shared value are dropped so the pair keeps inheriting them.
export function setOverride(owner: EdgeOwner, base: Edge, edge: Edge): EdgeOverride[] {
  const others = (owner.overrides ?? []).filter((o) => !samePair(o, edge.a, edge.b))
  const o: EdgeOverride = { a: edge.a, b: edge.b }
  if (edge.weight !== base.weight) o.weight = edge.weight
  if (edge.enabled !== base.enabled) o.enabled = edge.enabled
  if (JSON.stringify(edge.transports) !== JSON.stringify(base.transports))
    o.transports = edge.transports
  if (JSON.stringify(edge.methods) !== JSON.stringify(base.methods)) o.methods = edge.methods
  if (edge.preferred_candidate) o.preferred_candidate = edge.preferred_candidate
  return Object.keys(o).length > 2 ? [...others, o] : others
}
export const groupEdgeID = (group: string, a: string, b: string) =>
  bytesToHex(sha256(utf8ToBytes(`graphwan/full-mesh/${group}/${[a, b].sort().join('/')}`))).slice(
    0,
    32,
  )
// Shared settings without overrides; `inherit` lets the inspector reset a pair.
export function internalEdges(group: FullMeshGroup, inherit = false): Edge[] {
  const members = [...group.members].sort()
  return members.flatMap((a, i) =>
    members.slice(i + 1).map((b) => {
      const edge = {
        id: groupEdgeID(group.id, a, b),
        a,
        b,
        weight: group.weight ?? 1,
        enabled: true,
        transports: group.transports,
        methods: group.methods,
      }
      return inherit ? edge : overridden(group, edge)
    }),
  )
}
export function linkSources(network: Network, link: GroupLink) {
  return link.source_group
    ? (network.groups?.find((g) => g.id === link.source_group)?.members ?? [])
    : [link.node!]
}
export function childEdges(network: Network, link: GroupLink, inherit = false): Edge[] {
  const targets = network.groups?.find((g) => g.id === link.group)?.members ?? []
  return linkSources(network, link).flatMap((a) =>
    targets.map((b) => {
      const edge = {
        id: groupEdgeID(link.id, a, b),
        a,
        b,
        weight: link.weight,
        enabled: link.enabled,
        transports: link.transports,
        methods: link.methods,
      }
      return inherit ? edge : overridden(link, edge)
    }),
  )
}
export function effectiveEdges(network: Network): Edge[] {
  return [
    ...network.edges,
    ...(network.groups ?? []).flatMap((g) => internalEdges(g)),
    ...(network.group_links ?? []).flatMap((l) => childEdges(network, l)),
  ]
}
export function aggregate(
  network: Network,
  edges: Edge[],
  statuses: AgentStatus[],
  rates: Rates,
  live: boolean,
) {
  const views = edges.map((e) => edgeView(network, e, statuses, rates, live))
  const connected = views.filter((v) => v.state === 'Connected')
  const rtts = connected
    .flatMap((v) => v.links.filter((l) => l.active && l.healthy).map(linkRTT))
    .filter((r): r is number => r !== undefined)
  const samples = views.filter((v) => v.rx !== undefined && v.tx !== undefined)
  const speed =
    live && samples.length ? samples.reduce((sum, v) => sum + v.rx! + v.tx!, 0) : undefined
  const maximum = live && rtts.length ? Math.max(...rtts) : undefined
  const state = !live
    ? 'Unknown'
    : edges.every((e) => !e.enabled)
      ? 'Disabled'
      : connected.length === edges.filter((e) => e.enabled).length
        ? 'Connected'
        : connected.length
          ? 'Partial'
          : 'Down'
  return {
    state,
    connected: connected.length,
    total: edges.length,
    speed,
    maximum,
    label: `${rate(speed)} · ${maximum === undefined ? 'RTT unknown' : `max ${maximum.toFixed(1)} ms`} · ${live ? connected.length : '?'}/${edges.length}`,
  }
}
// Also drops overrides for pairs that membership changes no longer expand.
export function pruneGroups(network: Network): Network {
  const ids = new Set(network.nodes.map((n) => n.id))
  const groups = (network.groups ?? [])
    .map((g) => ({ ...g, members: g.members.filter((id) => ids.has(id)) }))
    .filter((g) => g.members.length >= 2)
    .map((g) => ({
      ...g,
      overrides: g.overrides?.filter(
        (o) => o.a !== o.b && g.members.includes(o.a) && g.members.includes(o.b),
      ),
    }))
  const pruned = { ...network, groups }
  return {
    ...pruned,
    group_links: (network.group_links ?? [])
      .filter(
        (l) =>
          (l.source_group ? groups.some((g) => g.id === l.source_group) : ids.has(l.node!)) &&
          groups.some((g) => g.id === l.group),
      )
      .map((l) => {
        const children = childEdges(pruned, { ...l, overrides: [] })
        return {
          ...l,
          overrides: l.overrides?.filter((o) => children.some((e) => samePair(o, e.a, e.b))),
        }
      }),
  }
}
// Explicit edges covered by a group are replaced only after confirmation in the editor.
export function coveredEdges(
  network: Network,
  groups = network.groups ?? [],
  links = network.group_links ?? [],
) {
  const pairs = new Set(
    [
      ...groups.flatMap((g) => internalEdges(g, true)),
      ...links.flatMap((l) => childEdges({ ...network, groups }, l, true)),
    ].map((e) => [e.a, e.b].sort().join('/')),
  )
  return network.edges.filter((e) => pairs.has([e.a, e.b].sort().join('/')))
}
export function topologyError(network: Network): string | undefined {
  const seen = new Set<string>()
  for (const group of network.groups ?? []) {
    if (!group.name.trim() || group.members.length < 2)
      return 'Each group needs a name and at least two members.'
    for (const id of group.members) {
      if (seen.has(id)) return 'A node can belong to only one group.'
      seen.add(id)
    }
  }
  const count =
    network.edges.length +
    (network.groups ?? []).reduce(
      (n, g) => n + (g.members.length * (g.members.length - 1)) / 2,
      0,
    ) +
    (network.group_links ?? []).reduce(
      (n, l) =>
        n +
        linkSources(network, l).length *
          (network.groups?.find((g) => g.id === l.group)?.members.length ?? 0),
      0,
    )
  if (count > 100000) return 'Expanded topology exceeds 100,000 edges.'
  const pairs = new Set<string>()
  for (const link of network.group_links ?? []) {
    const group = network.groups?.find((g) => g.id === link.group)
    if (link.source_group === link.group) return 'A group cannot connect to itself.'
    if (!group || (link.node && group.members.includes(link.node)))
      return 'A node cannot connect to its own group.'
  }
  for (const edge of effectiveEdges(network)) {
    const pair = [edge.a, edge.b].sort().join('/')
    if (pairs.has(pair))
      return 'These groups or aggregate links create duplicate connections. Remove the conflicting link first.'
    pairs.add(pair)
  }
}

// Switching an aggregate to individual edges removes the aggregate as a whole.
export function individualConnection(network: Network, a: string, b: string): Network | undefined {
  if (network.groups?.some((g) => g.members.includes(a) && g.members.includes(b))) return undefined
  const conflicts = (network.group_links ?? []).filter((l) =>
    childEdges(network, l).some((e) => (e.a === a && e.b === b) || (e.a === b && e.b === a)),
  )
  if (!conflicts.length) return network
  if (
    !window.confirm(
      'Replace the conflicting group link(s) and all their child edges with this individual edge?',
    )
  )
    return undefined
  return { ...network, group_links: network.group_links?.filter((l) => !conflicts.includes(l)) }
}
