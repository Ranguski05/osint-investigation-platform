import type { EntityKind, InvestigationGraph } from "../types/graph";

/**
 * "all" plus every EntityKind -- the value the entity-type filter control
 * operates on. Kept separate from EntityKind itself since "all" is a
 * presentation-only concept, not a real entity kind any node ever has.
 */
export type EntityFilterValue = EntityKind | "all";

/**
 * Presentation-layer filtering, applied AFTER dnsToGraph/subdomainsToGraph/
 * mergeGraphs have already produced the full merged graph (see DashboardBody
 * in App.tsx). Never mutates its input and never drops data from the
 * underlying collections -- it only decides which of the already-merged
 * nodes/edges the current renderer (2D or 3D) should draw.
 *
 * The investigation target itself (dnsToGraph always creates it first, so
 * it's reliably `graph.nodes[0]` -- the same convention InvestigationGraph
 * and InvestigationGraph2D already rely on for their own layouts) stays
 * visible no matter which kind is selected, rather than being filtered out
 * like any other node whose kind doesn't match. Narrowing to one kind is
 * meant to isolate *that kind's relationship to the investigation*, not
 * strand it with no anchor: without the target, same-kind nodes are never
 * connected to each other (nothing in this graph model links two IPs or
 * two nameservers directly), so every edge would vanish and selecting one
 * card would dim every other one on screen with nothing left to relate it
 * to.
 *
 * An edge is visible only when BOTH endpoints are visible, so filtering
 * down to one entity kind (plus the target) never leaves a dangling edge
 * pointing at a node that didn't pass the filter.
 */
export function filterGraphByEntityKind(graph: InvestigationGraph, filter: EntityFilterValue): InvestigationGraph {
  if (filter === "all") return graph;

  const targetId = graph.nodes[0]?.id;
  const nodes = graph.nodes.filter((node) => node.kind === filter || node.id === targetId);
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target));

  return { nodes, edges };
}

/** Node count per entity kind in the given graph -- drives which options the filter dropdown offers (and their counts), so it never lists a kind with zero nodes. */
export function countNodesByKind(graph: InvestigationGraph): Partial<Record<EntityKind, number>> {
  const counts: Partial<Record<EntityKind, number>> = {};
  for (const node of graph.nodes) {
    counts[node.kind] = (counts[node.kind] ?? 0) + 1;
  }
  return counts;
}
