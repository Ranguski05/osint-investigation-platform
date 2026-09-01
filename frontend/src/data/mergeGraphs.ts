import type { GraphNode, InvestigationGraph } from "../types/graph";

/**
 * Combine multiple collectors' InvestigationGraph outputs into one.
 *
 * Nodes are deduplicated by id -- the `${kind}:${value}` convention
 * already shared by every xToGraph function (dnsToGraph.ts,
 * subdomainsToGraph.ts) is what makes this correct: the same real-world
 * hostname discovered by two different collectors always produces the
 * same id, so it becomes one node with both collectors listed in
 * `sources`, never two separate nodes for the same entity.
 *
 * Edges are concatenated, not deduplicated -- two collectors may
 * legitimately draw two distinct, differently-labeled edges between the
 * same pair of nodes (e.g. DNS's "resolves_to" vs. a future collector's
 * own relationship), which is meaningful information, not duplication.
 */
export function mergeGraphs(graphs: InvestigationGraph[]): InvestigationGraph {
  const nodes = new Map<string, GraphNode>();

  for (const graph of graphs) {
    for (const node of graph.nodes) {
      const existing = nodes.get(node.id);

      if (!existing) {
        nodes.set(node.id, { ...node, sources: [...node.sources] });
        continue;
      }

      for (const source of node.sources) {
        if (!existing.sources.includes(source)) existing.sources.push(source);
      }
      existing.data = { ...existing.data, ...node.data };
    }
  }

  const edges = graphs.flatMap((graph) => graph.edges);

  return { nodes: Array.from(nodes.values()), edges };
}
