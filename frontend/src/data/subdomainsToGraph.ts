import type { SubdomainCollection } from "../types/subdomains";
import type { EntityKind, GraphEdge, GraphNode, InvestigationGraph } from "../types/graph";

const COLLECTOR_NAME = "subdomains";

/**
 * Transform a subdomain collector JSON result into a generic investigation
 * graph -- same pattern as dnsToGraph.ts, so the two collectors' output
 * can be merged (see mergeGraphs.ts) into one graph without either
 * knowing the other exists.
 *
 * The target becomes the root "domain" node. Every discovered hostname
 * becomes a "hostname" node connected to it by a "discovered_subdomain"
 * edge, read directly from related_entities -- nothing here is specific
 * to any domain or to Certificate Transparency; it would work unchanged
 * for any future discovery source that populates the same
 * EntityRelationship shape.
 */
export function subdomainsToGraph(collection: SubdomainCollection): InvestigationGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  let edgeCounter = 0;

  const targetValue = collection.target.value;
  const targetKind: EntityKind = "domain";

  function getOrCreateNode(id: string, kind: EntityKind, label: string): GraphNode {
    const existing = nodes.get(id);
    if (existing) {
      if (!existing.sources.includes(COLLECTOR_NAME)) {
        existing.sources.push(COLLECTOR_NAME);
      }
      return existing;
    }

    const node: GraphNode = { id, kind, label, data: {}, sources: [COLLECTOR_NAME] };
    nodes.set(id, node);
    return node;
  }

  const root = getOrCreateNode(`${targetKind}:${targetValue}`, targetKind, targetValue);

  for (const relation of collection.related_entities) {
    if (relation.relationship !== "discovered_subdomain") continue;

    // A source occasionally "discovers" the target itself (e.g. a
    // certificate whose SAN list includes the bare domain) -- that isn't
    // a new entity, just confirmation the root exists.
    if (relation.value === targetValue) continue;

    const hostnameNode = getOrCreateNode(`hostname:${relation.value}`, "hostname", relation.value);

    edgeCounter += 1;
    edges.push({
      id: `subdomains-e${edgeCounter}`,
      source: root.id,
      target: hostnameNode.id,
      relationship: relation.relationship,
      sourceRecord: relation.source_record,
      data: {},
      sources: [COLLECTOR_NAME],
    });
  }

  return { nodes: Array.from(nodes.values()), edges };
}
