/**
 * Generic investigation graph types.
 *
 * These are deliberately independent of any single collector's schema.
 * Today only `dnsToGraph` (src/data/dnsToGraph.ts) produces graph data,
 * but a future `rdapToGraph`, `certToGraph`, etc. should all target
 * this same shape so multiple collectors can be merged into one graph.
 */

/** Broad entity categories, used for node color/shape/legend grouping. */
export type EntityKind =
  | "domain"
  | "hostname"
  | "ip"
  | "nameserver"
  | "mail_server"
  | "organization"
  | "certificate"
  | "other";

export interface GraphNode {
  /** Stable identity: `${kind}:${value}`. Lets multiple collectors merge on the same entity. */
  id: string;
  kind: EntityKind;
  label: string;
  /** Arbitrary provenance/detail preserved for the inspector panel (never thrown away). */
  data: Record<string, unknown>;
  /** Which collector(s) contributed this node, e.g. ["dns"]. */
  sources: string[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  /** Short label shown on the edge, e.g. "A", "NS", "MX", "issued_for". */
  relationship: string;
  /** Which DNS/collector record produced this edge, preserved for the inspector. */
  sourceRecord: string;
  /** Extra detail preserved for the inspector (e.g. ttl, MX priority). Never thrown away. */
  data: Record<string, unknown>;
  sources: string[];
}

export interface InvestigationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
