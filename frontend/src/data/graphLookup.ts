import type { DnsRecord, EntityRelationship } from "../types/dns";
import type { InvestigationGraph } from "../types/graph";

/**
 * Resolves sidebar rows (DNS records, related entities, subdomains,
 * certificates) to the graph node id they correspond to, so clicking a row
 * can select the matching node -- see RecordsPanel/RelatedEntitiesPanel/
 * SubdomainsPanel/CertificatesPanel.
 *
 * Every id convention here is read directly from the three graph builders
 * (dnsToGraph.ts, subdomainsToGraph.ts, certificatesToGraph.ts), never
 * re-derived from scratch, so this can never classify a value differently
 * than the graph itself did:
 * - domain/hostname/ip/nameserver/mail_server nodes: id is `${kind}:${value}`
 *   and label === value, so a label -> id index is sufficient.
 * - TXT records produce an "other" node with a COMPOSITE id,
 *   `other:${record.name}:${record.value}` (full value, not the truncated
 *   display label) -- resolved directly, no index needed.
 * - subdomain hostnames: always `hostname:${hostname}`.
 * - certificates: always `certificate:${certificate_id}` -- the node's
 *   label is the certificate's common_name, NOT the id, so certificates
 *   must never be matched through the label index.
 * - SOA/CAA/DNSKEY/DS records were never turned into graph nodes at all
 *   (see dnsToGraph.ts) -- resolving one of these correctly returns null
 *   rather than guessing at a nonexistent node.
 */

export type NodeIdIndex = {
  /** node label -> id, for kinds where label === value (everything except "other"). */
  byLabel: Map<string, string>;
  /** every valid node id, for existence checks (e.g. the TXT composite id). */
  ids: Set<string>;
};

export function buildNodeIdIndex(graph: InvestigationGraph): NodeIdIndex {
  const byLabel = new Map<string, string>();
  const ids = new Set<string>();

  for (const node of graph.nodes) {
    ids.add(node.id);
    // First-wins on a label collision -- only possible in principle for two
    // distinct "other" nodes truncated to the same display label, which
    // never reach this map anyway (TXT resolves by composite id below).
    if (!byLabel.has(node.label)) {
      byLabel.set(node.label, node.id);
    }
  }

  return { byLabel, ids };
}

const NODELESS_RECORD_TYPES = new Set(["SOA", "CAA", "DNSKEY", "DS"]);

export function resolveRecordNodeId(record: DnsRecord, index: NodeIdIndex): string | null {
  if (NODELESS_RECORD_TYPES.has(record.type)) return null;

  if (record.type === "TXT") {
    const compositeId = `other:${record.name}:${record.value}`;
    return index.ids.has(compositeId) ? compositeId : null;
  }

  // MX "no mail service" (value ".") never becomes a node -- dnsToGraph.ts
  // skips it, so it correctly won't be found in the index either.
  return index.byLabel.get(record.value) ?? null;
}

export function resolveRelatedEntityNodeId(entity: EntityRelationship, index: NodeIdIndex): string | null {
  return index.byLabel.get(entity.value) ?? null;
}

export function resolveSubdomainNodeId(hostname: string, index: NodeIdIndex): string | null {
  const id = `hostname:${hostname}`;
  return index.ids.has(id) ? id : null;
}

export function resolveCertificateNodeId(certificateId: string, index: NodeIdIndex): string | null {
  const id = `certificate:${certificateId}`;
  return index.ids.has(id) ? id : null;
}
