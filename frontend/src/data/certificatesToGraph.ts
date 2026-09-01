import type { CertificateCollection, CertificateObservation } from "../types/certificates";
import type { EntityKind, GraphEdge, GraphNode, InvestigationGraph } from "../types/graph";

const COLLECTOR_NAME = "certificates";

/**
 * Transform a certificate collector JSON result into a generic
 * investigation graph -- same pattern as dnsToGraph.ts/
 * subdomainsToGraph.ts, so all three collectors' output can be merged
 * (see mergeGraphs.ts) into one graph without any of them knowing the
 * others exist.
 *
 * Unlike subdomainsToGraph.ts (which only ever adds hostname leaves
 * around the existing target), a certificate must become its OWN graph
 * node: several distinct certificates can cover overlapping hostnames,
 * and the investigator needs to see which certificate covers which name.
 * This is why this reads `collection.certificates` directly (the rich,
 * per-certificate SAN list) rather than `collection.related_entities` --
 * the same choice dnsToGraph.ts already made for its own richer
 * `records` array, for the same reason: a flat (entity_type, value,
 * relationship, source_record) row has no way to represent "this
 * specific certificate, with these specific SANs" as one addressable
 * node.
 *
 * Certificate metadata (issuer, validity, status, fingerprint, SAN
 * summary) is attached directly to the certificate node's own `data` --
 * unlike DNS/subdomain nodes, whose `data` stays empty because their
 * per-record detail (ttl, MX priority, ...) describes *how they were
 * connected* and belongs on the edge instead (see dnsToGraph.ts). A
 * certificate's issuer/validity/fingerprint describe the certificate
 * itself, not the "covered_by" edge that points at it, so the node's own
 * `data` is the natural place for it (see entityCardData.ts's
 * "certificate" case, which reads it back for the 2D card).
 */
export function certificatesToGraph(collection: CertificateCollection): InvestigationGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  let edgeCounter = 0;

  const targetValue = collection.target.value;
  const targetKind: EntityKind = "domain";

  function getOrCreateNode(id: string, kind: EntityKind, label: string, data: Record<string, unknown> = {}): GraphNode {
    const existing = nodes.get(id);
    if (existing) {
      if (!existing.sources.includes(COLLECTOR_NAME)) {
        existing.sources.push(COLLECTOR_NAME);
      }
      return existing;
    }

    const node: GraphNode = { id, kind, label, data, sources: [COLLECTOR_NAME] };
    nodes.set(id, node);
    return node;
  }

  const root = getOrCreateNode(`${targetKind}:${targetValue}`, targetKind, targetValue);

  for (const certificate of collection.certificates) {
    const certificateNode = getOrCreateNode(
      `certificate:${certificate.certificate_id}`,
      "certificate",
      certificate.common_name ?? certificate.certificate_id,
      certificateNodeData(certificate)
    );

    edgeCounter += 1;
    edges.push({
      id: `certificates-e${edgeCounter}`,
      source: root.id,
      target: certificateNode.id,
      relationship: "covered_by",
      sourceRecord: certificate.certificate_id,
      data: {},
      sources: [COLLECTOR_NAME],
    });

    // Deduplicated by (name, is_wildcard) already at the collector level
    // (see collectors/certificates/collector.py's _merge_sans), so an
    // exact-match SAN and a wildcard SAN on the same name each get their
    // own edge here -- both are real, distinct coverage facts.
    for (const san of certificate.sans) {
      const hostnameKind: EntityKind = san.name === targetValue ? "domain" : "hostname";
      const hostnameNode = getOrCreateNode(`${hostnameKind}:${san.name}`, hostnameKind, san.name);

      edgeCounter += 1;
      edges.push({
        id: `certificates-e${edgeCounter}`,
        source: certificateNode.id,
        target: hostnameNode.id,
        relationship: "covers",
        sourceRecord: certificate.certificate_id,
        data: { wildcard: san.is_wildcard, raw: san.raw },
        sources: [COLLECTOR_NAME],
      });
    }
  }

  return { nodes: Array.from(nodes.values()), edges };
}

function certificateNodeData(certificate: CertificateObservation): Record<string, unknown> {
  return {
    certificateId: certificate.certificate_id,
    issuer: certificate.issuer,
    notBefore: certificate.not_before,
    notAfter: certificate.not_after,
    status: certificate.status,
    fingerprintSha256: certificate.fingerprint_sha256,
    serialNumber: certificate.serial_number,
    sanCount: certificate.sans.length,
    hasWildcardSan: certificate.has_wildcard_san,
  };
}
