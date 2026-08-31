import type { DnsCollection, DnsEntityType, DnsRecord } from "../types/dns";
import type { EntityKind, GraphEdge, GraphNode, InvestigationGraph } from "../types/graph";

const COLLECTOR_NAME = "dns";

/**
 * Transform a DNS collector JSON result into a generic investigation graph.
 *
 * This is the ONLY place DNS-specific structure is interpreted for
 * graph purposes. It reads `records` (name -> value, typed) and uses
 * `related_entities` purely to classify what kind of thing each value
 * is (ip / nameserver / mail_server / hostname). Nothing here is aware
 * of any specific domain -- run it on any DnsCollection and it produces
 * the matching graph.
 *
 * Design notes:
 * - `records` is the source of truth for edges, because it is the only
 *   place that records *which* name produced a given value (e.g. which
 *   nameserver resolved to which IP). `related_entities` does not carry
 *   a "from" field, so it cannot alone reconstruct multi-hop structure.
 * - SOA and CAA records describe policy/metadata about a single name
 *   rather than a relationship to another entity, so they are not
 *   turned into graph nodes/edges -- they remain fully visible in the
 *   Records panel instead. Nothing is discarded, just not everything
 *   needs to be a graph node.
 * - A null MX record (value ".") means "no mail service" and must not
 *   produce a mail_server node, per the collector's own convention.
 */
export function dnsToGraph(collection: DnsCollection): InvestigationGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  let edgeCounter = 0;

  const targetKind = targetTypeToKind(collection.target.type);
  const targetValue = collection.target.value;

  // Pre-compute value -> entity kind from related_entities. The collector
  // already knows (e.g.) that a given NS record's value is a nameserver;
  // reuse that classification instead of re-guessing it here.
  const classification = new Map<string, DnsEntityType | string>();
  for (const relation of collection.related_entities) {
    if (!classification.has(relation.value)) {
      classification.set(relation.value, relation.entity_type);
    }
  }

  function kindOf(value: string): EntityKind {
    if (value === targetValue) return targetKind;

    const classified = classification.get(value);
    if (classified === "ip") return "ip";
    if (classified === "nameserver") return "nameserver";
    if (classified === "mail_server") return "mail_server";
    if (classified === "hostname") return "hostname";

    if (isIpAddress(value)) return "ip";
    return "hostname";
  }

  function getOrCreateNode(id: string, kind: EntityKind, label: string): GraphNode {
    const existing = nodes.get(id);
    if (existing) {
      if (!existing.sources.includes(COLLECTOR_NAME)) {
        existing.sources.push(COLLECTOR_NAME);
      }
      return existing;
    }

    const node: GraphNode = {
      id,
      kind,
      label,
      data: {},
      sources: [COLLECTOR_NAME],
    };
    nodes.set(id, node);
    return node;
  }

  function entityNode(value: string): GraphNode {
    const kind = kindOf(value);
    return getOrCreateNode(`${kind}:${value}`, kind, value);
  }

  function addEdge(
    sourceNode: GraphNode,
    targetNode: GraphNode,
    relationship: string,
    sourceRecord: string,
    data: Record<string, unknown> = {}
  ): void {
    edgeCounter += 1;
    edges.push({
      id: `e${edgeCounter}`,
      source: sourceNode.id,
      target: targetNode.id,
      relationship,
      sourceRecord,
      data,
      sources: [COLLECTOR_NAME],
    });
  }

  // Always create the root target node, even if collection has no records
  // (e.g. NXDOMAIN) -- the investigator should still see what was queried.
  const root = getOrCreateNode(`${targetKind}:${targetValue}`, targetKind, targetValue);

  for (const record of collection.records) {
    applyRecord({
      record,
      root,
      targetValue,
      entityNode,
      getOrCreateNode,
      addEdge,
    });
  }

  return { nodes: Array.from(nodes.values()), edges };
}

interface ApplyRecordArgs {
  record: DnsRecord;
  root: GraphNode;
  targetValue: string;
  entityNode: (value: string) => GraphNode;
  getOrCreateNode: (id: string, kind: EntityKind, label: string) => GraphNode;
  addEdge: (
    source: GraphNode,
    target: GraphNode,
    relationship: string,
    sourceRecord: string,
    data?: Record<string, unknown>
  ) => void;
}

function applyRecord({ record, root, targetValue, entityNode, getOrCreateNode, addEdge }: ApplyRecordArgs): void {
  const sourceEntity = record.name === targetValue ? root : entityNode(record.name);

  switch (record.type) {
    case "A":
    case "AAAA": {
      const ipNode = getOrCreateNode(`ip:${record.value}`, "ip", record.value);
      addEdge(sourceEntity, ipNode, record.type, record.type, { ttl: record.ttl });
      return;
    }

    case "CNAME": {
      const targetNode = entityNode(record.value);
      addEdge(sourceEntity, targetNode, "CNAME", "CNAME", { ttl: record.ttl });
      return;
    }

    case "NS": {
      const nsNode = getOrCreateNode(`nameserver:${record.value}`, "nameserver", record.value);
      addEdge(sourceEntity, nsNode, "NS", "NS", { ttl: record.ttl });
      return;
    }

    case "MX": {
      // Null MX ("MX 0 .") means "does not accept email" -- not an entity.
      if (record.value === ".") return;

      const mxNode = getOrCreateNode(`mail_server:${record.value}`, "mail_server", record.value);
      addEdge(sourceEntity, mxNode, "MX", "MX", {
        priority: record.attributes.priority,
        ttl: record.ttl,
      });
      return;
    }

    case "TXT": {
      // TXT values are attributes of a name, not standalone entities
      // (two unrelated domains could share identical TXT text), so the
      // node id is namespaced by the owning name rather than by value alone.
      const txtNode = getOrCreateNode(`other:${record.name}:${record.value}`, "other", truncate(record.value, 40));
      addEdge(sourceEntity, txtNode, "TXT", "TXT", { ttl: record.ttl, fullValue: record.value });
      return;
    }

    case "PTR": {
      // record.name is the reverse "in-addr.arpa"/"ip6.arpa" name, which is
      // not a meaningful graph entity -- the interesting edge is
      // (queried IP) -> (hostname).
      const hostnameNode = entityNode(record.value);
      addEdge(root, hostnameNode, "PTR", "PTR", { ttl: record.ttl });
      return;
    }

    case "SOA":
    case "CAA":
      // Metadata about the name itself, not a relationship to another
      // entity. Fully preserved in the Records panel; intentionally
      // absent from the graph.
      return;

    default:
      // Unknown/future record types (e.g. DNSSEC) are ignored by the graph
      // rather than crashing it. They remain visible in the Records panel.
      return;
  }
}

function targetTypeToKind(type: DnsCollection["target"]["type"]): EntityKind {
  switch (type) {
    case "domain":
      return "domain";
    case "hostname":
      return "hostname";
    case "ip":
      return "ip";
    default:
      return "other";
  }
}

export function isIpAddress(value: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;
  return ipv4.test(value) || ipv6.test(value);
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength)}…` : value;
}
