import type { GraphEdge, GraphNode } from "../../types/graph";
import type { SubdomainCollection } from "../../types/subdomains";
import { styleFor } from "../../styles/entityStyle";

/**
 * Frontend-only mapping from the existing GraphNode/GraphEdge shape to what
 * an entity card actually shows. GraphNode.data is intentionally empty for
 * every node dnsToGraph/subdomainsToGraph produce today -- per-record
 * detail (TTL, MX priority, a TXT record's full value, ...) lives on the
 * EDGE that created the node instead (see dnsToGraph.ts). Rather than
 * expanding the generic GraphNode model to carry a copy of that detail,
 * this derives display fields on demand from the node's own edges, which
 * is exactly the "small frontend-only mapping" the graph model doesn't
 * need to grow to support.
 */

export interface CardField {
  label: string;
  value: string;
}

export interface CardContent {
  /** Human entity-kind label, e.g. "Domain / Hostname target", "IP Address". */
  typeLabel: string;
  /** The node's own value/name, e.g. "google.com", truncated if very long. */
  primaryValue: string;
  /** Secondary/tertiary metadata, already formatted for display -- kept short so cards stay compact. */
  fields: CardField[];
}

const MAX_PRIMARY_LENGTH = 42;
const MAX_FIELD_VALUE_LENGTH = 56;
const MAX_FIELDS = 4;

/** hostname -> discovery detail, built once per subdomain collection (see buildHostnameDiscoveryMap). */
export type HostnameDiscoveryMap = Map<string, { sources: string[]; dnsStatus: string | null }>;

export function buildHostnameDiscoveryMap(subdomainCollection: SubdomainCollection | null): HostnameDiscoveryMap {
  const map: HostnameDiscoveryMap = new Map();
  if (!subdomainCollection) return map;

  for (const observation of subdomainCollection.observations) {
    const sources = Array.from(new Set(observation.discovery.map((evidence) => evidence.source)));
    const dnsStatus = observation.dns_status === "not_checked" ? null : observation.dns_status;
    map.set(observation.hostname, { sources, dnsStatus });
  }

  return map;
}

export function buildCardContent(
  node: GraphNode,
  edges: GraphEdge[],
  hostnameDiscovery: HostnameDiscoveryMap
): CardContent {
  const fields: CardField[] = [];
  const incoming = edges.filter((edge) => edge.target === node.id);

  // A subdomain hostname's real discovery source(s) (e.g. "dns_bruteforce",
  // or both "certificate_transparency" and "dns_bruteforce") are richer and
  // more specific than the generic collector-level `node.sources` -- use
  // them when available, matching the existing SubdomainsPanel's own
  // multi-source provenance display (see subdomainsToGraph.ts, which
  // otherwise only carries the first source onto the edge).
  const discovery = hostnameDiscovery.get(node.label);
  const sourceValue = discovery ? discovery.sources.join(", ") : node.sources.join(", ").toUpperCase();
  if (sourceValue) fields.push({ label: "SOURCE", value: sourceValue });

  if (discovery?.dnsStatus) {
    fields.push({ label: "DNS STATUS", value: discovery.dnsStatus });
  }

  switch (node.kind) {
    case "ip": {
      pushTtl(fields, incoming);
      break;
    }

    case "nameserver": {
      pushTtl(fields, incoming);
      break;
    }

    case "mail_server": {
      const mxEdge = incoming.find((edge) => edge.relationship === "MX");
      const priority = mxEdge?.data.priority;
      if (priority !== undefined) fields.push({ label: "PRIORITY", value: String(priority) });
      pushTtl(fields, incoming);
      break;
    }

    case "other": {
      const txtEdge = incoming.find((edge) => edge.relationship === "TXT");
      if (txtEdge && typeof txtEdge.data.fullValue === "string") {
        fields.push({ label: "VALUE", value: truncate(txtEdge.data.fullValue, MAX_FIELD_VALUE_LENGTH) });
      }
      break;
    }

    case "hostname": {
      // Only relevant for a hostname NOT already covered by subdomain
      // discovery info above (e.g. a CNAME target or a PTR result).
      if (!discovery) {
        const via = incoming.find((edge) => edge.relationship === "CNAME" || edge.relationship === "PTR");
        if (via) fields.push({ label: "VIA", value: via.relationship });
        pushTtl(fields, incoming);
      }
      break;
    }

    default:
      break;
  }

  return {
    typeLabel: styleFor(node.kind).label,
    primaryValue: truncate(node.label, MAX_PRIMARY_LENGTH),
    fields: fields.slice(0, MAX_FIELDS),
  };
}

function pushTtl(fields: CardField[], incoming: GraphEdge[]): void {
  for (const edge of incoming) {
    const ttl = edge.data.ttl;
    if (typeof ttl === "number") {
      fields.push({ label: "TTL", value: `${ttl}s` });
      return;
    }
  }
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}
