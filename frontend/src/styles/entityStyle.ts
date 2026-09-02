import type { EntityKind } from "../types/graph";

/**
 * Single source of truth for how each entity kind looks, so the 3D graph
 * and the Legend panel can never drift out of sync with each other.
 */
export interface EntityStyle {
  color: string;
  label: string;
  /** Relative sphere size in the 3D graph. */
  size: number;
}

export const ENTITY_STYLES: Record<EntityKind, EntityStyle> = {
  domain: { color: "#5ec8f8", label: "Domain / Hostname target", size: 9 },
  hostname: { color: "#7fd1ae", label: "Hostname", size: 5 },
  ip: { color: "#f2a65a", label: "IP Address", size: 5 },
  nameserver: { color: "#c792ea", label: "Nameserver", size: 5 },
  mail_server: { color: "#3fdb3a", label: "Mail Server", size: 5 },
  organization: { color: "#ef6a6a", label: "Organization", size: 6 },
  certificate: { color: "#6ae0d9", label: "Certificate", size: 6 },
  other: { color: "#8a92a6", label: "Other", size: 3 },
};

export function styleFor(kind: EntityKind): EntityStyle {
  return ENTITY_STYLES[kind] ?? ENTITY_STYLES.other;
}

/**
 * react-force-graph-3d renders a node as a sphere of radius
 * `Math.cbrt(nodeVal) * nodeRelSize`. Shared here so the graph's collision
 * force (sphereLayout.ts) can compute the *actual* rendered radius instead
 * of drifting out of sync with a separately hand-tuned number.
 */
export const NODE_REL_SIZE = 4;

export function visualNodeRadius(kind: EntityKind): number {
  return Math.cbrt(styleFor(kind).size) * NODE_REL_SIZE;
}
