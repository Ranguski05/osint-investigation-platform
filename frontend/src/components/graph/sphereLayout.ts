import { forceCollide, forceRadial } from "d3-force-3d";
import type { GraphEdge, GraphNode } from "../../types/graph";
import { visualNodeRadius } from "../../styles/entityStyle";

/**
 * Hierarchical/radial 3D layout: the target sits at the center (depth 0),
 * directly-related entities form a ring around it (depth 1), entities only
 * reachable through those form a wider ring (depth 2), and so on for
 * further levels if the data has them.
 *
 * Depth is computed generically from the graph's own edges (BFS hop-count
 * from the root) -- nothing here knows about DNS record types. This is
 * what replaces the old single fixed-radius "shell" that made large graphs
 * (many TXT/mail/nameserver entries) compress into one overlapping cluster.
 */

/**
 * BFS hop-distance from `rootId` to every other node, using the graph's
 * edges as an undirected adjacency list. Nodes unreachable from the root
 * (shouldn't happen given how dnsToGraph builds the graph, but data is
 * data) are omitted rather than assumed to be depth 0.
 */
export function computeNodeDepths(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rootId: string
): Map<string, number> {
  const adjacency = new Map<string, string[]>();
  for (const node of nodes) adjacency.set(node.id, []);

  for (const edge of edges) {
    adjacency.get(edge.source)?.push(edge.target);
    adjacency.get(edge.target)?.push(edge.source);
  }

  const depths = new Map<string, number>();
  if (!adjacency.has(rootId)) return depths;

  depths.set(rootId, 0);
  const queue: string[] = [rootId];

  for (let head = 0; head < queue.length; head++) {
    const current = queue[head];
    const currentDepth = depths.get(current)!;

    for (const neighbor of adjacency.get(current) ?? []) {
      if (!depths.has(neighbor)) {
        depths.set(neighbor, currentDepth + 1);
        queue.push(neighbor);
      }
    }
  }

  return depths;
}

// Base spacing between rings. A ring holding more than RING_CAPACITY nodes
// grows its radius (proportional to sqrt of the overflow) so a crowded
// level -- e.g. cloudflare.com's dozens of TXT records -- spreads out
// instead of overlapping, rather than every level using one fixed size
// regardless of how many nodes landed on it.
const LEVEL_UNIT = 90;
const RING_CAPACITY = 8;

export function computeLevelRadii(depths: Map<string, number>): Map<number, number> {
  const countsByDepth = new Map<number, number>();
  for (const depth of depths.values()) {
    countsByDepth.set(depth, (countsByDepth.get(depth) ?? 0) + 1);
  }

  const radii = new Map<number, number>();
  for (const [depth, count] of countsByDepth) {
    if (depth === 0) {
      radii.set(0, 0);
      continue;
    }
    const crowding = Math.max(1, Math.sqrt(count / RING_CAPACITY));
    radii.set(depth, LEVEL_UNIT * depth * crowding);
  }

  return radii;
}

/**
 * Seed each node's initial (x, y, z) on its depth's ring, using a
 * deterministic "Fibonacci sphere" distribution *within that ring* so
 * same-depth nodes start evenly spread rather than randomly clumped.
 * Each depth gets its own Fibonacci sequence (rather than one global
 * sequence) so a ring's spacing depends only on its own population.
 */
export function seedLayeredPositions(
  nodes: GraphNode[],
  depths: Map<string, number>,
  levelRadii: Map<number, number>
): void {
  const byDepth = new Map<number, GraphNode[]>();
  for (const node of nodes) {
    const depth = depths.get(node.id) ?? 0;
    const group = byDepth.get(depth) ?? [];
    group.push(node);
    byDepth.set(depth, group);
  }

  const goldenAngle = Math.PI * (3 - Math.sqrt(5));

  for (const [depth, group] of byDepth) {
    const radius = levelRadii.get(depth) ?? 0;
    const count = group.length;

    group.forEach((node, index) => {
      if (radius === 0 || count === 1) {
        Object.assign(node, { x: 0, y: 0, z: 0 });
        return;
      }

      const y = 1 - (index / (count - 1)) * 2; // 1 -> -1
      const radiusAtY = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = goldenAngle * index;

      Object.assign(node, {
        x: Math.cos(theta) * radiusAtY * radius,
        y: y * radius,
        z: Math.sin(theta) * radiusAtY * radius,
      });
    });
  }
}

/**
 * Continuously pulls each node toward its depth's ring radius, layered on
 * top of the library's default charge (repulsion) and link (spring)
 * forces. Strength is high enough that levels stay visually distinct.
 */
export function createLevelRadialForce(depths: Map<string, number>, levelRadii: Map<number, number>) {
  return forceRadial<GraphNode>(
    (node) => levelRadii.get(depths.get(node.id) ?? 0) ?? 0,
    0,
    0,
    0
  ).strength(0.6);
}

/**
 * Guarantees nodes cannot end up overlapping regardless of what the radial
 * and charge forces do, sized from each node's *actual rendered* sphere
 * radius (see visualNodeRadius) plus a little clearance for edge labels.
 */
export function createCollisionForce() {
  const COLLISION_PADDING = 6;
  return forceCollide<GraphNode>((node) => visualNodeRadius(node.kind) + COLLISION_PADDING).strength(0.9);
}
