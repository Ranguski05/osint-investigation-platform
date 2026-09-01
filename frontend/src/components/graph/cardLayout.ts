import type { GraphEdge, GraphNode } from "../../types/graph";
import { computeNodeDepths } from "./sphereLayout";

/**
 * Deterministic radial layout for the card-based 2D investigation board:
 * the target sits at the center (depth 0); every other node is placed on a
 * ring for its BFS hop-depth from the target (see computeNodeDepths, reused
 * unchanged from sphereLayout.ts -- pure graph topology, no coordinates),
 * mirroring the 3D view's own hub-and-spoke layout instead of a flattened
 * tree of rows.
 *
 * A depth level with many nodes -- e.g. dozens of directly-discovered
 * subdomains, which all sit at depth 1 since subdomainsToGraph.ts links
 * every hostname straight to the target -- does NOT get one giant ring
 * sized to fit all of them: that would push its radius out so far that
 * none of it is visible near the target at a readable zoom (the opposite
 * of "related entities positioned around" the target). Instead each depth
 * caps how many cards share one ring (RING_CAPACITY) and spills the rest
 * onto additional concentric sub-rings at increasing radius -- still the
 * same hop-depth, just visually layered outward -- so the nearest handful
 * of relationships always land close to the target and only the overflow
 * extends further out. Rings (and sub-rings) are always spaced at least
 * RING_STEP/SUB_RING_STEP apart so crowding can never cause a collision.
 */

const CARD_WIDTH = 240;
const CARD_GAP = 60;
const RING_STEP = 260;
const MIN_RING_RADIUS = 340;
const RING_CAPACITY = 12;
const SUB_RING_STEP = 260;

export interface CardPosition {
  x: number;
  y: number;
}

export function computeCardPositions(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rootId: string
): Map<string, CardPosition> {
  const depths = computeNodeDepths(nodes, edges, rootId);
  const finiteDepths = Array.from(depths.values());
  const maxDepth = finiteDepths.length > 0 ? Math.max(...finiteDepths) : 0;

  const byDepth = new Map<number, GraphNode[]>();
  for (const node of nodes) {
    // A node unreachable from the root (shouldn't happen given how
    // dnsToGraph/subdomainsToGraph build edges, but data is data) goes on
    // its own outer ring, rather than colliding with the root at depth 0.
    const depth = depths.has(node.id) ? depths.get(node.id)! : maxDepth + 1;
    const group = byDepth.get(depth) ?? [];
    group.push(node);
    byDepth.set(depth, group);
  }

  const positions = new Map<string, CardPosition>();
  const sortedDepths = Array.from(byDepth.keys()).sort((a, b) => a - b);

  let radius = 0;
  for (const depth of sortedDepths) {
    const group = byDepth.get(depth)!;

    if (depth === 0) {
      // The target (and any other root-depth node, though there is
      // normally exactly one) stays at the visual center.
      group.forEach((node) => positions.set(node.id, { x: 0, y: 0 }));
      continue;
    }

    const count = group.length;
    const subRingCount = Math.ceil(count / RING_CAPACITY);

    // Stagger each ring's start angle so spokes from consecutive depths
    // (and consecutive sub-rings) don't all line up into one straight
    // line out from the center.
    const angleOffset = depth * 0.35;

    // Each sub-ring's radius only needs to be large enough for the cards
    // actually on it (at most RING_CAPACITY), so the innermost sub-ring --
    // the one nearest the target -- stays bounded regardless of how many
    // total nodes this depth has, rather than sizing one ring for all of
    // them. Successive sub-rings step outward from there.
    let subRingRadius = radius;
    for (let subRing = 0; subRing < subRingCount; subRing++) {
      const countInSubRing = Math.min(RING_CAPACITY, count - subRing * RING_CAPACITY);
      const radiusForCrowding = (countInSubRing * (CARD_WIDTH + CARD_GAP)) / (2 * Math.PI);
      subRingRadius = Math.max(subRingRadius + (subRing === 0 ? RING_STEP : SUB_RING_STEP), MIN_RING_RADIUS * depth, radiusForCrowding);

      for (let posInSubRing = 0; posInSubRing < countInSubRing; posInSubRing++) {
        const node = group[subRing * RING_CAPACITY + posInSubRing];
        const angle = (2 * Math.PI * posInSubRing) / countInSubRing + angleOffset + subRing * 0.5;
        positions.set(node.id, {
          x: Math.cos(angle) * subRingRadius,
          y: Math.sin(angle) * subRingRadius,
        });
      }
    }

    radius = subRingRadius;
  }

  return positions;
}

export interface InitialFitOptions {
  nodes: { id: string }[];
  /** React Flow fitViewOptions.padding for this node set -- see below for why it differs by case. */
  padding: number;
  /** React Flow fitViewOptions.minZoom -- omitted (no floor beyond the canvas-wide minZoom) for the multi-node fallback, where a fixed floor could crop an already-large bounding box instead of framing it. */
  minZoom?: number;
}

/**
 * Node id(s) the initial (and post-"Reset view") camera fit should frame --
 * just the target itself. Most investigations produce a near-star graph
 * (every discovered subdomain attaches directly to the target, see
 * subdomainsToGraph.ts), so "the target plus its depth-1 relationships" is
 * frequently *almost the entire graph* -- fitting to that set would still
 * force the same zoomed-out, unreadable result the fix is meant to solve.
 * Fitting to the target alone with a large, fixed padding instead yields a
 * CONSTANT default zoom level regardless of how many entities the
 * investigation turned up: the target and whichever nearby cards fall
 * within that fixed radius are readable by default, and the rest of the
 * topology (however large) remains reachable by panning/zooming out --
 * exactly the "readable entities over fitting everything on screen"
 * tradeoff the investigation-board view calls for.
 *
 * When the entity-type filter is narrowed to a kind other than the
 * target's own (the common case -- the target is almost always "domain"),
 * the target itself isn't part of the current node set at all. Fitting to
 * a nonexistent id has no reasonable "nearby" region to frame, so this
 * falls back to fitting every currently-visible node instead -- reasonable
 * since a single-kind filter's node count is typically small. That
 * fallback set is a real (already spread-out) multi-node bounding box,
 * not one tiny card, so it uses an ordinary margin instead of the single-
 * root case's large padding -- reusing that padding here would wildly
 * over-zoom-out the calculation and, once clamped back up by fitView's own
 * minZoom, paradoxically leave the cards mis-centered and clipped instead
 * of neatly framed.
 */
export function computeInitialFitOptions(nodes: GraphNode[], rootId: string): InitialFitOptions {
  if (!nodes.some((node) => node.id === rootId)) {
    return { nodes: nodes.map((node) => ({ id: node.id })), padding: 0.4 };
  }
  return { nodes: [{ id: rootId }], padding: 3.2, minZoom: 0.35 };
}

export { CARD_WIDTH };
