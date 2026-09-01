import type { GraphEdge, GraphNode } from "../../types/graph";
import { computeNodeDepths } from "./sphereLayout";

/**
 * Deterministic hierarchical layout for the card-based 2D investigation
 * board: the target sits at depth 0 (top, centered); every other node is
 * placed in a band for its BFS hop-depth from the target (see
 * computeNodeDepths, reused unchanged from sphereLayout.ts -- pure graph
 * topology, no coordinates).
 *
 * Each depth's nodes wrap into a roughly-square grid rather than one
 * single row -- a domain with dozens of A/TXT records at the same depth
 * would otherwise produce one absurdly wide row, forcing the view to
 * zoom out until every card is unreadably tiny. Wrapping keeps the whole
 * graph's aspect ratio reasonable regardless of how many nodes land on
 * one level, which is what lets this scale to 5, 20, or 50+ nodes without
 * hardcoding positions for specific entity types or domains.
 *
 * Deliberately NOT the 3D sphere/circular layout flattened to 2D: cards
 * are much larger than dots and read far better arranged in a grid a
 * viewer can scan top-to-bottom, which is also what lets every card use
 * plain top/bottom connection handles (see EntityCard.tsx) instead of
 * needing angle-aware multi-handle routing.
 */

const CARD_WIDTH = 220;
const CARD_GAP_X = 50;
const ROW_HEIGHT = 170;
const BAND_GAP = 70;
const MAX_PER_ROW = 8;

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
    // dnsToGraph/subdomainsToGraph build edges, but data is data) goes
    // in its own band past everything else, rather than colliding with
    // the root at depth 0.
    const depth = depths.has(node.id) ? depths.get(node.id)! : maxDepth + 1;
    const group = byDepth.get(depth) ?? [];
    group.push(node);
    byDepth.set(depth, group);
  }

  const positions = new Map<string, CardPosition>();
  const sortedDepths = Array.from(byDepth.keys()).sort((a, b) => a - b);

  let bandY = 0;
  for (const depth of sortedDepths) {
    const group = byDepth.get(depth)!;
    const count = group.length;
    const perRow = Math.min(MAX_PER_ROW, Math.max(1, Math.ceil(Math.sqrt(count))));
    const rowsInBand = Math.ceil(count / perRow);

    group.forEach((node, index) => {
      const row = Math.floor(index / perRow);
      const col = index % perRow;
      const itemsInThisRow = Math.min(perRow, count - row * perRow);
      const rowWidth = itemsInThisRow * CARD_WIDTH + Math.max(0, itemsInThisRow - 1) * CARD_GAP_X;
      const startX = -rowWidth / 2;

      positions.set(node.id, {
        x: startX + col * (CARD_WIDTH + CARD_GAP_X),
        y: bandY + row * ROW_HEIGHT,
      });
    });

    bandY += rowsInBand * ROW_HEIGHT + BAND_GAP;
  }

  return positions;
}

export { CARD_WIDTH };
