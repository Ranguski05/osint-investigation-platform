/**
 * d3-force-3d ships no TypeScript declarations. Only `forceRadial` and
 * `forceCollide` are used here (see src/components/graph/sphereLayout.ts),
 * so only those are typed. Both accept either a constant or a per-node
 * accessor `(node, index, nodes) => number`, mirroring vanilla d3-force.
 */
declare module "d3-force-3d" {
  type Accessor<NodeDatum> = (node: NodeDatum, index: number, nodes: NodeDatum[]) => number;

  export interface ForceRadial<NodeDatum> {
    (alpha: number): void;
    initialize(nodes: NodeDatum[]): void;
    strength(strength: number | Accessor<NodeDatum>): ForceRadial<NodeDatum>;
    radius(radius: number | Accessor<NodeDatum>): ForceRadial<NodeDatum>;
    x(x: number): ForceRadial<NodeDatum>;
    y(y: number): ForceRadial<NodeDatum>;
    z(z: number): ForceRadial<NodeDatum>;
  }

  export function forceRadial<NodeDatum = unknown>(
    radius: number | Accessor<NodeDatum>,
    x?: number,
    y?: number,
    z?: number
  ): ForceRadial<NodeDatum>;

  export interface ForceCollide<NodeDatum> {
    (alpha: number): void;
    initialize(nodes: NodeDatum[]): void;
    strength(strength: number): ForceCollide<NodeDatum>;
    radius(radius: number | Accessor<NodeDatum>): ForceCollide<NodeDatum>;
    iterations(iterations: number): ForceCollide<NodeDatum>;
  }

  export function forceCollide<NodeDatum = unknown>(
    radius?: number | Accessor<NodeDatum>
  ): ForceCollide<NodeDatum>;
}
