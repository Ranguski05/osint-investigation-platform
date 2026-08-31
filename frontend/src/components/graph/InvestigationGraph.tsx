import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D, { type ForceGraphMethods } from "react-force-graph-3d";
import * as THREE from "three";
import type { GraphEdge, GraphNode, InvestigationGraph as GraphData } from "../../types/graph";
import { ENTITY_STYLES, NODE_REL_SIZE, styleFor, visualNodeRadius } from "../../styles/entityStyle";
import {
  computeLevelRadii,
  computeNodeDepths,
  createCollisionForce,
  createLevelRadialForce,
  seedLayeredPositions,
} from "./sphereLayout";
import { GlobeBackdrop } from "./GlobeBackdrop";

interface InvestigationGraphProps {
  graph: GraphData;
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  onHoverNode: (id: string | null) => void;
  /** Bumped whenever the parent wants the camera reset (e.g. "Reset view" button). */
  resetToken: number;
}

/** Force-graph nodes/links carry extra runtime fields (x, y, z, fx, fy, fz, ...); this is a practical typing. */
type FgNode = GraphNode & { x?: number; y?: number; z?: number; fx?: number; fy?: number; fz?: number };
type FgLink = Omit<GraphEdge, "source" | "target"> & {
  source: string | FgNode;
  target: string | FgNode;
};

export function InvestigationGraph({
  graph,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
  resetToken,
}: InvestigationGraphProps) {
  const fgRef = useRef<ForceGraphMethods<FgNode, FgLink> | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);

  // ForceGraph3D defaults to the *window's* size unless told otherwise, which
  // makes its canvas overflow this component's actual grid cell and paint
  // over the side panels. Track the container's real size and pass it in
  // explicitly, updating whenever the dashboard layout resizes.
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      setDimensions({ width, height });
    });
    observer.observe(container);

    return () => observer.disconnect();
  }, []);

  // Depth (hop-count from the target) drives the hierarchical/radial
  // layout -- see sphereLayout.ts. Computed from the graph's own edges,
  // so it adapts to whatever structure the current investigation has.
  //
  // dnsToGraph always creates the target node first, so it's reliably
  // graph.nodes[0] -- relied on here rather than adding a dedicated
  // "isRoot" field to the generic GraphNode type for one layout detail.
  const rootId = graph.nodes[0]?.id ?? "";
  const depths = useMemo(() => computeNodeDepths(graph.nodes, graph.edges, rootId), [graph, rootId]);
  const levelRadii = useMemo(() => computeLevelRadii(depths), [depths]);

  // Re-seed positions whenever the underlying node set changes (i.e. a new
  // investigation was loaded), not on every render.
  const fgData = useMemo(() => {
    const nodes = graph.nodes.map((node) => ({ ...node })) as FgNode[];
    seedLayeredPositions(nodes, depths, levelRadii);

    // Pin the target permanently at the exact center, rather than relying
    // on force balance to keep it "usually" near the middle.
    const root = nodes.find((node) => node.id === rootId);
    if (root) Object.assign(root, { fx: 0, fy: 0, fz: 0 });

    const links = graph.edges.map((edge) => ({ ...edge })) as unknown as FgLink[];
    return { nodes, links };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph]);

  useEffect(() => {
    const fg = fgRef.current;
    if (!fg) return;
    fg.d3Force("level-radial", createLevelRadialForce(depths, levelRadii) as never);
    fg.d3Force("collide", createCollisionForce() as never);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fgData]);

  // Fit the camera to the graph's actual bounds once the layout settles,
  // rather than a fixed distance that's wrong for a 5-node vs. 100-node
  // graph. Fires automatically after (re)heating settles, and again
  // whenever "Reset view" is clicked.
  const fitToGraph = useCallback(() => {
    fgRef.current?.zoomToFit(800, 30);
  }, []);

  useEffect(() => {
    if (resetToken === 0) return;
    fitToGraph();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetToken]);

  const connectedNodeIds = useMemo(
    () => connectedTo(selectedNodeId ?? hoveredNodeId, graph.edges),
    [selectedNodeId, hoveredNodeId, graph.edges]
  );
  const focusId = selectedNodeId ?? hoveredNodeId;

  return (
    <div ref={containerRef} className="graph-canvas-container">
      <GlobeBackdrop />
      <ForceGraph3D<FgNode, FgLink>
        ref={fgRef}
        graphData={fgData}
        width={dimensions.width || undefined}
        height={dimensions.height || undefined}
        // Transparent so the GlobeBackdrop behind it shows through; the
        // graph's own dark backdrop now comes from that SVG layer instead
        // of an opaque canvas fill.
        backgroundColor="rgba(0,0,0,0)"
        showNavInfo={false}
        nodeRelSize={NODE_REL_SIZE}
        nodeVal={(node) => (node.id === selectedNodeId ? styleFor(node.kind).size * 1.5 : styleFor(node.kind).size)}
        nodeColor={(node) => nodeColor(node, focusId, connectedNodeIds)}
        nodeOpacity={0.95}
        nodeLabel={(node) => nodeTooltip(node)}
        onNodeClick={(node) => onSelectNode(node.id === selectedNodeId ? null : node.id)}
        onNodeHover={(node) => onHoverNode(node ? node.id : null)}
        onBackgroundClick={() => onSelectNode(null)}
        onEngineStop={fitToGraph}
        // Glow halo: every node gets a decorative sprite attached alongside
        // the library's own default sphere (nodeThreeObjectExtend), sized
        // to zero opacity by default. nodeThreeObject/nodeThreeObjectExtend
        // must stay referentially stable -- the library rebuilds every node
        // object from scratch when either of those two props changes, so
        // they take no per-render state; nodePositionUpdate runs every
        // frame regardless (same mechanism already used for edge labels
        // above) and is where the actual per-node glow tier is computed.
        nodeThreeObject={createNodeGlowObject}
        nodeThreeObjectExtend={true}
        nodePositionUpdate={(obj, _coords, node) => {
          const n = node as unknown as FgNode;
          const material = (obj as THREE.Sprite).material as THREE.SpriteMaterial;
          const depth = depths.get(n.id) ?? -1;
          const spec = glowSpecFor(n, depth, n.id === selectedNodeId);

          if (!spec) {
            material.opacity = 0;
            return false;
          }

          const dimmed = focusId !== null && !connectedNodeIds.has(n.id);
          material.color.set(spec.color);
          material.opacity = dimmed ? spec.opacity * 0.15 : spec.opacity;
          const radius = visualNodeRadius(n.kind);
          (obj as THREE.Sprite).scale.set(radius * spec.scale, radius * spec.scale, 1);

          return false; // positioning itself is still handled by the library's own default logic
        }}
        linkColor={(link) => linkColor(link as FgLink, focusId)}
        linkOpacity={0.55}
        linkWidth={(link) => (isLinkActive(link as FgLink, focusId) ? 1.6 : 0.6)}
        linkDirectionalArrowLength={3.5}
        linkDirectionalArrowRelPos={1}
        linkThreeObjectExtend
        linkThreeObject={(link) => makeEdgeLabel(link as FgLink)}
        linkPositionUpdate={(sprite, { start, end }, link) => {
          const middle = {
            x: (start.x + end.x) / 2,
            y: (start.y + end.y) / 2,
            z: (start.z + end.z) / 2,
          };
          Object.assign(sprite.position, middle);

          // Edge labels are hidden by default and only shown for edges
          // touching the currently hovered/selected node -- otherwise a
          // graph of any real size has every label visible at once.
          const material = (sprite as THREE.Sprite).material as THREE.SpriteMaterial;
          material.opacity = isLinkActive(link as unknown as FgLink, focusId) ? 1 : 0;

          return true;
        }}
      />
    </div>
  );
}

function connectedTo(nodeId: string | null, edges: GraphEdge[]): Set<string> {
  const ids = new Set<string>();
  if (!nodeId) return ids;
  ids.add(nodeId);
  for (const edge of edges) {
    if (edge.source === nodeId) ids.add(edge.target);
    if (edge.target === nodeId) ids.add(edge.source);
  }
  return ids;
}

function nodeColor(node: FgNode, focusId: string | null, connected: Set<string>): string {
  const base = styleFor(node.kind).color;
  if (!focusId) return base;
  return connected.has(node.id) ? base : dim(base);
}

function isLinkActive(link: FgLink, focusId: string | null): boolean {
  if (!focusId) return false;
  const sourceId = typeof link.source === "string" ? link.source : link.source.id;
  const targetId = typeof link.target === "string" ? link.target : link.target.id;
  return sourceId === focusId || targetId === focusId;
}

function linkColor(link: FgLink, focusId: string | null): string {
  return isLinkActive(link, focusId) ? "#e8edf5" : "#3a4152";
}

function dim(hex: string): string {
  // Fade a color toward the background for de-emphasized nodes.
  const color = new THREE.Color(hex);
  color.lerp(new THREE.Color("#05070c"), 0.75);
  return `#${color.getHexString()}`;
}

function nodeTooltip(node: FgNode): string {
  const kindLabel = styleFor(node.kind).label;
  return `${kindLabel}\n${node.label}`;
}

interface GlowSpec {
  color: string;
  opacity: number;
  /** Multiplier applied to the node's own visual radius (visualNodeRadius). */
  scale: number;
}

/**
 * Decides which nodes emit a glow and how strong it is, purely from
 * existing graph properties -- entity kind and hop-depth from the target
 * (already computed above via computeNodeDepths) -- plus current
 * selection. Nothing here is specific to any domain/target value.
 */
function glowSpecFor(node: FgNode, depth: number, isSelected: boolean): GlowSpec | null {
  if (isSelected) {
    // Strongest glow regardless of entity type. The target keeps its
    // signature cyan/blue even when selected; everything else glows in
    // its own established color.
    return { color: depth === 0 ? ENTITY_STYLES.domain.color : styleFor(node.kind).color, opacity: 0.95, scale: 5.5 };
  }
  if (depth === 0) {
    // The investigation target itself, regardless of its literal entity
    // kind (a hostname or IP target should still read as "the target").
    return { color: ENTITY_STYLES.domain.color, opacity: 0.85, scale: 4.5 };
  }
  if (node.kind === "nameserver") {
    // Purple reads as less luminant than gold at equal opacity (lower
    // perceived brightness for the same additive-blend intensity), so this
    // tier runs slightly hotter than mail_server to look comparably "lit".
    return { color: styleFor(node.kind).color, opacity: 0.8, scale: 3.8 };
  }
  if (node.kind === "mail_server") {
    return { color: styleFor(node.kind).color, opacity: 0.7, scale: 3.8 };
  }
  if (node.kind === "ip" && depth === 1) {
    // Only IPs directly connected to the target (e.g. its own A/AAAA
    // records) -- an IP discovered two hops out via a nameserver's own
    // A record does not glow, matching "little or no glow" for secondary
    // entities.
    return { color: styleFor(node.kind).color, opacity: 0.6, scale: 3.3 };
  }
  return null;
}

let cachedGlowTexture: THREE.Texture | null = null;

/** Soft white-to-transparent radial gradient; tinted per-node via SpriteMaterial.color, so one shared texture covers every glow tier. */
function getGlowTexture(): THREE.Texture {
  if (cachedGlowTexture) return cachedGlowTexture;

  const size = 128;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;
  const gradient = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
  gradient.addColorStop(0, "rgba(255, 255, 255, 1)");
  gradient.addColorStop(0.35, "rgba(255, 255, 255, 0.4)");
  gradient.addColorStop(1, "rgba(255, 255, 255, 0)");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, size, size);

  cachedGlowTexture = new THREE.CanvasTexture(canvas);
  return cachedGlowTexture;
}

/** Decorative glow sprite attached to every node (opacity 0 until nodePositionUpdate assigns a tier); never intercepts clicks/hover. */
function createNodeGlowObject(): THREE.Sprite {
  const material = new THREE.SpriteMaterial({
    map: getGlowTexture(),
    transparent: true,
    opacity: 0,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  const sprite = new THREE.Sprite(material);
  sprite.raycast = () => {};
  return sprite;
}

const spriteCache = new Map<string, THREE.Sprite>();

/** Draws a small text label for the edge's relationship (e.g. "NS", "A", "MX"); visibility is toggled per-frame in linkPositionUpdate. */
function makeEdgeLabel(link: FgLink): THREE.Sprite {
  // Edge ids (e1, e2, ...) are only unique within one loaded graph, so the
  // cache key includes the label text itself to avoid showing a stale
  // relationship label left over from a previously loaded investigation.
  const cacheKey = `${link.id}:${link.relationship}`;
  const cached = spriteCache.get(cacheKey);
  if (cached) return cached;

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d")!;
  const text = link.relationship;
  const fontSize = 28;
  ctx.font = `${fontSize}px sans-serif`;
  const width = ctx.measureText(text).width + 12;
  canvas.width = width;
  canvas.height = fontSize + 8;

  ctx.font = `${fontSize}px sans-serif`;
  ctx.fillStyle = "rgba(5, 7, 12, 0.85)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#e8edf5";
  ctx.textBaseline = "middle";
  ctx.fillText(text, 6, canvas.height / 2);

  const texture = new THREE.CanvasTexture(canvas);
  const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false, opacity: 0 });
  const sprite = new THREE.Sprite(material);
  sprite.scale.set(canvas.width / 6, canvas.height / 6, 1);

  spriteCache.set(cacheKey, sprite);
  return sprite;
}
