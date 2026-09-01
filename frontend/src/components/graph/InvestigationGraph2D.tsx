import { useEffect, useMemo, useRef } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Edge,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { InvestigationGraph as GraphData } from "../../types/graph";
import type { SubdomainCollection } from "../../types/subdomains";
import { connectedTo } from "./InvestigationGraph";
import { computeCardPositions, computeInitialFitOptions } from "./cardLayout";
import { buildCardContent, buildHostnameDiscoveryMap } from "./entityCardData";
import { EntityCard, type EntityCardNode } from "./EntityCard";

const nodeTypes = { entityCard: EntityCard };

const EDGE_ACTIVE_COLOR = "#e8edf5";
const EDGE_INACTIVE_COLOR = "#3a4152";

function edgeStyle(active: boolean) {
  return {
    style: { stroke: active ? EDGE_ACTIVE_COLOR : EDGE_INACTIVE_COLOR, strokeWidth: active ? 1.6 : 1 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: active ? EDGE_ACTIVE_COLOR : EDGE_INACTIVE_COLOR,
      width: 16,
      height: 16,
    },
    labelStyle: {
      fill: active ? EDGE_ACTIVE_COLOR : "#6b7280",
      fontSize: active ? 10 : 9,
      fontWeight: active ? 600 : 500,
      opacity: active ? 1 : 0.6,
    },
    labelBgStyle: { fill: "rgba(5, 7, 12, 0.85)", fillOpacity: active ? 0.85 : 0.55 },
    zIndex: active ? 1 : 0,
  };
}

interface InvestigationGraph2DProps {
  graph: GraphData;
  /** Optional -- used only to enrich subdomain cards with real multi-source discovery provenance (see entityCardData.ts). Never a second data source: the graph itself already came from the same merged data. */
  subdomainCollection: SubdomainCollection | null;
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  onHoverNode: (id: string | null) => void;
  /** Bumped whenever the parent wants the view reset (e.g. "Reset view" button) -- shared with the 3D graph's resetToken. */
  resetToken: number;
}

/**
 * Card-based "investigation board" presentation of the same
 * InvestigationGraph data the 3D view renders (see InvestigationGraph.tsx).
 * Built on React Flow (@xyflow/react): entities are draggable information
 * cards (EntityCard.tsx) with always-visible relationship labels, laid out
 * once via a deterministic hierarchical layout (cardLayout.ts) rather than
 * a continuous physics simulation -- React Flow provides interaction
 * (drag/zoom/pan/selection rendering), not automatic layout, which is the
 * right split here since a live force simulation would fight the
 * investigator's own dragging.
 *
 * Split into this outer component (derives pure node/edge data from
 * `graph`) and an inner <GraphCanvas> that owns React Flow's own
 * nodes/edges state, remounted via `key={resetToken}`. Remounting is what
 * makes "Reset view" reliably re-fit the camera to the CURRENT layout in
 * one render (React Flow's `fitView` prop fits on mount, against whatever
 * nodes the fresh instance is constructed with -- no effect-ordering race
 * against a stale previous layout) -- it also resets any dragged
 * positions back to the deterministic layout, which the project's Reset
 * view spec explicitly allows ("optionally restore automatic layout").
 * Selection/hover changes alone (no reset) update the mounted instance's
 * node/edge data in place instead (see GraphCanvas's effect), which is
 * what preserves dragged positions during ordinary use.
 */
export function InvestigationGraph2D({
  graph,
  subdomainCollection,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
  resetToken,
}: InvestigationGraph2DProps) {
  const hostnameDiscovery = useMemo(() => buildHostnameDiscoveryMap(subdomainCollection), [subdomainCollection]);

  const focusId = selectedNodeId ?? hoveredNodeId;

  const rootId = graph.nodes[0]?.id ?? "";

  const initialFit = useMemo(() => computeInitialFitOptions(graph.nodes, rootId), [graph.nodes, rootId]);

  // Card dimming is deliberately keyed to selectedNodeId alone, NOT focusId
  // (selection OR hover) -- most nodes in this graph only connect to the
  // target, not to each other, so merely hovering any one card would dim
  // nearly every other card on the board. That reads as "everything
  // disappearing" from a passive mouse movement, which is far more
  // disruptive here than in the 3D view (small spheres are rarely hovered
  // by accident; large cards covering most of the canvas are). A real
  // click-to-select is a deliberate action and keeps the stronger focus
  // effect; hover still lightly highlights the touched card's edges below
  // (via focusId, unchanged) without fading out the rest of the board.
  const connectedToSelection = useMemo(
    () => connectedTo(selectedNodeId, graph.edges),
    [selectedNodeId, graph.edges]
  );

  // Deliberately its OWN memo, depending on selection but NOT on focusId/
  // hover: React Flow measures each node's real DOM size before it can be
  // positioned/fitted, so replacing this array forces every card to be
  // re-measured. If this depended on hover too (as it used to, bundled
  // together with edges below), merely sweeping the mouse across the board
  // would re-measure the entire node set on every mouseenter/mouseleave --
  // and colliding with the imperative re-fit below (or a concurrent data
  // update, e.g. subdomain enrichment arriving) that churn could leave
  // React Flow's viewport stuck reporting nodes as unmeasured for an
  // extended stretch, rendering the whole board invisible. Keeping this
  // array referentially stable across hover changes is what actually fixes
  // that: hover recomputes (and re-syncs, see GraphCanvas) only the much
  // cheaper edges below, never touching node measurement at all.
  const nodes: EntityCardNode[] = useMemo(() => {
    const positions = computeCardPositions(graph.nodes, graph.edges, rootId);

    return graph.nodes.map((node) => ({
      id: node.id,
      type: "entityCard",
      position: positions.get(node.id) ?? { x: 0, y: 0 },
      data: {
        kind: node.kind,
        content: buildCardContent(node, graph.edges, hostnameDiscovery),
        selected: node.id === selectedNodeId,
        dimmed: selectedNodeId !== null && !connectedToSelection.has(node.id),
      },
    }));
  }, [graph, rootId, hostnameDiscovery, selectedNodeId, connectedToSelection]);

  // Hover-reactive (via focusId) but kept separate from `nodes` above --
  // edges are plain SVG paths React Flow doesn't need to measure, so
  // recomputing this on every hover is cheap and never triggers the node
  // re-measurement path.
  const edges: Edge[] = useMemo(() => {
    return graph.edges.map((edge) => {
      const active = focusId !== null && (edge.source === focusId || edge.target === focusId);
      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.relationship,
        ...edgeStyle(active),
      };
    });
  }, [graph, focusId]);

  return (
    <div className="graph-canvas-container investigation-board">
      <GraphCanvas
        key={resetToken}
        initialNodes={nodes}
        initialEdges={edges}
        initialFitNodes={initialFit.nodes}
        initialFitPadding={initialFit.padding}
        initialFitMinZoom={initialFit.minZoom}
        selectedNodeId={selectedNodeId}
        onSelectNode={onSelectNode}
        onHoverNode={onHoverNode}
      />
    </div>
  );
}

interface GraphCanvasProps {
  initialNodes: EntityCardNode[];
  initialEdges: Edge[];
  initialFitNodes: { id: string }[];
  initialFitPadding: number;
  initialFitMinZoom?: number;
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  onHoverNode: (id: string | null) => void;
}

function GraphCanvas({
  initialNodes,
  initialEdges,
  initialFitNodes,
  initialFitPadding,
  initialFitMinZoom,
  selectedNodeId,
  onSelectNode,
  onHoverNode,
}: GraphCanvasProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<EntityCardNode>(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(initialEdges);
  const reactFlowRef = useRef<ReactFlowInstance<EntityCardNode, Edge> | null>(null);
  const isFirstFit = useRef(true);
  const pendingFit = useRef<{ nodes: { id: string }[]; padding: number; minZoom?: number } | null>(null);

  // React Flow's `fitView`/`fitViewOptions` props only take effect ON
  // MOUNT -- changing them later (e.g. the entity-type filter narrowing
  // which nodes exist, see EntityTypeFilter/filterGraph.ts) does NOT
  // re-trigger a fit on its own. Without this, filtering while already in
  // 2D mode would silently leave the camera framed on wherever it was
  // before (typically centered on the now-hidden target), showing an
  // arbitrary, badly-cropped slice of the new (usually much smaller) node
  // set instead of a proper fit.
  //
  // Re-fitting needs to happen imperatively, and only AFTER the node/edge
  // sync effect below has actually committed the new set (fitView needs
  // those nodes' bounds to already exist in React Flow's own store, which
  // only happens on the render after `setNodes`/`setEdges` runs) -- so
  // this just records what to fit to; the effect further below (watching
  // the actual `nodes`/`edges` state) performs it once that's true. This
  // also naturally never fires mid-drag: dragging updates `nodes` via
  // `onNodesChange`, not this ref, so the guard there stays a no-op then.
  useEffect(() => {
    if (isFirstFit.current) {
      // The `fitView` prop below already handles the initial mount.
      isFirstFit.current = false;
      return;
    }
    pendingFit.current = { nodes: initialFitNodes, padding: initialFitPadding, minZoom: initialFitMinZoom };
  }, [initialFitNodes, initialFitPadding, initialFitMinZoom]);

  // Re-sync nodes from the latest computed set without a full remount (see
  // the key-remount above, reserved for actual camera resets) -- this runs
  // for selection changes AND for the entity-type filter narrowing/
  // widening which nodes exist at all (see EntityTypeFilter/filterGraph.ts).
  // Deliberately NOT dependent on hover: `initialNodes` itself only changes
  // identity for those reasons (see the memo in InvestigationGraph2D), so
  // this effect -- and the node re-measurement React Flow does whenever
  // the array changes -- never runs from a mere mouse movement. Content/
  // styling and the node *set* itself always mirror `initialNodes`; only
  // `position` is taken from the currently-mounted node instead, so a card
  // the investigator dragged stays exactly where they put it, while a node
  // that appears or disappears (filter change) is added or removed
  // immediately rather than waiting for a remount.
  useEffect(() => {
    setNodes((current) => {
      const currentById = new Map(current.map((node) => [node.id, node]));
      return initialNodes.map((incoming) => {
        const existing = currentById.get(incoming.id);
        return existing ? { ...incoming, position: existing.position } : incoming;
      });
    });
  }, [initialNodes, setNodes]);

  // Edges re-sync independently and much more often (every hover changes
  // which edge is highlighted) -- cheap, since edges are plain SVG paths
  // React Flow never measures, unlike nodes above.
  useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

  // Performs a fit scheduled above, once `nodes`/`edges` (React Flow's
  // actual rendered state) reflect the new filtered set.
  useEffect(() => {
    if (!pendingFit.current) return;
    const fit = pendingFit.current;
    pendingFit.current = null;
    reactFlowRef.current?.fitView({
      nodes: fit.nodes,
      padding: fit.padding,
      duration: 300,
      maxZoom: 0.9,
      minZoom: fit.minZoom,
    });
  }, [nodes, edges]);

  return (
    <ReactFlow
      nodeTypes={nodeTypes}
      nodes={nodes}
      edges={edges}
      onInit={(instance) => {
        reactFlowRef.current = instance;
      }}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={(_event, node) => onSelectNode(node.id === selectedNodeId ? null : node.id)}
      onNodeMouseEnter={(_event, node) => onHoverNode(node.id)}
      onNodeMouseLeave={() => onHoverNode(null)}
      onPaneClick={() => onSelectNode(null)}
      elementsSelectable={false}
      nodesConnectable={false}
      fitView
      fitViewOptions={{
        nodes: initialFitNodes,
        padding: initialFitPadding,
        duration: 0,
        maxZoom: 0.9,
        minZoom: initialFitMinZoom,
      }}
      minZoom={0.05}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} color="#1c2433" gap={28} size={1} />
      {/* bottom-right, not React Flow's bottom-left default -- the
          existing Node Inspector already occupies bottom-left (see
          NodeInspector.tsx / .node-inspector in app.css). */}
      <Controls position="bottom-right" showInteractive={false} />
    </ReactFlow>
  );
}
