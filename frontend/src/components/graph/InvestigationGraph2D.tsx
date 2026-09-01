import { useEffect, useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { InvestigationGraph as GraphData } from "../../types/graph";
import type { SubdomainCollection } from "../../types/subdomains";
import { connectedTo } from "./InvestigationGraph";
import { computeCardPositions } from "./cardLayout";
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
    labelStyle: { fill: active ? EDGE_ACTIVE_COLOR : "#6b7280", fontSize: 10, fontWeight: 600 },
    labelBgStyle: { fill: "rgba(5, 7, 12, 0.85)" },
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
  const connectedNodeIds = useMemo(() => connectedTo(focusId, graph.edges), [focusId, graph.edges]);

  const elements = useMemo(() => {
    const rootId = graph.nodes[0]?.id ?? "";
    const positions = computeCardPositions(graph.nodes, graph.edges, rootId);

    const nodes: EntityCardNode[] = graph.nodes.map((node) => ({
      id: node.id,
      type: "entityCard",
      position: positions.get(node.id) ?? { x: 0, y: 0 },
      data: {
        kind: node.kind,
        content: buildCardContent(node, graph.edges, hostnameDiscovery),
        selected: node.id === selectedNodeId,
        dimmed: focusId !== null && !connectedNodeIds.has(node.id),
      },
    }));

    const edges: Edge[] = graph.edges.map((edge) => {
      const active = focusId !== null && (edge.source === focusId || edge.target === focusId);
      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.relationship,
        ...edgeStyle(active),
      };
    });

    return { nodes, edges };
  }, [graph, hostnameDiscovery, selectedNodeId, focusId, connectedNodeIds]);

  return (
    <div className="graph-canvas-container investigation-board">
      <GraphCanvas
        key={resetToken}
        initialNodes={elements.nodes}
        initialEdges={elements.edges}
        selectedNodeId={selectedNodeId}
        focusId={focusId}
        connectedNodeIds={connectedNodeIds}
        onSelectNode={onSelectNode}
        onHoverNode={onHoverNode}
      />
    </div>
  );
}

interface GraphCanvasProps {
  initialNodes: EntityCardNode[];
  initialEdges: Edge[];
  selectedNodeId: string | null;
  focusId: string | null;
  connectedNodeIds: Set<string>;
  onSelectNode: (id: string | null) => void;
  onHoverNode: (id: string | null) => void;
}

function GraphCanvas({
  initialNodes,
  initialEdges,
  selectedNodeId,
  focusId,
  connectedNodeIds,
  onSelectNode,
  onHoverNode,
}: GraphCanvasProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<EntityCardNode>(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(initialEdges);

  // Selection/hover changed without a reset (see the key-remount above) --
  // update each card/edge's visual state in place, never touching
  // position, so a dragged card stays exactly where the investigator put
  // it while hovering/selecting elsewhere.
  useEffect(() => {
    setNodes((current) =>
      current.map((node) => ({
        ...node,
        data: {
          ...node.data,
          selected: node.id === selectedNodeId,
          dimmed: focusId !== null && !connectedNodeIds.has(node.id),
        },
      }))
    );
    setEdges((current) =>
      current.map((edge) => {
        const active = focusId !== null && (edge.source === focusId || edge.target === focusId);
        return { ...edge, ...edgeStyle(active) };
      })
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedNodeId, focusId, connectedNodeIds]);

  return (
    <ReactFlow
      nodeTypes={nodeTypes}
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={(_event, node) => onSelectNode(node.id === selectedNodeId ? null : node.id)}
      onNodeMouseEnter={(_event, node) => onHoverNode(node.id)}
      onNodeMouseLeave={() => onHoverNode(null)}
      onPaneClick={() => onSelectNode(null)}
      elementsSelectable={false}
      nodesConnectable={false}
      fitView
      fitViewOptions={{ padding: 0.2, duration: 0 }}
      minZoom={0.1}
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
