import type { InvestigationGraph } from "../types/graph";
import { styleFor } from "../styles/entityStyle";

interface NodeInspectorProps {
  graph: InvestigationGraph;
  selectedNodeId: string;
  onClose: () => void;
}

/** Shown when a node is selected in the 3D graph -- surfaces its edges without leaving the graph view. */
export function NodeInspector({ graph, selectedNodeId, onClose }: NodeInspectorProps) {
  const node = graph.nodes.find((candidate) => candidate.id === selectedNodeId);
  if (!node) return null;

  const connections = graph.edges
    .filter((edge) => edge.source === selectedNodeId || edge.target === selectedNodeId)
    .map((edge) => {
      const outgoing = edge.source === selectedNodeId;
      const otherId = outgoing ? edge.target : edge.source;
      const otherNode = graph.nodes.find((candidate) => candidate.id === otherId);
      return { edge, outgoing, otherNode };
    });

  return (
    <div className="node-inspector">
      <button className="node-inspector-close" onClick={onClose} aria-label="Close">
        ×
      </button>
      <div className="node-inspector-header">
        <span className="legend-swatch" style={{ backgroundColor: styleFor(node.kind).color }} />
        <div>
          <div className="node-inspector-label">{node.label}</div>
          <div className="node-inspector-kind">{styleFor(node.kind).label}</div>
        </div>
      </div>

      {connections.length > 0 && (
        <ul className="record-list">
          {connections.map(({ edge, outgoing, otherNode }) => (
            <li className="record-item" key={edge.id}>
              <span className="record-attrs">
                <span>{edge.relationship}</span>
                <span>{outgoing ? "→" : "←"}</span>
                <span>{otherNode?.label ?? "?"}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
