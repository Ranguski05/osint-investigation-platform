import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import type { EntityKind } from "../../types/graph";
import { styleFor } from "../../styles/entityStyle";
import type { CardContent } from "./entityCardData";

export interface EntityCardData extends Record<string, unknown> {
  kind: EntityKind;
  content: CardContent;
  selected: boolean;
  dimmed: boolean;
}

export type EntityCardNode = Node<EntityCardData, "entityCard">;

/**
 * The investigation-board "card" representation of one entity -- the 2D
 * counterpart to the 3D graph's colored sphere. All displayed content
 * comes from `data.content`, already derived from the existing
 * GraphNode/GraphEdge shape by entityCardData.ts; this component only
 * renders it, it never reads collector data directly.
 *
 * Selection/dimming are driven entirely by the app's existing
 * selectedNodeId/hoveredNodeId state (passed in via data.selected/
 * data.dimmed -- see InvestigationGraph2D.tsx) rather than React Flow's
 * own built-in selection, so there is exactly one selection system
 * shared with the 3D view.
 */
export function EntityCard({ data }: NodeProps<EntityCardNode>) {
  const accentColor = styleFor(data.kind).color;
  const { content } = data;

  return (
    <div
      className={`entity-card${data.selected ? " entity-card-selected" : ""}${data.dimmed ? " entity-card-dimmed" : ""}`}
      style={{ borderColor: data.selected ? accentColor : undefined }}
    >
      <Handle type="target" position={Position.Top} className="entity-card-handle" />

      <div className="entity-card-accent" style={{ backgroundColor: accentColor }} />

      <div className="entity-card-body">
        <div className="entity-card-type">{content.typeLabel}</div>
        <div className="entity-card-value" title={content.primaryValue}>
          {content.primaryValue}
        </div>

        {content.fields.length > 0 && (
          <dl className="entity-card-fields">
            {content.fields.map((field) => (
              <div className="entity-card-field" key={field.label}>
                <dt>{field.label}</dt>
                <dd title={field.value}>{field.value}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="entity-card-handle" />
    </div>
  );
}
