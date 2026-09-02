import { useMemo } from "react";
import type { DnsCollection, EntityRelationship } from "../types/dns";
import type { EntityKind, InvestigationGraph } from "../types/graph";
import { CollapsiblePanel } from "../components/CollapsiblePanel";
import { buildNodeIdIndex, resolveRelatedEntityNodeId } from "../data/graphLookup";
import { styleFor } from "../styles/entityStyle";

interface RelatedEntitiesPanelProps {
  collection: DnsCollection;
  graph: InvestigationGraph;
  selectedNodeId: string | null;
  onSelectEntity: (nodeId: string) => void;
}

const GROUP_LABELS: Record<string, string> = {
  ip: "IPs",
  nameserver: "Nameservers",
  mail_server: "Mail Servers",
  hostname: "Hosts",
};

export function RelatedEntitiesPanel({ collection, graph, selectedNodeId, onSelectEntity }: RelatedEntitiesPanelProps) {
  const nodeIndex = useMemo(() => buildNodeIdIndex(graph), [graph]);
  const grouped = groupByEntityType(collection.related_entities);
  const groupKeys = Array.from(grouped.keys());

  // See RecordsPanel.tsx's identical comment -- reveals this panel when a
  // node selected elsewhere (e.g. directly in the graph) is one of its own.
  const matchedNodeId = useMemo(() => {
    if (!selectedNodeId) return null;
    for (const entity of collection.related_entities) {
      if (resolveRelatedEntityNodeId(entity, nodeIndex) === selectedNodeId) return selectedNodeId;
    }
    return null;
  }, [collection.related_entities, nodeIndex, selectedNodeId]);

  return (
    <CollapsiblePanel title="Related Entities" ariaLabel="Related entities" defaultExpanded={false} scroll expandSignal={matchedNodeId}>
      {groupKeys.length === 0 && <p className="empty-state">No related entities were discovered.</p>}

      {groupKeys.map((entityType) => (
        <div className="record-group" key={entityType}>
          <h3 className="record-group-title">
            {GROUP_LABELS[entityType] ?? entityType} <span className="record-count">{grouped.get(entityType)!.length}</span>
          </h3>
          <ul className="record-list">
            {grouped.get(entityType)!.map((entity, index) => {
              const nodeId = resolveRelatedEntityNodeId(entity, nodeIndex);
              const active = nodeId !== null && nodeId === selectedNodeId;
              const kind = nodeId ? (nodeId.slice(0, nodeId.indexOf(":")) as EntityKind) : null;
              return (
                <li
                  className={`record-item${nodeId ? " record-item-interactive" : ""}${active ? " record-item-active" : ""}`}
                  key={`${entityType}-${index}`}
                  role={nodeId ? "button" : undefined}
                  tabIndex={nodeId ? 0 : undefined}
                  data-node-id={nodeId ?? undefined}
                  onClick={nodeId ? () => onSelectEntity(nodeId) : undefined}
                  onKeyDown={
                    nodeId
                      ? (event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            onSelectEntity(nodeId);
                          }
                        }
                      : undefined
                  }
                >
                  {kind && <span className="record-item-swatch" style={{ backgroundColor: styleFor(kind).color }} aria-hidden="true" />}
                  <span className="record-value">{entity.value}</span>
                  <span className="record-attrs">
                    <span>{entity.relationship}</span>
                    <span>via {entity.source_record}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </CollapsiblePanel>
  );
}

function groupByEntityType(entities: EntityRelationship[]): Map<string, EntityRelationship[]> {
  const map = new Map<string, EntityRelationship[]>();
  for (const entity of entities) {
    const list = map.get(entity.entity_type) ?? [];
    list.push(entity);
    map.set(entity.entity_type, list);
  }
  return map;
}
