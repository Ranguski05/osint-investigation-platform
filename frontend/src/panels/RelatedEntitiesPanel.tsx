import type { DnsCollection, EntityRelationship } from "../types/dns";
import { CollapsiblePanel } from "../components/CollapsiblePanel";

interface RelatedEntitiesPanelProps {
  collection: DnsCollection;
}

const GROUP_LABELS: Record<string, string> = {
  ip: "IPs",
  nameserver: "Nameservers",
  mail_server: "Mail Servers",
  hostname: "Hosts",
};

export function RelatedEntitiesPanel({ collection }: RelatedEntitiesPanelProps) {
  const grouped = groupByEntityType(collection.related_entities);
  const groupKeys = Array.from(grouped.keys());

  return (
    <CollapsiblePanel title="Related Entities" ariaLabel="Related entities" defaultExpanded={false} scroll>
      {groupKeys.length === 0 && <p className="empty-state">No related entities were discovered.</p>}

      {groupKeys.map((entityType) => (
        <div className="record-group" key={entityType}>
          <h3 className="record-group-title">
            {GROUP_LABELS[entityType] ?? entityType} <span className="record-count">{grouped.get(entityType)!.length}</span>
          </h3>
          <ul className="record-list">
            {grouped.get(entityType)!.map((entity, index) => (
              <li className="record-item" key={`${entityType}-${index}`}>
                <span className="record-value">{entity.value}</span>
                <span className="record-attrs">
                  <span>{entity.relationship}</span>
                  <span>via {entity.source_record}</span>
                </span>
              </li>
            ))}
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
