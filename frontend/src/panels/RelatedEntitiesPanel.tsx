import type { DnsCollection, EntityRelationship } from "../types/dns";

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
    <section className="panel panel-scroll" aria-label="Related entities">
      <h2 className="panel-title">Related Entities</h2>

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
    </section>
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
