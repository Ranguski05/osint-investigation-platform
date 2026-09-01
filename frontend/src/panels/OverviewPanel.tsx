import type { DnsCollection } from "../types/dns";

interface OverviewPanelProps {
  collection: DnsCollection;
}

const STATUS_LABEL: Record<DnsCollection["status"], string> = {
  success: "Collection Successful",
  partial: "Partial Collection",
  failed: "Collection Failed",
};

export function OverviewPanel({ collection }: OverviewPanelProps) {
  const resolvers = uniqueResolvers(collection);

  return (
    <section className="panel" aria-label="Investigation overview">
      <h2 className="panel-title">Overview</h2>

      <dl className="kv-list">
        <div className="kv-row">
          <dt>Target</dt>
          <dd>{collection.target.value}</dd>
        </div>
        <div className="kv-row">
          <dt>Type</dt>
          <dd>{collection.target.type}</dd>
        </div>
        <div className="kv-row">
          <dt>Status</dt>
          <dd className={`status-badge status-${collection.status}`}>{STATUS_LABEL[collection.status]}</dd>
        </div>
        <div className="kv-row">
          <dt>Resolver(s)</dt>
          <dd>{resolvers.length > 0 ? resolvers.join(", ") : "—"}</dd>
        </div>
        <div className="kv-row">
          <dt>Observed at</dt>
          <dd>{collection.observed_at}</dd>
        </div>
        <div className="kv-row">
          <dt>Collector</dt>
          <dd>
            {collection.collector.name} v{collection.collector.version}
          </dd>
        </div>
        <div className="kv-row">
          <dt>Errors</dt>
          <dd>{collection.errors.length}</dd>
        </div>
        {collection.dnssec_signed !== null && (
          <div className="kv-row">
            <dt>DNSSEC</dt>
            <dd>{collection.dnssec_signed ? "Signed" : "Not signed"}</dd>
          </div>
        )}
      </dl>
    </section>
  );
}

function uniqueResolvers(collection: DnsCollection): string[] {
  const set = new Set<string>();
  for (const query of collection.queries) {
    if (query.resolver) set.add(query.resolver);
  }
  return Array.from(set);
}
