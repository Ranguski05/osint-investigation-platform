import type { DnsCollection, DnsRecord } from "../types/dns";

interface RecordsPanelProps {
  collection: DnsCollection;
}

const RECORD_ORDER = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR", "DNSKEY", "DS"];

/**
 * Renders every DNS record grouped by type, in a format closer to how an
 * investigator reads a zone than raw JSON -- but every field the collector
 * produced is still shown somewhere here. Nothing is summarized away.
 */
export function RecordsPanel({ collection }: RecordsPanelProps) {
  const grouped = groupByType(collection.records);
  const orderedTypes = [
    ...RECORD_ORDER.filter((type) => grouped.has(type)),
    ...Array.from(grouped.keys()).filter((type) => !RECORD_ORDER.includes(type)),
  ];

  return (
    <section className="panel panel-scroll" aria-label="DNS records">
      <h2 className="panel-title">Records</h2>

      {orderedTypes.length === 0 && <p className="empty-state">No records were collected.</p>}

      {orderedTypes.map((type) => (
        <RecordGroup key={type} type={type} records={grouped.get(type)!} />
      ))}
    </section>
  );
}

function RecordGroup({ type, records }: { type: string; records: DnsRecord[] }) {
  return (
    <div className="record-group">
      <h3 className="record-group-title">
        {type} <span className="record-count">{records.length}</span>
      </h3>
      <ul className="record-list">
        {records.map((record, index) => (
          <RecordItem key={`${type}-${index}`} record={record} />
        ))}
      </ul>
    </div>
  );
}

function RecordItem({ record }: { record: DnsRecord }) {
  switch (record.type) {
    case "MX":
      return <MxRecordItem record={record} />;
    case "SOA":
      return <SoaRecordItem record={record} />;
    case "CAA":
      return <CaaRecordItem record={record} />;
    case "DNSKEY":
      return <DnskeyRecordItem record={record} />;
    case "DS":
      return <DsRecordItem record={record} />;
    case "TXT":
      // dnspython's to_text() already wraps TXT content in quotes
      // (e.g. `"v=spf1 -all"`), so the raw value is rendered as-is.
      return (
        <li className="record-item">
          <span className="record-name">{record.name}</span>
          <code className="record-value">{record.value}</code>
          <RecordMeta record={record} />
        </li>
      );
    default:
      return (
        <li className="record-item">
          <span className="record-name">{record.name}</span>
          <span className="record-value">{record.value}</span>
          <RecordMeta record={record} />
        </li>
      );
  }
}

function MxRecordItem({ record }: { record: DnsRecord }) {
  const priority = record.attributes.priority;
  const isNullMx = record.value === ".";

  return (
    <li className="record-item">
      <span className="record-name">{record.name}</span>
      {isNullMx ? (
        <span className="record-value record-value-muted">No mail service</span>
      ) : (
        <span className="record-value">{record.value}</span>
      )}
      <div className="record-attrs">
        {priority !== undefined && <span>Priority: {String(priority)}</span>}
        <RecordMeta record={record} inline />
      </div>
    </li>
  );
}

function SoaRecordItem({ record }: { record: DnsRecord }) {
  const attrs = record.attributes;

  return (
    <li className="record-item soa-record">
      <dl className="kv-list">
        <div className="kv-row">
          <dt>Primary server</dt>
          <dd>{record.value}</dd>
        </div>
        <div className="kv-row">
          <dt>RNAME</dt>
          <dd>{String(attrs.rname ?? "—")}</dd>
        </div>
        <div className="kv-row">
          <dt>Serial</dt>
          <dd>{String(attrs.serial ?? "—")}</dd>
        </div>
        <div className="kv-row">
          <dt>Refresh</dt>
          <dd>{String(attrs.refresh ?? "—")}</dd>
        </div>
        <div className="kv-row">
          <dt>Retry</dt>
          <dd>{String(attrs.retry ?? "—")}</dd>
        </div>
        <div className="kv-row">
          <dt>Expire</dt>
          <dd>{String(attrs.expire ?? "—")}</dd>
        </div>
        <div className="kv-row">
          <dt>Minimum</dt>
          <dd>{String(attrs.minimum ?? "—")}</dd>
        </div>
      </dl>
    </li>
  );
}

function CaaRecordItem({ record }: { record: DnsRecord }) {
  const attrs = record.attributes;

  return (
    <li className="record-item">
      <span className="record-name">{record.name}</span>
      <code className="record-value">{record.value}</code>
      <div className="record-attrs">
        <span>Tag: {String(attrs.tag ?? "—")}</span>
        <span>Flags: {String(attrs.flags ?? "—")}</span>
        <RecordMeta record={record} inline />
      </div>
    </li>
  );
}

function DnskeyRecordItem({ record }: { record: DnsRecord }) {
  const attrs = record.attributes;

  return (
    <li className="record-item">
      <span className="record-name">{record.name}</span>
      <div className="record-attrs">
        <span>Flags: {String(attrs.flags ?? "—")}</span>
        <span>Protocol: {String(attrs.protocol ?? "—")}</span>
        <span>Algorithm: {String(attrs.algorithm ?? "—")}</span>
        <RecordMeta record={record} inline />
      </div>
    </li>
  );
}

function DsRecordItem({ record }: { record: DnsRecord }) {
  const attrs = record.attributes;

  return (
    <li className="record-item">
      <span className="record-name">{record.name}</span>
      <div className="record-attrs">
        <span>Key tag: {String(attrs.key_tag ?? "—")}</span>
        <span>Algorithm: {String(attrs.algorithm ?? "—")}</span>
        <span>Digest type: {String(attrs.digest_type ?? "—")}</span>
        <RecordMeta record={record} inline />
      </div>
      {typeof attrs.digest === "string" && <code className="record-value">{attrs.digest}</code>}
    </li>
  );
}

function RecordMeta({ record, inline = false }: { record: DnsRecord; inline?: boolean }) {
  if (record.ttl === null) return null;
  return <span className={inline ? undefined : "record-ttl"}>TTL: {record.ttl}s</span>;
}

function groupByType(records: DnsRecord[]): Map<string, DnsRecord[]> {
  const map = new Map<string, DnsRecord[]>();
  for (const record of records) {
    const list = map.get(record.type) ?? [];
    list.push(record);
    map.set(record.type, list);
  }
  return map;
}
