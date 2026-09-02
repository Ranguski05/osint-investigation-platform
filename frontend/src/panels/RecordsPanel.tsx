import { useMemo, useState, type ReactNode } from "react";
import type { DnsCollection, DnsRecord } from "../types/dns";
import type { EntityKind, InvestigationGraph } from "../types/graph";
import { CollapsiblePanel } from "../components/CollapsiblePanel";
import { buildNodeIdIndex, resolveRecordNodeId, type NodeIdIndex } from "../data/graphLookup";
import { styleFor } from "../styles/entityStyle";

interface RecordsPanelProps {
  collection: DnsCollection;
  /** The full merged investigation graph -- used only to resolve which record rows correspond to a real graph node (see graphLookup.ts). Never re-derives or duplicates graph-building logic. */
  graph: InvestigationGraph;
  selectedNodeId: string | null;
  onSelectEntity: (nodeId: string) => void;
}

const RECORD_ORDER = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR", "DNSKEY", "DS"];
const ALL_TYPES = "all";

/**
 * Renders every DNS record grouped by type, in a format closer to how an
 * investigator reads a zone than raw JSON -- but every field the collector
 * produced is still shown somewhere here. Nothing is summarized away.
 *
 * The type filter and search box only narrow which of those records are
 * displayed -- they never change what was collected or how it's grouped.
 * Search matches a record's own displayed value only (not TTL/attributes).
 */
export function RecordsPanel({ collection, graph, selectedNodeId, onSelectEntity }: RecordsPanelProps) {
  const [selectedType, setSelectedType] = useState(ALL_TYPES);
  const [searchTerm, setSearchTerm] = useState("");

  const nodeIndex = useMemo(() => buildNodeIdIndex(graph), [graph]);

  // Reveals this panel (see CollapsiblePanel's expandSignal) when the
  // graph's current selection is one of THIS panel's own rows -- so
  // selecting a record's entity directly in the graph, not just from here,
  // still surfaces it if the panel happens to be collapsed.
  const matchedNodeId = useMemo(() => {
    if (!selectedNodeId) return null;
    for (const record of collection.records) {
      if (resolveRecordNodeId(record, nodeIndex) === selectedNodeId) return selectedNodeId;
    }
    return null;
  }, [collection.records, nodeIndex, selectedNodeId]);

  const grouped = groupByType(collection.records);
  const orderedTypes = [
    ...RECORD_ORDER.filter((type) => grouped.has(type)),
    ...Array.from(grouped.keys()).filter((type) => !RECORD_ORDER.includes(type)),
  ];

  const visibleTypes = selectedType === ALL_TYPES ? orderedTypes : orderedTypes.filter((type) => type === selectedType);
  const normalizedSearch = searchTerm.trim().toLowerCase();

  const filteredGroups = visibleTypes
    .map((type) => ({
      type,
      records: normalizedSearch
        ? grouped.get(type)!.filter((record) => record.value.toLowerCase().includes(normalizedSearch))
        : grouped.get(type)!,
    }))
    .filter((group) => group.records.length > 0);

  return (
    <CollapsiblePanel title="Records" ariaLabel="DNS records" defaultExpanded scroll expandSignal={matchedNodeId}>
      {orderedTypes.length === 0 ? (
        <p className="empty-state">No records were collected.</p>
      ) : (
        <>
          <div className="records-filters">
            <select
              className="records-type-select"
              value={selectedType}
              onChange={(event) => setSelectedType(event.target.value)}
              aria-label="Filter by record type"
            >
              <option value={ALL_TYPES}>All Records</option>
              {orderedTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
            <input
              type="text"
              className="records-search-input"
              placeholder="Search records..."
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              aria-label="Search records"
            />
          </div>

          {filteredGroups.length === 0 && <p className="empty-state">No records match your filters.</p>}

          {filteredGroups.map(({ type, records }) => (
            <RecordGroup
              key={type}
              type={type}
              records={records}
              nodeIndex={nodeIndex}
              selectedNodeId={selectedNodeId}
              onSelectEntity={onSelectEntity}
            />
          ))}
        </>
      )}
    </CollapsiblePanel>
  );
}

interface RecordRowProps {
  nodeIndex: NodeIdIndex;
  selectedNodeId: string | null;
  onSelectEntity: (nodeId: string) => void;
}

function RecordGroup({
  type,
  records,
  nodeIndex,
  selectedNodeId,
  onSelectEntity,
}: { type: string; records: DnsRecord[] } & RecordRowProps) {
  return (
    <div className="record-group">
      <h3 className="record-group-title">
        {type} <span className="record-count">{records.length}</span>
      </h3>
      <ul className="record-list">
        {records.map((record, index) => (
          <RecordItem
            key={`${type}-${index}`}
            record={record}
            nodeIndex={nodeIndex}
            selectedNodeId={selectedNodeId}
            onSelectEntity={onSelectEntity}
          />
        ))}
      </ul>
    </div>
  );
}

function RecordItem({ record, nodeIndex, selectedNodeId, onSelectEntity }: { record: DnsRecord } & RecordRowProps) {
  const nodeId = resolveRecordNodeId(record, nodeIndex);

  switch (record.type) {
    case "MX":
      return (
        <MxRecordItem record={record} nodeIndex={nodeIndex} selectedNodeId={selectedNodeId} onSelectEntity={onSelectEntity} />
      );
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
        <EntityRow nodeId={nodeId} selectedNodeId={selectedNodeId} onSelectEntity={onSelectEntity}>
          <span className="record-name">{record.name}</span>
          <code className="record-value">{record.value}</code>
          <RecordMeta record={record} />
        </EntityRow>
      );
    default:
      return (
        <EntityRow nodeId={nodeId} selectedNodeId={selectedNodeId} onSelectEntity={onSelectEntity}>
          <span className="record-name">{record.name}</span>
          <span className="record-value">{record.value}</span>
          <RecordMeta record={record} />
        </EntityRow>
      );
  }
}

/**
 * Shared clickable-row wrapper: renders a plain `<li>` when the record has
 * no corresponding graph node (SOA/CAA/DNSKEY/DS, or a null MX) -- an
 * honest reflection of the data model, not a missing feature -- and an
 * interactive `<li>` with click-to-select + active-state highlighting when
 * it does. See graphLookup.ts for how nodeId is resolved.
 */
function EntityRow({
  nodeId,
  selectedNodeId,
  onSelectEntity,
  children,
}: {
  nodeId: string | null;
  selectedNodeId: string | null;
  onSelectEntity: (nodeId: string) => void;
  children: ReactNode;
}) {
  if (!nodeId) {
    return <li className="record-item">{children}</li>;
  }

  const active = nodeId === selectedNodeId;
  // The id's own `${kind}:${value}` prefix names its entity kind (see
  // graphLookup.ts) -- reused directly rather than looking the node back up
  // in the graph, so the row's swatch always matches the exact color the
  // graph renders that kind in.
  const kind = nodeId.slice(0, nodeId.indexOf(":")) as EntityKind;

  return (
    <li
      className={`record-item record-item-interactive${active ? " record-item-active" : ""}`}
      role="button"
      tabIndex={0}
      data-node-id={nodeId}
      onClick={() => onSelectEntity(nodeId)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelectEntity(nodeId);
        }
      }}
    >
      <span className="record-item-swatch" style={{ backgroundColor: styleFor(kind).color }} aria-hidden="true" />
      {children}
    </li>
  );
}

function MxRecordItem({ record, nodeIndex, selectedNodeId, onSelectEntity }: { record: DnsRecord } & RecordRowProps) {
  const priority = record.attributes.priority;
  const isNullMx = record.value === ".";
  const nodeId = resolveRecordNodeId(record, nodeIndex);

  return (
    <EntityRow nodeId={nodeId} selectedNodeId={selectedNodeId} onSelectEntity={onSelectEntity}>
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
    </EntityRow>
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
