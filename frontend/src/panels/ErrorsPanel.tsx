import type { DnsCollection } from "../types/dns";
import { CollapsiblePanel } from "../components/CollapsiblePanel";

interface ErrorsPanelProps {
  collection: DnsCollection;
}

/**
 * The per-error detail list, split out of OverviewPanel into its own
 * collapsible section -- Overview keeps only the "Errors: N" count for a
 * quick-glance summary, this panel holds the full list.
 */
export function ErrorsPanel({ collection }: ErrorsPanelProps) {
  return (
    <CollapsiblePanel title="Errors" ariaLabel="Collection errors" defaultExpanded={false} scroll>
      {collection.errors.length === 0 ? (
        <p className="empty-state">No errors were recorded.</p>
      ) : (
        <ul className="record-list error-list">
          {collection.errors.map((error, index) => (
            <li className="record-item" key={`${error.query_type}-${index}`}>
              <span className="record-name">
                {error.query_type ?? "target"} · {error.error_type}
              </span>
              <span className="record-value">{error.message}</span>
            </li>
          ))}
        </ul>
      )}
    </CollapsiblePanel>
  );
}
