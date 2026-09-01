import type { DnsValidationStatus, SubdomainCollection } from "../types/subdomains";
import { CollapsiblePanel } from "../components/CollapsiblePanel";

interface SubdomainsPanelProps {
  collection: SubdomainCollection;
}

/**
 * Reuses the existing .panel/.record-list/.record-item CSS classes
 * verbatim -- no new styling needed for this panel.
 */
export function SubdomainsPanel({ collection }: SubdomainsPanelProps) {
  const failedSources = collection.sources.filter((source) => source.status === "failed");

  return (
    <CollapsiblePanel
      title={
        <>
          Subdomains <span className="record-count">{collection.candidate_count}</span>
        </>
      }
      ariaLabel="Discovered subdomains"
      defaultExpanded={false}
      scroll
    >
      {collection.observations.length === 0 && failedSources.length === 0 && (
        <p className="empty-state">No subdomains discovered.</p>
      )}

      {collection.observations.length > 0 && (
        <ul className="record-list">
          {collection.observations.map((observation) => (
            <li className="record-item" key={observation.hostname}>
              <span className="record-value">{observation.hostname}</span>
              <span className="record-attrs">
                <span>{uniqueSources(observation.discovery).join(", ")}</span>
                <span>{dnsStatusLabel(observation.dns_status)}</span>
                {observation.is_wildcard_match && <span>wildcard match</span>}
              </span>
            </li>
          ))}
        </ul>
      )}

      {failedSources.length > 0 && (
        <p className="empty-state">
          {failedSources.map((source) => `${source.source}: ${source.message}`).join("; ")}
        </p>
      )}
    </CollapsiblePanel>
  );
}

function uniqueSources(discovery: SubdomainCollection["observations"][number]["discovery"]): string[] {
  return Array.from(new Set(discovery.map((evidence) => evidence.source)));
}

function dnsStatusLabel(status: DnsValidationStatus): string {
  switch (status) {
    case "resolved":
      return "resolved";
    case "unresolved":
      return "unresolved";
    default:
      return "not checked";
  }
}
