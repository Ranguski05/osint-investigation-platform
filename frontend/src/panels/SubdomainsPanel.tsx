import { useMemo } from "react";
import type { DnsValidationStatus, SubdomainCollection } from "../types/subdomains";
import type { EntityKind, InvestigationGraph } from "../types/graph";
import { CollapsiblePanel } from "../components/CollapsiblePanel";
import { buildNodeIdIndex, resolveSubdomainNodeId } from "../data/graphLookup";
import { styleFor } from "../styles/entityStyle";

interface SubdomainsPanelProps {
  collection: SubdomainCollection;
  graph: InvestigationGraph;
  selectedNodeId: string | null;
  onSelectEntity: (nodeId: string) => void;
}

/**
 * Reuses the existing .panel/.record-list/.record-item CSS classes
 * verbatim -- no new styling needed for this panel.
 */
export function SubdomainsPanel({ collection, graph, selectedNodeId, onSelectEntity }: SubdomainsPanelProps) {
  const nodeIndex = useMemo(() => buildNodeIdIndex(graph), [graph]);
  const failedSources = collection.sources.filter((source) => source.status === "failed");

  // See RecordsPanel.tsx's identical comment -- reveals this panel when a
  // node selected elsewhere (e.g. directly in the graph) is one of its own.
  const matchedNodeId = useMemo(() => {
    if (!selectedNodeId) return null;
    for (const observation of collection.observations) {
      if (resolveSubdomainNodeId(observation.hostname, nodeIndex) === selectedNodeId) return selectedNodeId;
    }
    return null;
  }, [collection.observations, nodeIndex, selectedNodeId]);

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
      expandSignal={matchedNodeId}
    >
      {collection.observations.length === 0 && failedSources.length === 0 && (
        <p className="empty-state">No subdomains discovered.</p>
      )}

      {collection.observations.length > 0 && (
        <ul className="record-list">
          {collection.observations.map((observation) => {
            const nodeId = resolveSubdomainNodeId(observation.hostname, nodeIndex);
            const active = nodeId !== null && nodeId === selectedNodeId;
            const kind = nodeId ? (nodeId.slice(0, nodeId.indexOf(":")) as EntityKind) : null;
            return (
              <li
                className={`record-item${nodeId ? " record-item-interactive" : ""}${active ? " record-item-active" : ""}`}
                key={observation.hostname}
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
                <span className="record-value">{observation.hostname}</span>
                <span className="record-attrs">
                  <span>{uniqueSources(observation.discovery).join(", ")}</span>
                  <span>{dnsStatusLabel(observation.dns_status)}</span>
                  {observation.is_wildcard_match && <span>wildcard match</span>}
                </span>
              </li>
            );
          })}
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
