import { useMemo } from "react";
import type { CertificateCollection, CertificateObservation, CertificateValidityStatus } from "../types/certificates";
import type { EntityKind, InvestigationGraph } from "../types/graph";
import { CollapsiblePanel } from "../components/CollapsiblePanel";
import { buildNodeIdIndex, resolveCertificateNodeId } from "../data/graphLookup";
import { styleFor } from "../styles/entityStyle";

interface CertificatesPanelProps {
  collection: CertificateCollection;
  graph: InvestigationGraph;
  selectedNodeId: string | null;
  onSelectEntity: (nodeId: string) => void;
}

/**
 * Reuses the existing .panel/.record-list/.record-item CSS classes
 * verbatim -- no new styling needed for this panel, same approach as
 * SubdomainsPanel.tsx.
 */
export function CertificatesPanel({ collection, graph, selectedNodeId, onSelectEntity }: CertificatesPanelProps) {
  const nodeIndex = useMemo(() => buildNodeIdIndex(graph), [graph]);
  const failedSources = collection.sources.filter((source) => source.status === "failed");

  // See RecordsPanel.tsx's identical comment -- reveals this panel when a
  // node selected elsewhere (e.g. directly in the graph) is one of its own.
  const matchedNodeId = useMemo(() => {
    if (!selectedNodeId) return null;
    for (const certificate of collection.certificates) {
      if (resolveCertificateNodeId(certificate.certificate_id, nodeIndex) === selectedNodeId) return selectedNodeId;
    }
    return null;
  }, [collection.certificates, nodeIndex, selectedNodeId]);

  return (
    <CollapsiblePanel
      title={
        <>
          Certificates <span className="record-count">{collection.candidate_count}</span>
        </>
      }
      ariaLabel="Discovered certificates"
      defaultExpanded={false}
      scroll
      expandSignal={matchedNodeId}
    >
      {collection.certificates.length === 0 && failedSources.length === 0 && (
        <p className="empty-state">No certificates discovered.</p>
      )}

      {collection.certificates.length > 0 && (
        <ul className="record-list">
          {collection.certificates.map((certificate) => {
            const nodeId = resolveCertificateNodeId(certificate.certificate_id, nodeIndex);
            const active = nodeId !== null && nodeId === selectedNodeId;
            const kind = nodeId ? (nodeId.slice(0, nodeId.indexOf(":")) as EntityKind) : null;
            return (
              <li
                className={`record-item${nodeId ? " record-item-interactive" : ""}${active ? " record-item-active" : ""}`}
                key={certificate.certificate_id}
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
                <span className="record-value">{certificate.common_name ?? certificate.certificate_id}</span>
                <span className="record-attrs">
                  <span>{certificate.issuer ?? "unknown issuer"}</span>
                  <span>{validityRangeLabel(certificate)}</span>
                  <span>{validityStatusLabel(certificate.status)}</span>
                  <span>{certificate.sans.length} SAN{certificate.sans.length === 1 ? "" : "s"}</span>
                  {certificate.has_wildcard_san && <span>wildcard</span>}
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

function validityRangeLabel(certificate: CertificateObservation): string {
  const before = certificate.not_before?.slice(0, 10) ?? "?";
  const after = certificate.not_after?.slice(0, 10) ?? "?";
  return `${before} → ${after}`;
}

function validityStatusLabel(status: CertificateValidityStatus): string {
  switch (status) {
    case "current":
      return "current";
    case "expired":
      return "expired";
    case "not_yet_valid":
      return "not yet valid";
    default:
      return "unknown";
  }
}
