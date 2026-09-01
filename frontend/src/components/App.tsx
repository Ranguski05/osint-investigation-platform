import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiDataSource, FileDataSource, type InvestigationDataSource } from "../data/InvestigationDataSource";
import { SubdomainApiDataSource, type SubdomainDataSource } from "../data/SubdomainDataSource";
import { dnsToGraph } from "../data/dnsToGraph";
import { subdomainsToGraph } from "../data/subdomainsToGraph";
import { mergeGraphs } from "../data/mergeGraphs";
import type { DnsCollection } from "../types/dns";
import type { SubdomainCollection } from "../types/subdomains";
import { InvestigationGraph } from "./graph/InvestigationGraph";
import { TargetSearch } from "./TargetSearch";
import { StatusView } from "./StatusView";
import { InvestigationBanner } from "./InvestigationBanner";
import { OverviewPanel } from "../panels/OverviewPanel";
import { RecordsPanel } from "../panels/RecordsPanel";
import { RelatedEntitiesPanel } from "../panels/RelatedEntitiesPanel";
import { SubdomainsPanel } from "../panels/SubdomainsPanel";
import { ErrorsPanel } from "../panels/ErrorsPanel";
import { QueryPerformancePanel } from "../panels/QueryPerformancePanel";
import { Legend } from "../panels/Legend";
import { NodeInspector } from "../panels/NodeInspector";

// The initial page load always reads the saved fixture -- this keeps the
// offline/no-backend workflow from the original prototype working exactly
// as before. Investigating a new target from the search box goes through
// the local FastAPI dev server instead (see backend/main.py).
const fixtureSource: InvestigationDataSource = new FileDataSource("example-dns.json");
const apiSource: InvestigationDataSource = new ApiDataSource("http://localhost:8000/api");

// Subdomain enumeration is independent, optional graph enrichment (see
// collectors/subdomains) -- fetched alongside the DNS investigation, but
// its failure never affects the DNS investigation already on screen (no
// error banner for it; the graph and Subdomains panel simply don't gain
// the extra hostnames). Kept as a separate data source rather than
// bolted onto InvestigationDataSource, which is typed for DnsCollection.
const subdomainSource: SubdomainDataSource = new SubdomainApiDataSource("http://localhost:8000/api");

type Phase = "loading" | "investigating" | "error" | "idle";

interface AppState {
  phase: Phase;
  /** The most recently successful collection, kept on screen through later searches/errors so nothing disappears mid-investigation. */
  collection: DnsCollection | null;
  /** Target currently investigating, or the one that last failed. */
  pendingTarget: string | null;
  errorMessage: string | null;
}

export function App() {
  const [state, setState] = useState<AppState>({
    phase: "loading",
    collection: null,
    pendingTarget: null,
    errorMessage: null,
  });
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [resetToken, setResetToken] = useState(0);
  const [subdomainCollection, setSubdomainCollection] = useState<SubdomainCollection | null>(null);

  const fetchSubdomains = useCallback((target: string) => {
    subdomainSource
      .load(target)
      .then((collection) => setSubdomainCollection(collection))
      .catch((error: unknown) => {
        // Optional enrichment: log for debugging, but never surface an
        // error banner for this -- a subdomain-source outage must not
        // look like the DNS investigation itself failed.
        console.warn("Subdomain enumeration unavailable:", error);
        setSubdomainCollection(null);
      });
  }, []);

  useEffect(() => {
    let cancelled = false;

    // FileDataSource ignores its argument and always reads the fixture
    // file -- see InvestigationDataSource.ts. The value passed here is
    // never used, only shown if the load fails.
    fixtureSource
      .load("fixture")
      .then((collection) => {
        if (!cancelled) {
          setState({ phase: "idle", collection, pendingTarget: null, errorMessage: null });
          fetchSubdomains(collection.target.value);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            phase: "error",
            collection: null,
            pendingTarget: "example-dns.json",
            errorMessage: error instanceof Error ? error.message : "Failed to load investigation data.",
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [fetchSubdomains]);

  const handleInvestigate = useCallback(
    (target: string) => {
      // Deliberately keeps whatever collection is already on screen -- a new
      // search overlays a banner rather than blanking the existing graph.
      setState((prev) => ({ ...prev, phase: "investigating", pendingTarget: target, errorMessage: null }));
      setSubdomainCollection(null);

      apiSource
        .load(target)
        .then((collection) => {
          // A new investigation starts fresh: no stale selection, camera
          // re-fit to the new graph's actual bounds.
          setSelectedNodeId(null);
          setResetToken((token) => token + 1);
          setState({ phase: "idle", collection, pendingTarget: null, errorMessage: null });
          fetchSubdomains(target);
        })
        .catch((error: unknown) => {
          setState((prev) => ({
            ...prev,
            phase: "error",
            pendingTarget: target,
            errorMessage: error instanceof Error ? error.message : "Investigation failed.",
          }));
        });
    },
    [fetchSubdomains]
  );

  const dismissError = useCallback(() => {
    setState((prev) => ({ ...prev, phase: "idle", pendingTarget: null, errorMessage: null }));
  }, []);

  const isBusy = state.phase === "investigating";

  return (
    <div className="dashboard">
      <div className="dashboard-atmosphere" aria-hidden="true" />

      <header className="dashboard-header">
        <div className="dashboard-header-left">
          <h1>OSINT Investigation</h1>
          {state.collection && <span className="dashboard-target">{state.collection.target.value}</span>}
        </div>

        <div className="dashboard-header-right">
          <TargetSearch onInvestigate={handleInvestigate} disabled={isBusy} />
          {state.collection && (
            <span className={`status-badge status-${state.collection.status}`}>
              {state.collection.status.toUpperCase()}
            </span>
          )}
        </div>
      </header>

      {/* Nothing has ever loaded yet -- full-screen status, there's no dashboard to overlay onto. */}
      {!state.collection && state.phase === "loading" && <StatusView variant="loading" />}
      {!state.collection && state.phase === "error" && (
        <StatusView
          variant="error"
          target={state.pendingTarget ?? ""}
          message={state.errorMessage ?? "Unknown error."}
          onRetry={() => handleInvestigate(state.pendingTarget ?? "")}
        />
      )}

      {state.collection && (
        <DashboardBody
          collection={state.collection}
          subdomainCollection={subdomainCollection}
          selectedNodeId={selectedNodeId}
          hoveredNodeId={hoveredNodeId}
          onSelectNode={setSelectedNodeId}
          onHoverNode={setHoveredNodeId}
          resetToken={resetToken}
          onResetCamera={() => setResetToken((token) => token + 1)}
          banner={
            state.phase === "investigating" ? (
              <InvestigationBanner variant="investigating" target={state.pendingTarget ?? ""} />
            ) : state.phase === "error" ? (
              <InvestigationBanner
                variant="error"
                target={state.pendingTarget ?? ""}
                message={state.errorMessage ?? "Unknown error."}
                onRetry={() => handleInvestigate(state.pendingTarget ?? "")}
                onDismiss={dismissError}
              />
            ) : undefined
          }
        />
      )}
    </div>
  );
}

interface DashboardBodyProps {
  collection: DnsCollection;
  /** Optional -- subdomain enrichment loads independently and may not be ready/available yet (see fetchSubdomains). */
  subdomainCollection: SubdomainCollection | null;
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  onHoverNode: (id: string | null) => void;
  resetToken: number;
  onResetCamera: () => void;
  /** Investigating/error banner for a search in flight -- rendered over the graph, not replacing it. */
  banner?: ReactNode;
}

function DashboardBody({
  collection,
  subdomainCollection,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
  resetToken,
  onResetCamera,
  banner,
}: DashboardBodyProps) {
  // Recomputed only when either source collection changes, not on every
  // hover/select. dnsToGraph/subdomainsToGraph/mergeGraphs are pure and
  // collector-agnostic -- neither knows the other collector exists.
  const graph = useMemo(() => {
    const dnsGraph = dnsToGraph(collection);
    if (!subdomainCollection) return dnsGraph;
    return mergeGraphs([dnsGraph, subdomainsToGraph(subdomainCollection)]);
  }, [collection, subdomainCollection]);

  return (
    <main className="dashboard-body">
      <aside className="dashboard-column dashboard-column-left">
        <OverviewPanel collection={collection} />
        <QueryPerformancePanel collection={collection} />
      </aside>

      <div className="dashboard-graph">
        <div className="graph-controls">
          <button onClick={onResetCamera}>Reset view</button>
        </div>
        {banner}
        <InvestigationGraph
          graph={graph}
          selectedNodeId={selectedNodeId}
          hoveredNodeId={hoveredNodeId}
          onSelectNode={onSelectNode}
          onHoverNode={onHoverNode}
          resetToken={resetToken}
        />
        {selectedNodeId && (
          <NodeInspector graph={graph} selectedNodeId={selectedNodeId} onClose={() => onSelectNode(null)} />
        )}
      </div>

      <aside className="dashboard-column dashboard-column-right">
        <RecordsPanel collection={collection} />
        <RelatedEntitiesPanel collection={collection} />
        {subdomainCollection && <SubdomainsPanel collection={subdomainCollection} />}
        <ErrorsPanel collection={collection} />
        <Legend />
      </aside>
    </main>
  );
}
