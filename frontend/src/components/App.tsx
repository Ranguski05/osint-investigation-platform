import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiDataSource, FileDataSource, type InvestigationDataSource } from "../data/InvestigationDataSource";
import { SubdomainApiDataSource, type SubdomainDataSource } from "../data/SubdomainDataSource";
import { CertificateApiDataSource, type CertificateDataSource } from "../data/CertificateDataSource";
import { dnsToGraph } from "../data/dnsToGraph";
import { subdomainsToGraph } from "../data/subdomainsToGraph";
import { certificatesToGraph } from "../data/certificatesToGraph";
import { mergeGraphs } from "../data/mergeGraphs";
import type { DnsCollection } from "../types/dns";
import type { SubdomainCollection } from "../types/subdomains";
import type { CertificateCollection } from "../types/certificates";
import { filterGraphByEntityKind, countNodesByKind, type EntityFilterValue } from "../data/filterGraph";
import { InvestigationGraph } from "./graph/InvestigationGraph";
import { InvestigationGraph2D } from "./graph/InvestigationGraph2D";
import { GraphViewToggle, type GraphViewMode } from "./graph/GraphViewToggle";
import { EntityTypeFilter } from "./graph/EntityTypeFilter";
import { TargetSearch } from "./TargetSearch";
import { StatusView } from "./StatusView";
import { InvestigationBanner } from "./InvestigationBanner";
import { SidebarEdgeToggle } from "./SidebarEdgeToggle";
import { OverviewPanel } from "../panels/OverviewPanel";
import { RecordsPanel } from "../panels/RecordsPanel";
import { RelatedEntitiesPanel } from "../panels/RelatedEntitiesPanel";
import { SubdomainsPanel } from "../panels/SubdomainsPanel";
import { CertificatesPanel } from "../panels/CertificatesPanel";
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

// Certificate intelligence is the same kind of independent, optional graph
// enrichment as subdomain enumeration above -- fetched alongside the DNS
// investigation, never blocking or failing it (see fetchCertificates).
const certificateSource: CertificateDataSource = new CertificateApiDataSource("http://localhost:8000/api");

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
  const [certificateCollection, setCertificateCollection] = useState<CertificateCollection | null>(null);

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

  const fetchCertificates = useCallback((target: string) => {
    certificateSource
      .load(target)
      .then((collection) => setCertificateCollection(collection))
      .catch((error: unknown) => {
        // Same treatment as fetchSubdomains: optional enrichment, never
        // an error banner for the DNS investigation already on screen.
        // A structurally-failed CertificateCollection (e.g. crt.sh down)
        // is still a successful fetch and is handled by
        // certificatesToGraph/CertificatesPanel, not here.
        console.warn("Certificate intelligence unavailable:", error);
        setCertificateCollection(null);
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
          fetchCertificates(collection.target.value);
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
  }, [fetchSubdomains, fetchCertificates]);

  const handleInvestigate = useCallback(
    (target: string) => {
      // Deliberately keeps whatever collection is already on screen -- a new
      // search overlays a banner rather than blanking the existing graph.
      setState((prev) => ({ ...prev, phase: "investigating", pendingTarget: target, errorMessage: null }));
      setSubdomainCollection(null);
      setCertificateCollection(null);

      apiSource
        .load(target)
        .then((collection) => {
          // A new investigation starts fresh: no stale selection, camera
          // re-fit to the new graph's actual bounds.
          setSelectedNodeId(null);
          setResetToken((token) => token + 1);
          setState({ phase: "idle", collection, pendingTarget: null, errorMessage: null });
          fetchSubdomains(target);
          fetchCertificates(target);
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
    [fetchSubdomains, fetchCertificates]
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
          certificateCollection={certificateCollection}
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
  /** Optional -- certificate enrichment loads independently and may not be ready/available yet (see fetchCertificates). */
  certificateCollection: CertificateCollection | null;
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
  certificateCollection,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
  resetToken,
  onResetCamera,
  banner,
}: DashboardBodyProps) {
  // Recomputed only when a source collection changes, not on every
  // hover/select. dnsToGraph/subdomainsToGraph/certificatesToGraph/
  // mergeGraphs are pure and collector-agnostic -- none of them knows
  // any other collector exists. Both the 2D and 3D representations
  // render this exact same merged graph (see InvestigationGraph.tsx /
  // InvestigationGraph2D.tsx) -- the toggle below only changes which one
  // is mounted, never what data either sees.
  const graph = useMemo(() => {
    const graphs = [dnsToGraph(collection)];
    if (subdomainCollection) graphs.push(subdomainsToGraph(subdomainCollection));
    if (certificateCollection) graphs.push(certificatesToGraph(certificateCollection));
    return graphs.length === 1 ? graphs[0] : mergeGraphs(graphs);
  }, [collection, subdomainCollection, certificateCollection]);

  // Local to the dashboard body (not lifted to App) since it's a pure view
  // preference, not investigation state -- it deliberately does NOT reset
  // on a new search, unlike selectedNodeId/resetToken above.
  const [viewMode, setViewMode] = useState<GraphViewMode>("3d");

  const handleViewModeChange = useCallback(
    (mode: GraphViewMode) => {
      setViewMode(mode);
      // A hover highlight from the previous representation wouldn't
      // correspond to any real pointer position in the new one -- the
      // selected node (and Node Inspector) deliberately survive the
      // switch, only the transient hover state is cleared.
      onHoverNode(null);
    },
    [onHoverNode]
  );

  // Also a pure view preference (same reasoning as viewMode above), and
  // deliberately shared by both representations: this is the ONE piece of
  // filter state, applied to `graph` below to derive what 2D and 3D each
  // render, rather than each representation tracking its own copy.
  const [entityFilter, setEntityFilter] = useState<EntityFilterValue>("all");

  // Sidebar visibility is a pure layout preference, same category as
  // viewMode/entityFilter above -- local to the dashboard body, and
  // deliberately does not reset on a new search. Both start open (the
  // dashboard's existing default), so a collapse is always something the
  // investigator does deliberately, not a surprise on first load. Panel
  // content itself is never unmounted on collapse (see the JSX below) --
  // only hidden via CSS -- so each CollapsiblePanel's own expand/collapse
  // state and scroll position survive a sidebar collapse/reopen.
  const [leftCollapsed, setLeftCollapsed] = useState(false);
  const [rightCollapsed, setRightCollapsed] = useState(false);

  const entityCounts = useMemo(() => countNodesByKind(graph), [graph]);

  // Presentation-only narrowing of the already-merged graph -- see
  // filterGraph.ts. `graph` itself (the full merged DNS + subdomain data)
  // is never mutated or recomputed here; 2D and 3D both render whatever
  // this produces, so the filter can never drift between representations.
  const visibleGraph = useMemo(() => filterGraphByEntityKind(graph, entityFilter), [graph, entityFilter]);

  const visibleNodeIds = useMemo(() => new Set(visibleGraph.nodes.map((node) => node.id)), [visibleGraph]);

  // A selected/hovered node that the current filter hides simply isn't
  // rendered -- selectedNodeId/hoveredNodeId themselves are left alone, so
  // the Node Inspector cleanly disappears instead of showing a node that
  // isn't on screen, and the exact same selection reappears automatically
  // if the investigator switches back to a filter that includes it again.
  const effectiveSelectedNodeId = selectedNodeId && visibleNodeIds.has(selectedNodeId) ? selectedNodeId : null;
  const effectiveHoveredNodeId = hoveredNodeId && visibleNodeIds.has(hoveredNodeId) ? hoveredNodeId : null;

  return (
    <main
      className={`dashboard-body${leftCollapsed ? " left-collapsed" : ""}${rightCollapsed ? " right-collapsed" : ""}`}
    >
      <aside className={`dashboard-column dashboard-column-left${leftCollapsed ? " dashboard-column-collapsed" : ""}`}>
        <OverviewPanel collection={collection} />
        <QueryPerformancePanel collection={collection} />
      </aside>

      <div className="dashboard-graph">
        <SidebarEdgeToggle
          side="left"
          collapsed={leftCollapsed}
          onToggle={() => setLeftCollapsed((value) => !value)}
          label={leftCollapsed ? "Show overview panel" : "Hide overview panel"}
        />
        <SidebarEdgeToggle
          side="right"
          collapsed={rightCollapsed}
          onToggle={() => setRightCollapsed((value) => !value)}
          label={rightCollapsed ? "Show records panel" : "Hide records panel"}
        />
        <div className="graph-controls">
          <button onClick={onResetCamera}>Reset view</button>
        </div>
        <div className="graph-toolbar">
          <EntityTypeFilter
            value={entityFilter}
            onChange={setEntityFilter}
            counts={entityCounts}
            totalCount={graph.nodes.length}
          />
          <GraphViewToggle mode={viewMode} onChange={handleViewModeChange} />
        </div>
        {banner}
        {viewMode === "3d" ? (
          <InvestigationGraph
            graph={visibleGraph}
            selectedNodeId={effectiveSelectedNodeId}
            hoveredNodeId={effectiveHoveredNodeId}
            onSelectNode={onSelectNode}
            onHoverNode={onHoverNode}
            resetToken={resetToken}
          />
        ) : (
          <InvestigationGraph2D
            graph={visibleGraph}
            subdomainCollection={subdomainCollection}
            selectedNodeId={effectiveSelectedNodeId}
            hoveredNodeId={effectiveHoveredNodeId}
            onSelectNode={onSelectNode}
            onHoverNode={onHoverNode}
            resetToken={resetToken}
          />
        )}
        {effectiveSelectedNodeId && (
          <NodeInspector graph={graph} selectedNodeId={effectiveSelectedNodeId} onClose={() => onSelectNode(null)} />
        )}
      </div>

      <aside
        className={`dashboard-column dashboard-column-right${rightCollapsed ? " dashboard-column-collapsed" : ""}`}
      >
        <RecordsPanel collection={collection} />
        <RelatedEntitiesPanel collection={collection} />
        {subdomainCollection && <SubdomainsPanel collection={subdomainCollection} />}
        {certificateCollection && <CertificatesPanel collection={certificateCollection} />}
        <ErrorsPanel collection={collection} />
        <Legend />
      </aside>
    </main>
  );
}
