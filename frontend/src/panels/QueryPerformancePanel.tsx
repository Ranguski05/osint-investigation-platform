import type { DnsCollection, DnsQueryMetadata } from "../types/dns";

interface QueryPerformancePanelProps {
  collection: DnsCollection;
}

const STATUS_COLOR: Record<DnsQueryMetadata["status"], string> = {
  success: "#4fd1a5",
  no_answer: "#8a92a6",
  nxdomain: "#f2a65a",
  timeout: "#ef6a6a",
  servfail: "#ef6a6a",
  refused: "#ef6a6a",
  error: "#ef6a6a",
};

/**
 * Small horizontal bar chart of query duration, meant to make slow
 * queries/resolver behavior visible at a glance -- not a general charting
 * component, so a hand-rolled bar is enough and avoids a charting
 * dependency for one chart type.
 */
export function QueryPerformancePanel({ collection }: QueryPerformancePanelProps) {
  const queries = collection.queries;
  const maxDuration = Math.max(1, ...queries.map((query) => query.duration_ms));

  return (
    <section className="panel panel-scroll" aria-label="Query performance">
      <h2 className="panel-title">Query Performance</h2>

      {queries.length === 0 && <p className="empty-state">No queries were recorded.</p>}

      <ul className="perf-list">
        {queries.map((query, index) => (
          <li className="perf-row" key={`${query.query_type}-${index}`}>
            <span className="perf-label" title={query.query_type}>
              {query.query_type}
            </span>
            <span className="perf-bar-track">
              <span
                className="perf-bar-fill"
                style={{
                  width: `${Math.max(2, (query.duration_ms / maxDuration) * 100)}%`,
                  backgroundColor: STATUS_COLOR[query.status],
                }}
              />
            </span>
            <span className="perf-value">{query.duration_ms.toFixed(1)} ms</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
