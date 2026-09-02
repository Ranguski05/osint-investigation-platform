import { useEffect, useState, type ReactNode } from "react";

interface CollapsiblePanelProps {
  title: ReactNode;
  ariaLabel: string;
  defaultExpanded: boolean;
  /** Applies the existing .panel-scroll class when expanded, matching the panels that already scrolled their own content. */
  scroll?: boolean;
  /**
   * Set (to the matched node's id, or any other non-null value) by a panel
   * that just discovered one of its own rows equals the graph's current
   * selection, so a node selected directly in the graph reveals its
   * sidebar row instead of silently expanding nothing. Changing to a new
   * value forces the panel open; never auto-collapses on its own.
   */
  expandSignal?: string | number | null;
  children: ReactNode;
}

/**
 * Shared collapsible wrapper for the right-column panels (Records,
 * Related Entities, Subdomains, Errors, Legend). Collapse state is local
 * to each mounted panel -- it resets on a fresh investigation along with
 * everything else in the dashboard, which matches how the rest of the
 * dashboard already treats a new search (see App.tsx's reset of
 * selectedNodeId/resetToken on a new collection).
 *
 * The body is always mounted (never conditionally removed) so the
 * expand/collapse can animate via a `grid-template-rows: 0fr -> 1fr`
 * transition (see .panel-body-wrapper in app.css) instead of snapping --
 * the standard no-JS-height-measurement accordion technique.
 */
export function CollapsiblePanel({
  title,
  ariaLabel,
  defaultExpanded,
  scroll,
  expandSignal,
  children,
}: CollapsiblePanelProps) {
  const [expanded, setExpanded] = useState(defaultExpanded);

  useEffect(() => {
    if (expandSignal !== undefined && expandSignal !== null) setExpanded(true);
    // Only forcing open, never closing -- expandSignal changing is always a
    // "make sure this is visible" request, not a toggle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expandSignal]);

  return (
    <section className={`panel${scroll && expanded ? " panel-scroll" : ""}`} aria-label={ariaLabel}>
      <button
        type="button"
        className="panel-header"
        onClick={() => setExpanded((value) => !value)}
        aria-expanded={expanded}
      >
        <h2 className="panel-title">{title}</h2>
        <span className="panel-toggle" aria-hidden="true">
          {expanded ? "▼" : "▶"}
        </span>
      </button>

      <div className={`panel-body-wrapper${expanded ? " panel-body-wrapper-expanded" : ""}`}>
        <div className="panel-body">{children}</div>
      </div>
    </section>
  );
}
