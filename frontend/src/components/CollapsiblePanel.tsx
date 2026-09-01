import { useState, type ReactNode } from "react";

interface CollapsiblePanelProps {
  title: ReactNode;
  ariaLabel: string;
  defaultExpanded: boolean;
  /** Applies the existing .panel-scroll class when expanded, matching the panels that already scrolled their own content. */
  scroll?: boolean;
  children: ReactNode;
}

/**
 * Shared collapsible wrapper for the right-column panels (Records,
 * Related Entities, Subdomains, Errors, Legend). Collapse state is local
 * to each mounted panel -- it resets on a fresh investigation along with
 * everything else in the dashboard, which matches how the rest of the
 * dashboard already treats a new search (see App.tsx's reset of
 * selectedNodeId/resetToken on a new collection).
 */
export function CollapsiblePanel({ title, ariaLabel, defaultExpanded, scroll, children }: CollapsiblePanelProps) {
  const [expanded, setExpanded] = useState(defaultExpanded);

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

      {expanded && <div className="panel-body">{children}</div>}
    </section>
  );
}
