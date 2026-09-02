interface SidebarEdgeToggleProps {
  side: "left" | "right";
  collapsed: boolean;
  onToggle: () => void;
  label: string;
}

/**
 * Small edge-mounted tab for collapsing/reopening a dashboard sidebar.
 * Lives at the graph viewport's own left/right edge (see .dashboard-graph
 * in app.css), not the sidebar itself, so its position never needs to
 * track the sidebar's animated width -- it's always exactly where the
 * sidebar/graph boundary currently is.
 */
export function SidebarEdgeToggle({ side, collapsed, onToggle, label }: SidebarEdgeToggleProps) {
  // The chevron always points in the direction the panel will move: left
  // sidebar collapses toward the left edge, right sidebar toward the right.
  const pointsRight = side === "left" ? collapsed : !collapsed;

  return (
    <button
      type="button"
      className={`sidebar-edge-toggle sidebar-edge-toggle-${side}`}
      onClick={onToggle}
      aria-label={label}
      aria-expanded={!collapsed}
    >
      <span className="sidebar-edge-toggle-chevron" aria-hidden="true">
        {pointsRight ? "›" : "‹"}
      </span>
    </button>
  );
}
