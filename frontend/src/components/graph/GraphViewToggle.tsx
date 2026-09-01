export type GraphViewMode = "2d" | "3d";

interface GraphViewToggleProps {
  mode: GraphViewMode;
  onChange: (mode: GraphViewMode) => void;
}

/**
 * Compact segmented control for switching how the current investigation
 * graph is rendered. Purely a presentation choice -- both options read the
 * same merged InvestigationGraph (see DashboardBody in App.tsx); nothing
 * here knows about DNS/subdomain data.
 */
export function GraphViewToggle({ mode, onChange }: GraphViewToggleProps) {
  return (
    <div className="graph-view-toggle" role="group" aria-label="Graph view">
      {(["2d", "3d"] as const).map((option) => (
        <button
          key={option}
          type="button"
          className={`graph-view-toggle-option${mode === option ? " active" : ""}`}
          aria-pressed={mode === option}
          onClick={() => onChange(option)}
        >
          {option.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
