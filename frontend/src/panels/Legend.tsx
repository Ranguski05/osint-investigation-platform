import { ENTITY_STYLES } from "../styles/entityStyle";
import { CollapsiblePanel } from "../components/CollapsiblePanel";

/** Legend is generated from the same style map the graph renders with, so it can never drift out of sync. */
export function Legend() {
  return (
    <CollapsiblePanel title="Legend" ariaLabel="Legend" defaultExpanded={false}>
      <ul className="legend-list">
        {Object.entries(ENTITY_STYLES).map(([kind, style]) => (
          <li className="legend-row" key={kind}>
            <span className="legend-swatch" style={{ backgroundColor: style.color }} />
            <span>{style.label}</span>
          </li>
        ))}
      </ul>
    </CollapsiblePanel>
  );
}
