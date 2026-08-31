import { ENTITY_STYLES } from "../styles/entityStyle";

/** Legend is generated from the same style map the graph renders with, so it can never drift out of sync. */
export function Legend() {
  return (
    <section className="panel" aria-label="Legend">
      <h2 className="panel-title">Legend</h2>
      <ul className="legend-list">
        {Object.entries(ENTITY_STYLES).map(([kind, style]) => (
          <li className="legend-row" key={kind}>
            <span className="legend-swatch" style={{ backgroundColor: style.color }} />
            <span>{style.label}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
