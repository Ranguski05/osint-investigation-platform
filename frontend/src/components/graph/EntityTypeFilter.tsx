import type { EntityKind } from "../../types/graph";
import type { EntityFilterValue } from "../../data/filterGraph";
import { ENTITY_STYLES, styleFor } from "../../styles/entityStyle";

// Same canonical order Legend.tsx already iterates ENTITY_STYLES in, so the
// dropdown, the legend, and the graph's own colors never drift apart.
const KIND_ORDER = Object.keys(ENTITY_STYLES) as EntityKind[];

interface EntityTypeFilterProps {
  value: EntityFilterValue;
  onChange: (value: EntityFilterValue) => void;
  /** Node count per kind in the *current* (unfiltered) graph -- determines which options are offered at all. */
  counts: Partial<Record<EntityKind, number>>;
  totalCount: number;
}

/**
 * Compact dropdown restricting the graph (2D and 3D alike) to a single
 * entity kind at a time. Only offers kinds that actually have at least one
 * node in the current investigation, so switching targets never leaves
 * stale options like "Certificate" sitting in the list with nothing behind
 * them. Purely a view preference -- see filterGraph.ts for how the
 * selection turns into an actual filtered graph.
 */
export function EntityTypeFilter({ value, onChange, counts, totalCount }: EntityTypeFilterProps) {
  const availableKinds = KIND_ORDER.filter((kind) => (counts[kind] ?? 0) > 0);

  return (
    <select
      className="entity-type-filter"
      aria-label="Entity type filter"
      value={value}
      onChange={(event) => onChange(event.target.value as EntityFilterValue)}
    >
      <option value="all">All Entities ({totalCount})</option>
      {availableKinds.map((kind) => (
        <option key={kind} value={kind}>
          {styleFor(kind).label} ({counts[kind]})
        </option>
      ))}
    </select>
  );
}
