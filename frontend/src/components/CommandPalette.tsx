import { useEffect, useMemo, useRef, useState } from "react";

export interface Command {
  id: string;
  group: string;
  label: string;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  commands: Command[];
}

/**
 * Small Ctrl/Cmd+K command palette -- an aggregator over actions that
 * already exist as callbacks in DashboardBody (reset view, 2D/3D switch,
 * panel toggle, entity filter, header-nav jumps), not new functionality.
 * Deliberately does not include "Investigate a new target": the search box
 * is already always visible in the header, so a command that only focuses
 * it would save nothing.
 */
export function CommandPalette({ open, onClose, commands }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((command) => command.label.toLowerCase().includes(q) || command.group.toLowerCase().includes(q));
  }, [commands, query]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActiveIndex(0);
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [open]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  if (!open) return null;

  function runCommand(command: Command | undefined) {
    if (!command) return;
    command.run();
    onClose();
  }

  return (
    <div className="command-palette-backdrop" onClick={onClose}>
      <div
        className="command-palette"
        role="dialog"
        aria-label="Command palette"
        onClick={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            onClose();
          } else if (event.key === "ArrowDown") {
            event.preventDefault();
            setActiveIndex((index) => Math.min(index + 1, filtered.length - 1));
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            setActiveIndex((index) => Math.max(index - 1, 0));
          } else if (event.key === "Enter") {
            event.preventDefault();
            runCommand(filtered[activeIndex]);
          }
        }}
      >
        <input
          ref={inputRef}
          type="text"
          className="command-palette-input"
          placeholder="Type a command..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Command search"
        />
        <ul className="command-palette-list">
          {filtered.length === 0 && <li className="command-palette-empty">No matching commands.</li>}
          {filtered.map((command, index) => (
            <li
              key={command.id}
              className={`command-palette-item${index === activeIndex ? " active" : ""}`}
              onMouseEnter={() => setActiveIndex(index)}
              onClick={() => runCommand(command)}
            >
              <span className="command-palette-item-group">{command.group}</span>
              <span>{command.label}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
