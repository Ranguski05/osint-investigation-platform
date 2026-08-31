import { useState, type FormEvent } from "react";

interface TargetSearchProps {
  onInvestigate: (target: string) => void;
  disabled: boolean;
}

/**
 * Header search box for investigating a new target without touching the
 * filesystem. Only submits a trimmed, non-empty value -- the collector
 * itself is responsible for deciding whether the target is a valid
 * domain/hostname/IP (see collectors/dns/utils.py:classify_target).
 */
export function TargetSearch({ onInvestigate, disabled }: TargetSearchProps) {
  const [value, setValue] = useState("");

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const target = value.trim();
    if (!target) return;
    onInvestigate(target);
  }

  return (
    <form className="target-search" onSubmit={handleSubmit}>
      <input
        type="text"
        className="target-search-input"
        placeholder="Investigate a domain, hostname, or IP"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        disabled={disabled}
        aria-label="Investigation target"
      />
      <button type="submit" className="target-search-button" disabled={disabled || !value.trim()}>
        Investigate
      </button>
    </form>
  );
}
