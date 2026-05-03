import type { Severity } from "../api.ts";

export function SeverityChip({ sev, count }: { sev: Severity; count?: number }): JSX.Element {
  const label = count != null ? `${count} ${sev}` : sev;
  return <span className={`chip chip-${sev}`}>{label}</span>;
}

export function SeverityCounts({ counts }: { counts: Record<Severity, number> }): JSX.Element {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const nonZero = order.filter((s) => counts[s] > 0);
  if (nonZero.length === 0) {
    return <span className="muted">no findings</span>;
  }
  return (
    <span className="chip-row">
      {nonZero.map((s) => <SeverityChip key={s} sev={s} count={counts[s]} />)}
    </span>
  );
}
