import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, SEVERITIES, type FindingsRollup, type Severity } from "../api.ts";
import { SeverityChip } from "../components/SeverityChip.tsx";

export function Findings(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState<FindingsRollup | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sevSet = useMemo(
    () => new Set<Severity>(
      (params.get("severity") ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter((s): s is Severity => SEVERITIES.includes(s as Severity)),
    ),
    [params],
  );

  const category = params.get("category")?.trim() ?? "";

  useEffect(() => {
    setData(null);
    setError(null);
    api.findings({
      severity: sevSet.size > 0 ? Array.from(sevSet) : undefined,
      category: category ? [category] : undefined,
    })
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [sevSet, category]);

  function toggleSeverity(s: Severity): void {
    const next = new Set(sevSet);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    const newParams = new URLSearchParams(params);
    if (next.size === 0) newParams.delete("severity");
    else newParams.set("severity", Array.from(next).join(","));
    setParams(newParams, { replace: true });
  }

  function setCategory(value: string): void {
    const newParams = new URLSearchParams(params);
    if (value) newParams.set("category", value);
    else newParams.delete("category");
    setParams(newParams, { replace: true });
  }

  return (
    <div className="findings-page">
      <h2>All findings</h2>
      <div className="filters">
        <div className="filter-group">
          <span className="filter-label">Severity:</span>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              className={`chip chip-${s} ${sevSet.has(s) ? "chip-active" : "chip-inactive"}`}
              onClick={() => toggleSeverity(s)}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="filter-group">
          <label className="filter-label" htmlFor="cat-filter">Category:</label>
          <input
            id="cat-filter"
            type="text"
            placeholder="e.g. injection"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
          />
        </div>
      </div>

      {error && <div className="error">Failed to load: {error}</div>}
      {!data && !error && <div className="loading">Loading…</div>}
      {data && (
        <>
          <p className="muted">
            {data.count} matching finding{data.count === 1 ? "" : "s"}
            {data.truncated && <> (showing first {data.findings.length})</>}
          </p>
          {data.findings.length === 0 ? (
            <p className="empty">No findings match these filters.</p>
          ) : (
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Project</th>
                  <th>Title</th>
                  <th>Location</th>
                  <th>Category</th>
                </tr>
              </thead>
              <tbody>
                {data.findings.map((f) => (
                  <tr key={`${f.urlName}:${f.id}`}>
                    <td><SeverityChip sev={f.severity} /></td>
                    <td>
                      <Link to={`/projects/${f.urlName}`}>{f.project}</Link>
                    </td>
                    <td>{f.title}</td>
                    <td><code>{f.file}:{f.line}</code></td>
                    <td>{f.category}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
