import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, SEVERITIES, type Finding, type ScanOutput } from "../api.ts";
import { SeverityChip, SeverityCounts } from "../components/SeverityChip.tsx";

export function Project(): JSX.Element {
  const { name } = useParams();
  const [data, setData] = useState<ScanOutput | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!name) return;
    setData(null);
    setError(null);
    api.project(name)
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [name]);

  if (error) return <div className="error">Failed to load: {error}</div>;
  if (!data) return <div className="loading">Loading…</div>;

  const grouped = SEVERITIES.map((s) => ({
    sev: s,
    findings: data.findings.filter((f) => f.severity === s),
  })).filter((g) => g.findings.length > 0);

  return (
    <div className="project-detail">
      <header className="doc-head">
        <Link to="/" className="back-link">← All projects</Link>
        <h1>{data.project}</h1>
        <div className="doc-meta">
          <SeverityCounts counts={data.counts} />
          {!data.triaged && <span className="tag-untriaged">untriaged</span>}
        </div>
        <p className="muted">
          Last scanned {new Date(data.last_scanned).toLocaleString()} at{" "}
          <code>{data.last_scanned_sha}</code> · {data.loc_at_scan.toLocaleString()} LOC
          {data.loc_changed_since_previous != null && data.loc_changed_since_previous > 0 && (
            <> · {data.loc_changed_since_previous.toLocaleString()} LOC changed since previous scan</>
          )}
        </p>
        <p className="muted">
          Tools:{" "}
          {data.tools_run.map((t) => (
            <code key={t.name}>{t.name}@{t.version ?? "?"}</code>
          )).reduce<React.ReactNode[]>((acc, el, i) => {
            if (i > 0) acc.push(", ");
            acc.push(el);
            return acc;
          }, [])}
          {data.tools_failed.length > 0 && (
            <>
              {" "}· <span className="error-inline">failed: {data.tools_failed.map((t) => t.name).join(", ")}</span>
            </>
          )}
        </p>
      </header>

      {data.findings.length === 0 ? (
        <p className="muted">No findings as of this scan.</p>
      ) : (
        grouped.map((g) => (
          <section key={g.sev} className="sev-group">
            <h2>
              <SeverityChip sev={g.sev} /> <span className="sev-count">({g.findings.length})</span>
            </h2>
            <ul className="findings-list">
              {g.findings.map((f) => <FindingCard key={f.id} f={f} />)}
            </ul>
          </section>
        ))
      )}
    </div>
  );
}

function FindingCard({ f }: { f: Finding }): JSX.Element {
  const where = f.line_end && f.line_end !== f.line
    ? `${f.file}:${f.line}-${f.line_end}`
    : `${f.file}:${f.line}`;
  return (
    <li className="finding">
      <h3>{f.title}</h3>
      <div className="finding-meta">
        <code>{where}</code>
        <span className="muted">·</span>
        <span className={`cat cat-${slugify(f.category)}`}>{f.category}</span>
        <span className="muted">·</span>
        <code>{f.source}</code>
        <span className="muted">·</span>
        <code className="rule">{f.rule_id}</code>
      </div>
      {f.rationale && <p className="rationale">{f.rationale}</p>}
      {f.links && f.links.length > 0 && (
        <ul className="ref-list">
          {f.links.map((l) => (
            <li key={l}><a href={l} target="_blank" rel="noreferrer">{l}</a></li>
          ))}
        </ul>
      )}
    </li>
  );
}

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}
