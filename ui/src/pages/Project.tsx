import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, SEVERITIES, type Finding, type HistoryEntry, type ScanOutput } from "../api.ts";
import { SeverityChip, SeverityCounts } from "../components/SeverityChip.tsx";

export function Project(): JSX.Element {
  const { name } = useParams();
  const [data, setData] = useState<ScanOutput | null>(null);
  const [history, setHistory] = useState<HistoryEntry[] | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!name) return;
    setData(null);
    setHistory(null);
    setError(null);
    setHistoryError(null);
    api.project(name)
      .then(setData)
      .catch((e: Error) => setError(e.message));
    api.history(name)
      .then((r) => setHistory(r.history))
      .catch((e: Error) => setHistoryError(e.message));
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

      <ScanHistory entries={history} error={historyError} currentSha={data.last_scanned_sha} />
    </div>
  );
}

function ScanHistory({
  entries,
  error,
  currentSha,
}: {
  entries: HistoryEntry[] | null;
  error: string | null;
  currentSha: string;
}): JSX.Element | null {
  if (error) {
    return (
      <section className="scan-history">
        <h2>Scan history</h2>
        <p className="error-inline">Failed to load history: {error}</p>
      </section>
    );
  }
  if (!entries) return null;
  // Hide entirely when there's only the current scan and no prior history
  // worth surfacing — the page header already shows last_scanned + sha.
  if (entries.length <= 1) return null;
  return (
    <section className="scan-history">
      <h2>Scan history <span className="muted">({entries.length})</span></h2>
      <ul className="history-list">
        {entries.map((e) => (
          <HistoryRow key={e.commit} entry={e} currentSha={currentSha} />
        ))}
      </ul>
    </section>
  );
}

function HistoryRow({ entry, currentSha }: { entry: HistoryEntry; currentSha: string }): JSX.Element {
  const isCurrent = entry.project_sha === currentSha;
  const date = new Date(entry.date);
  return (
    <li className={`history-row${isCurrent ? " history-current" : ""}`}>
      <time dateTime={entry.date} title={date.toLocaleString()}>
        {date.toISOString().slice(0, 10)}
      </time>
      <code className="history-commit" title={entry.commit}>{entry.commit.slice(0, 7)}</code>
      {entry.project_sha ? (
        <>
          <span className="history-summary">{entry.summary}</span>
          <span className="muted">@ <code>{entry.project_sha}</code></span>
          {entry.triaged === false && <span className="tag-untriaged">untriaged</span>}
          {isCurrent && <span className="muted">· current</span>}
        </>
      ) : (
        <span className="history-raw">{entry.raw_subject}</span>
      )}
    </li>
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
