import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  SEVERITIES,
  type Finding,
  type HostDetailResponse,
  type HostHistoryEntry,
  type Severity,
} from "../api.ts";
import { SeverityChip, SeverityCounts } from "../components/SeverityChip.tsx";

// Default filter: highs and criticals. A workstation can have 10k+ medium
// findings (kernel CVEs replicated across every linux-headers-* package);
// dumping those by default would bury the 27 things the user actually wants
// to look at. The full distribution is still one click away via the pills.
const DEFAULT_SEVERITY: ReadonlySet<Severity> = new Set(["critical", "high"]);
const PAGE_SIZE = 50;

export function Host(): JSX.Element {
  const { name } = useParams();
  const [meta, setMeta] = useState<HostDetailResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadingPage, setLoadingPage] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [severitySet, setSeveritySet] = useState<Set<Severity>>(new Set(DEFAULT_SEVERITY));
  const [pkgInput, setPkgInput] = useState("");
  const [pkgFilter, setPkgFilter] = useState("");

  const [history, setHistory] = useState<HostHistoryEntry[] | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);

  // Stable across renders so the load-more callback can reference the current
  // filter without re-binding every keystroke. Sorted so the URL/query order
  // is deterministic, which keeps the network panel readable.
  const severityList: Severity[] = useMemo(
    () => SEVERITIES.filter((s) => severitySet.has(s)),
    [severitySet],
  );

  const fetchPage = useCallback(
    async (offset: number) => {
      if (!name) return;
      setLoadingPage(true);
      setError(null);
      try {
        const q = {
          severity: severityList.length ? severityList : undefined,
          pkg: pkgFilter || undefined,
          offset,
          limit: PAGE_SIZE,
        };
        const r = await api.host(name, q);
        setMeta(r);
        setFindings((prev) => (offset === 0 ? r.findings : [...prev, ...r.findings]));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoadingPage(false);
      }
    },
    [name, severityList, pkgFilter],
  );

  // Filter change → reset list and refetch from offset 0.
  useEffect(() => {
    if (!name) return;
    setFindings([]);
    fetchPage(0);
  }, [name, fetchPage]);

  // Debounce package-name input so we don't hit the API on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setPkgFilter(pkgInput.trim()), 300);
    return () => clearTimeout(t);
  }, [pkgInput]);

  useEffect(() => {
    if (!name) return;
    setHistory(null);
    setHistoryError(null);
    api.hostHistory(name)
      .then((r) => setHistory(r.history))
      .catch((e: Error) => setHistoryError(e.message));
  }, [name]);

  if (error && !meta) return <div className="error">Failed to load: {error}</div>;
  if (!meta) return <div className="loading">Loading…</div>;

  const togglesev = (s: Severity): void => {
    setSeveritySet((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };
  const clearSev = (): void => setSeveritySet(new Set());
  const remaining = meta.page.matched - findings.length;

  return (
    <div className="project-detail">
      <header className="doc-head">
        <Link to="/hosts" className="back-link">← All hosts</Link>
        <h1>{meta.host}</h1>
        <div className="doc-meta">
          <SeverityCounts counts={meta.counts} />
          {!meta.triaged && <span className="tag-untriaged">untriaged</span>}
        </div>
        <p className="muted">
          Last scanned {new Date(meta.last_scanned).toLocaleString()} ·{" "}
          {meta.os_release.pretty_name} kernel <code>{meta.kernel_version}</code>{" "}
          ({meta.architecture}) · {meta.package_count.toLocaleString()} packages
          {meta.package_set_changed_since_previous != null && (
            <>
              {" "}·{" "}
              {meta.package_set_changed_since_previous
                ? "package set changed since last scan"
                : "package set unchanged since last scan"}
            </>
          )}
        </p>
        <p className="muted">
          Tools:{" "}
          {meta.tools_run.map((t) => (
            <code key={t.name}>{t.name}@{t.version ?? "?"}</code>
          )).reduce<React.ReactNode[]>((acc, el, i) => {
            if (i > 0) acc.push(", ");
            acc.push(el);
            return acc;
          }, [])}
          {meta.tools_failed.length > 0 && (
            <>
              {" "}· <span className="error-inline">failed: {meta.tools_failed.map((t) => t.name).join(", ")}</span>
            </>
          )}
        </p>
      </header>

      <section className="filter-bar">
        <div className="filter-group">
          <span className="filter-label">Severity:</span>
          {SEVERITIES.map((s) => {
            const active = severitySet.has(s);
            const count = meta.counts[s];
            return (
              <button
                key={s}
                type="button"
                className={`pill pill-${s}${active ? " pill-active" : ""}`}
                onClick={() => togglesev(s)}
                disabled={count === 0}
                title={count === 0 ? `0 ${s}` : `${count} ${s}`}
              >
                {s} <span className="pill-count">{count.toLocaleString()}</span>
              </button>
            );
          })}
          <button
            type="button"
            className="linkbtn"
            onClick={clearSev}
            disabled={severitySet.size === 0}
          >
            clear
          </button>
        </div>
        <div className="filter-group">
          <label className="filter-label" htmlFor="pkg-filter">Package:</label>
          <input
            id="pkg-filter"
            type="text"
            placeholder="substring match (e.g. openssl)"
            value={pkgInput}
            onChange={(e) => setPkgInput(e.target.value)}
          />
        </div>
      </section>

      {error && <div className="error-inline">Filter error: {error}</div>}

      {meta.page.matched === 0 ? (
        <p className="muted">No findings match the current filter.</p>
      ) : (
        <>
          <p className="muted">
            Showing {findings.length.toLocaleString()} of{" "}
            {meta.page.matched.toLocaleString()} matching findings
            {meta.page.matched < meta.findings_total && (
              <> ({meta.findings_total.toLocaleString()} total before filter)</>
            )}
            .
          </p>
          <ul className="findings-list">
            {findings.map((f) => <HostFindingCard key={f.id} f={f} />)}
          </ul>
          {remaining > 0 && (
            <div className="load-more">
              <button
                type="button"
                onClick={() => fetchPage(findings.length)}
                disabled={loadingPage}
                className="btn-secondary"
              >
                {loadingPage
                  ? "Loading…"
                  : `Load ${Math.min(PAGE_SIZE, remaining).toLocaleString()} more (${remaining.toLocaleString()} remaining)`}
              </button>
            </div>
          )}
        </>
      )}

      <HostScanHistory entries={history} error={historyError} currentSha={meta.package_set_sha} />
    </div>
  );
}

function HostFindingCard({ f }: { f: Finding }): JSX.Element {
  // Host findings render package metadata in place of file:line. The CVE id
  // doubles as rule_id in our schema, but show it explicitly here since the
  // title gets truncated by naive triage and we don't want to make a user
  // squint at the rule_id field to find the CVE.
  const fixed = f.fixed_version === null
    ? <span className="muted">no fix yet</span>
    : f.fixed_version
      ? <><span className="muted">→</span> <code>{f.fixed_version}</code></>
      : null;
  return (
    <li className="finding">
      <h3>
        {f.cve && <code className="cve-tag">{f.cve}</code>}{" "}
        {f.title}
      </h3>
      <div className="finding-meta">
        {f.package && (
          <>
            <code>{f.package}</code>
            {f.installed_version && <> <code>{f.installed_version}</code></>}
            {fixed && <> {fixed}</>}
            <span className="muted">·</span>
          </>
        )}
        <span className={`cat cat-${slugify(f.category)}`}>{f.category}</span>
        <span className="muted">·</span>
        <code>{f.source}</code>
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

function HostScanHistory({
  entries,
  error,
  currentSha,
}: {
  entries: HostHistoryEntry[] | null;
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
  if (entries.length <= 1) return null;
  return (
    <section className="scan-history">
      <h2>Scan history <span className="muted">({entries.length})</span></h2>
      <ul className="history-list">
        {entries.map((e) => {
          // The package_sha in the bot subject is a 7-char prefix; match it
          // against the full sha by prefix so the "current" tag highlights
          // correctly without us having to re-derive shorter forms here.
          const isCurrent =
            e.package_sha != null && currentSha.startsWith(e.package_sha);
          const date = new Date(e.date);
          return (
            <li
              key={e.commit}
              className={`history-row${isCurrent ? " history-current" : ""}`}
            >
              <time dateTime={e.date} title={date.toLocaleString()}>
                {date.toISOString().slice(0, 10)}
              </time>
              <code className="history-commit" title={e.commit}>{e.commit.slice(0, 7)}</code>
              {e.package_sha ? (
                <>
                  <span className="history-summary">{e.summary}</span>
                  <span className="muted">@ <code>{e.package_sha}</code></span>
                  {e.triaged === false && <span className="tag-untriaged">untriaged</span>}
                  {isCurrent && <span className="muted">· current</span>}
                </>
              ) : (
                <span className="history-raw">{e.raw_subject}</span>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}
