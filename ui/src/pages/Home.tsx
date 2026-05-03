import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ProjectsList } from "../api.ts";
import { SeverityCounts } from "../components/SeverityChip.tsx";

export function Home(): JSX.Element {
  const [data, setData] = useState<ProjectsList | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.projects()
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <div className="error">Failed to load: {error}</div>;
  if (!data) return <div className="loading">Loading…</div>;

  if (data.projects.length === 0) {
    return (
      <div className="empty">
        <h2>No scans yet</h2>
        <p>Run <code>npm run scanner -- run --all</code> in the service to populate findings.</p>
      </div>
    );
  }

  return (
    <div className="home">
      <h2>Projects</h2>
      <table className="projects-table">
        <thead>
          <tr>
            <th>Project</th>
            <th>Findings</th>
            <th>LOC</th>
            <th>Last scan</th>
            <th>SHA</th>
          </tr>
        </thead>
        <tbody>
          {data.projects.map((p) => (
            <tr key={p.urlName}>
              <td>
                <Link to={`/projects/${p.urlName}`} className="project-link">
                  {p.project}
                </Link>
                {!p.triaged && <span className="tag-untriaged">untriaged</span>}
              </td>
              <td><SeverityCounts counts={p.counts} /></td>
              <td className="num">{p.loc_at_scan.toLocaleString()}</td>
              <td><RelativeTime iso={p.last_scanned} /></td>
              <td><code>{p.last_scanned_sha}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RelativeTime({ iso }: { iso: string }): JSX.Element {
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return <span className="muted">—</span>;
  const ageMs = Date.now() - ts;
  const day = 86400_000;
  let label: string;
  if (ageMs < day) label = "today";
  else if (ageMs < 2 * day) label = "yesterday";
  else if (ageMs < 30 * day) label = `${Math.floor(ageMs / day)}d ago`;
  else label = new Date(ts).toISOString().slice(0, 10);
  return <span title={iso}>{label}</span>;
}
