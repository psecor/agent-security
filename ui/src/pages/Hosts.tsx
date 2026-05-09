import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type HostsList } from "../api.ts";
import { SeverityCounts } from "../components/SeverityChip.tsx";

export function Hosts(): JSX.Element {
  const [data, setData] = useState<HostsList | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.hosts()
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <div className="error">Failed to load: {error}</div>;
  if (!data) return <div className="loading">Loading…</div>;

  if (data.hosts.length === 0) {
    return (
      <div className="empty">
        <h2>No host scans yet</h2>
        <p>Run <code>npm run scanner -- run --host</code> on a host to populate findings.</p>
      </div>
    );
  }

  return (
    <div className="home">
      <h2>Hosts</h2>
      <table className="projects-table">
        <thead>
          <tr>
            <th>Host</th>
            <th>Findings</th>
            <th>OS</th>
            <th>Kernel</th>
            <th>Packages</th>
            <th>Last scan</th>
          </tr>
        </thead>
        <tbody>
          {data.hosts.map((h) => (
            <tr key={h.host}>
              <td>
                <Link to={`/hosts/${h.host}`} className="project-link">
                  {h.host}
                </Link>
                {!h.triaged && <span className="tag-untriaged">untriaged</span>}
              </td>
              <td><SeverityCounts counts={h.counts} /></td>
              <td>{h.os_pretty_name}</td>
              <td><code>{h.kernel_version}</code></td>
              <td className="num">{h.package_count.toLocaleString()}</td>
              <td><RelativeTime iso={h.last_scanned} /></td>
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
