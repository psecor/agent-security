// Thin client for the agent-security JSON API. All paths are relative to
// PATH_PREFIX — the server mounts everything under /security, and the
// router/Vite base mirror that, so we just say "/security/..." here.

const API = "/security/api";
const AUTH = "/security/auth";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface SessionUser {
  email: string;
  name: string;
  picture?: string;
}

export interface ToolRunRecord {
  name: string;
  version: string | null;
  error?: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  // file/line are present on project findings (Semgrep, Gitleaks); omitted on
  // host findings where the anchor is a package, not a source location.
  file?: string;
  line?: number;
  line_end?: number;
  source: string;
  rule_id: string;
  rationale: string;
  links?: string[];
  // Host-finding fields (schema v2). Present on package-CVE findings from
  // Trivy; absent on project findings.
  cve?: string;
  cvss?: number;
  package?: string;
  installed_version?: string;
  fixed_version?: string | null;
}

export interface FindingWithProject extends Finding {
  project: string;
  urlName: string;
}

export interface ScanOutput {
  project: string;
  root: string;
  project_path: string;
  scanner_version: string;
  schema_version: number;
  triaged: boolean;
  last_scanned: string;
  last_scanned_sha: string;
  loc_at_scan: number;
  loc_changed_since_previous: number | null;
  tools_run: ToolRunRecord[];
  tools_failed: ToolRunRecord[];
  counts: Record<Severity, number>;
  findings: Finding[];
}

export interface ProjectSummary {
  project: string;
  urlName: string;
  last_scanned: string;
  last_scanned_sha: string;
  loc_at_scan: number;
  loc_changed_since_previous: number | null;
  triaged: boolean;
  counts: Record<Severity, number>;
  findings_total: number;
}

export interface ProjectsList {
  projects: ProjectSummary[];
}

export interface FindingsRollup {
  findings: FindingWithProject[];
  truncated: boolean;
  count: number;
}

export interface HistoryEntry {
  commit: string;
  date: string;
  project_sha: string | null;
  summary: string | null;
  triaged: boolean | null;
  raw_subject: string;
}

export interface HistoryResponse {
  history: HistoryEntry[];
}

export interface FindingsQuery {
  severity?: Severity[];
  category?: string[];
  since?: string;
  limit?: number;
}

export interface OsRelease {
  id: string;
  version_id: string;
  pretty_name: string;
}

export interface HostSummary {
  host: string;
  os_pretty_name: string;
  kernel_version: string;
  triaged: boolean;
  last_scanned: string;
  package_count: number;
  package_set_sha: string;
  counts: Record<Severity, number>;
  findings_total: number;
}

export interface HostsList {
  hosts: HostSummary[];
}

export interface HostDetailResponse {
  host: string;
  kind: "host";
  os_release: OsRelease;
  hostname_kernel: string;
  kernel_version: string;
  architecture: string;
  scanner_version: string;
  schema_version: number;
  triaged: boolean;
  last_scanned: string;
  package_count: number;
  package_set_sha: string;
  package_set_changed_since_previous: boolean | null;
  tools_run: ToolRunRecord[];
  tools_failed: ToolRunRecord[];
  counts: Record<Severity, number>;
  findings_total: number;
  findings: Finding[];
  page: { offset: number; limit: number; matched: number; truncated: boolean };
}

export interface HostDetailQuery {
  severity?: Severity[];
  category?: string[];
  pkg?: string;
  offset?: number;
  limit?: number;
}

export interface HostHistoryEntry {
  commit: string;
  date: string;
  package_sha: string | null;
  summary: string | null;
  triaged: boolean | null;
  raw_subject: string;
}

export interface HostHistoryResponse {
  history: HostHistoryEntry[];
}

class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url, { credentials: "include" });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new HttpError(r.status, `${r.status} ${r.statusText}: ${text}`);
  }
  return (await r.json()) as T;
}

export const isUnauthenticated = (e: unknown): boolean =>
  e instanceof HttpError && e.status === 401;

export const api = {
  me: () => getJson<{ kind: "user"; user: SessionUser } | { kind: null }>(
    `${API}/auth/me`,
  ),
  projects: () => getJson<ProjectsList>(`${API}/projects`),
  project: (urlName: string) =>
    getJson<ScanOutput>(`${API}/projects/${encodeURIComponent(urlName)}`),
  history: (urlName: string, limit = 50) =>
    getJson<HistoryResponse>(
      `${API}/projects/${encodeURIComponent(urlName)}/history?limit=${limit}`,
    ),
  findings: (q: FindingsQuery = {}) => {
    const params = new URLSearchParams();
    if (q.severity?.length) params.set("severity", q.severity.join(","));
    if (q.category?.length) params.set("category", q.category.join(","));
    if (q.since) params.set("since", q.since);
    if (q.limit) params.set("limit", String(q.limit));
    const qs = params.toString();
    return getJson<FindingsRollup>(`${API}/findings${qs ? `?${qs}` : ""}`);
  },
  hosts: () => getJson<HostsList>(`${API}/hosts`),
  host: (name: string, q: HostDetailQuery = {}) => {
    const params = new URLSearchParams();
    if (q.severity?.length) params.set("severity", q.severity.join(","));
    if (q.category?.length) params.set("category", q.category.join(","));
    if (q.pkg) params.set("pkg", q.pkg);
    if (q.offset != null) params.set("offset", String(q.offset));
    if (q.limit != null) params.set("limit", String(q.limit));
    const qs = params.toString();
    return getJson<HostDetailResponse>(
      `${API}/hosts/${encodeURIComponent(name)}${qs ? `?${qs}` : ""}`,
    );
  },
  hostHistory: (name: string, limit = 50) =>
    getJson<HostHistoryResponse>(
      `${API}/hosts/${encodeURIComponent(name)}/history?limit=${limit}`,
    ),
  logout: () =>
    fetch(`${AUTH}/logout`, { method: "POST", credentials: "include" }),
};

export const loginUrl = `${AUTH}/google`;
