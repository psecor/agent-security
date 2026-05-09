// Data access for the server. Reads findings/{projects,hosts}/<key>.json
// from FINDINGS_DIR on demand. No in-memory cache for v1 — files are small,
// reads are cheap.
//
// Multi-root project keys contain "/" in JSON but use "__" in file basenames
// (see scanner/apply.ts → findingsPath). The URL :name param is the on-disk
// form (with "__"); the JSON shows the canonical projectKey. Hostnames don't
// have multi-root collisions, so the on-disk and url names match 1:1.

import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { HOST_FINDINGS_SUBDIR, PROJECT_FINDINGS_SUBDIR } from "../scanner/apply.js";
import type { HostScanOutput, OsRelease } from "../scanner/host-types.js";
import type { Finding, ScanOutput, Severity } from "../scanner/types.js";

export interface ProjectSummary {
  project: string;          // canonical projectKey (may contain "/")
  urlName: string;          // basename used in URLs and on disk ("/" → "__")
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

export interface FindingWithProject extends Finding {
  project: string;
  urlName: string;
}

export interface FindingsRollup {
  findings: FindingWithProject[];
  truncated: boolean;
  count: number;
}

export interface FindingsFilter {
  severity?: Severity[];
  category?: string[];
  since?: string;           // ISO timestamp; project's last_scanned must be >= this
  limit?: number;           // default 500
}

// One row in the per-project scan timeline. Sourced from `git log` in the
// findings repo, parsed from the bot commit subjects we already write
// (see scanner/run.ts → maybeCommit). Pre-scanner commits (milestone work,
// manual edits) appear with summary/project_sha/triaged = null so the UI can
// still render them as plain history entries instead of dropping them.
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

// Host history entry. Mirrors HistoryEntry but with package_sha instead of
// project_sha — the bot subject for host scans uses the package-set SHA as
// its "did anything change" anchor (see scanner/run-host.ts → maybeCommitHost).
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

// Mirrors ProjectSummary but for hosts. Distinct shape rather than a
// discriminated union because nearly every field is named differently and
// the UI's hosts list and projects list aren't going to share rendering.
export interface HostSummary {
  host: string;                  // matches the file basename and url :name
  os_pretty_name: string;        // os_release.pretty_name, surfaced for the table
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

export interface HostDetailFilter {
  severity?: Severity[];
  category?: string[];
  // Substring match on Finding.package — useful for "show me all openssl
  // CVEs" once a host's findings number in the thousands.
  pkg?: string;
  offset?: number;
  limit?: number;
}

// Host detail response: full envelope (metadata + total counts) plus a
// paginated/filtered slice of findings. `findings_total` and `counts` always
// reflect the unfiltered file so the UI's severity pills can show the full
// picture even when the page is filtered to severity=high.
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
  tools_run: HostScanOutput["tools_run"];
  tools_failed: HostScanOutput["tools_failed"];
  counts: Record<Severity, number>;
  findings_total: number;
  findings: Finding[];
  page: { offset: number; limit: number; matched: number; truncated: boolean };
}

export interface DataLayer {
  projects(): Promise<ProjectsList>;
  project(urlName: string): Promise<ScanOutput | null>;
  findings(filter: FindingsFilter): Promise<FindingsRollup>;
  history(urlName: string, limit: number): Promise<HistoryResponse | null>;
  hosts(): Promise<HostsList>;
  host(urlName: string, filter: HostDetailFilter): Promise<HostDetailResponse | null>;
  hostHistory(urlName: string, limit: number): Promise<HostHistoryResponse | null>;
}

export interface DataLayerOptions {
  findingsDir: string;
}

const DEFAULT_FINDINGS_LIMIT = 500;
// Smaller default than the cross-project rollup — the UI fetches one page at
// a time and a workstation host can produce >10k mediums.
const DEFAULT_HOST_FINDINGS_LIMIT = 100;
const MAX_HOST_FINDINGS_LIMIT = 2000;

// Reject anything that could escape findingsDir. Host names are written by
// the scanner from `os.hostname()` / HOST_NAME, so realistic values are
// hostname-shaped; this is a defense-in-depth check on the URL :name param.
function isSafeBasename(name: string): boolean {
  if (name.length === 0) return false;
  if (name.includes("/") || name.includes("\\")) return false;
  if (name.includes("..")) return false;
  return true;
}

export function createDataLayer(opts: DataLayerOptions): DataLayer {
  const projectsDir = join(opts.findingsDir, PROJECT_FINDINGS_SUBDIR);
  const hostsDir = join(opts.findingsDir, HOST_FINDINGS_SUBDIR);

  async function loadAll(): Promise<ScanOutput[]> {
    let entries: string[];
    try {
      entries = await fs.readdir(projectsDir);
    } catch {
      return [];
    }
    const out: ScanOutput[] = [];
    for (const name of entries) {
      if (!name.endsWith(".json")) continue;
      try {
        const raw = await fs.readFile(join(projectsDir, name), "utf8");
        out.push(JSON.parse(raw) as ScanOutput);
      } catch {
        // Skip malformed/partially-written files — never block a request on a
        // bad row. The next scan will overwrite them.
      }
    }
    return out;
  }

  async function loadAllHosts(): Promise<HostScanOutput[]> {
    let entries: string[];
    try {
      entries = await fs.readdir(hostsDir);
    } catch {
      return [];
    }
    const out: HostScanOutput[] = [];
    for (const name of entries) {
      if (!name.endsWith(".json")) continue;
      try {
        const raw = await fs.readFile(join(hostsDir, name), "utf8");
        const parsed = JSON.parse(raw) as HostScanOutput;
        // Defense in depth: a project file accidentally dropped into
        // hosts/ should not be served as a host. Same for a v1 file
        // missing the discriminator entirely.
        if (parsed.kind !== "host") continue;
        out.push(parsed);
      } catch {
        // Same skip-on-malformed policy as loadAll().
      }
    }
    return out;
  }

  function urlNameFor(projectKey: string): string {
    return projectKey.replace(/\//g, "__");
  }

  return {
    async projects(): Promise<ProjectsList> {
      const all = await loadAll();
      const projects: ProjectSummary[] = all.map((s) => ({
        project: s.project,
        urlName: urlNameFor(s.project),
        last_scanned: s.last_scanned,
        last_scanned_sha: s.last_scanned_sha,
        loc_at_scan: s.loc_at_scan,
        loc_changed_since_previous: s.loc_changed_since_previous,
        triaged: s.triaged,
        counts: s.counts,
        findings_total: s.findings.length,
      }));
      projects.sort((a, b) => a.project.localeCompare(b.project));
      return { projects };
    },

    async project(urlName: string): Promise<ScanOutput | null> {
      // Reject anything that could escape findingsDir. URL names are bare
      // filenames with "__" separators — no "/" or ".." allowed.
      if (urlName.includes("/") || urlName.includes("..") || urlName.includes("\\")) {
        return null;
      }
      const path = join(projectsDir, `${urlName}.json`);
      try {
        const raw = await fs.readFile(path, "utf8");
        return JSON.parse(raw) as ScanOutput;
      } catch {
        return null;
      }
    },

    async history(urlName: string, limit: number): Promise<HistoryResponse | null> {
      if (urlName.includes("/") || urlName.includes("..") || urlName.includes("\\")) {
        return null;
      }
      // Only return history for projects that actually have a findings file —
      // otherwise an attacker could probe `git log` with arbitrary basenames.
      const jsonPath = join(projectsDir, `${urlName}.json`);
      try {
        await fs.stat(jsonPath);
      } catch {
        return null;
      }
      const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 200);
      // Track both .json and .md so milestone-1 commits (which only touched
      // .json) still show, and any future md-only edit would too. Paths are
      // relative to the findings repo root (which is opts.findingsDir). The
      // pre-v2 `<urlName>.{json,md}` paths are also listed so a `git mv`
      // migration to projects/ doesn't break the timeline view.
      const args = [
        "log",
        `--max-count=${safeLimit}`,
        "--no-show-signature",
        "--format=%H%x09%cI%x09%s",
        "--",
        `${PROJECT_FINDINGS_SUBDIR}/${urlName}.json`,
        `${PROJECT_FINDINGS_SUBDIR}/${urlName}.md`,
        `${urlName}.json`,
        `${urlName}.md`,
      ];
      let stdout: string;
      try {
        stdout = await runGit(args, opts.findingsDir);
      } catch {
        // Findings dir might not be a git repo (rare; e.g. FINDINGS_DIR
        // pointed outside the project repo). Treat as "no history".
        return { history: [] };
      }
      const history: HistoryEntry[] = [];
      for (const line of stdout.split("\n")) {
        if (!line) continue;
        const tab1 = line.indexOf("\t");
        const tab2 = tab1 < 0 ? -1 : line.indexOf("\t", tab1 + 1);
        if (tab1 < 0 || tab2 < 0) continue;
        const commit = line.slice(0, tab1);
        const date = line.slice(tab1 + 1, tab2);
        const subject = line.slice(tab2 + 1);
        history.push({ commit, date, ...parseScanSubject(subject), raw_subject: subject });
      }
      return { history };
    },

    async findings(filter: FindingsFilter): Promise<FindingsRollup> {
      const all = await loadAll();
      const limit = filter.limit ?? DEFAULT_FINDINGS_LIMIT;
      const sevSet = filter.severity ? new Set(filter.severity) : null;
      const catSet = filter.category ? new Set(filter.category) : null;
      const sinceMs = filter.since ? Date.parse(filter.since) : NaN;

      const matched: FindingWithProject[] = [];
      for (const scan of all) {
        if (Number.isFinite(sinceMs)) {
          const ts = Date.parse(scan.last_scanned);
          if (!Number.isFinite(ts) || ts < sinceMs) continue;
        }
        for (const f of scan.findings) {
          if (sevSet && !sevSet.has(f.severity)) continue;
          if (catSet && !catSet.has(f.category)) continue;
          matched.push({ ...f, project: scan.project, urlName: urlNameFor(scan.project) });
        }
      }
      matched.sort(severityThenLocation);
      const truncated = matched.length > limit;
      return {
        findings: truncated ? matched.slice(0, limit) : matched,
        truncated,
        count: matched.length,
      };
    },

    async hosts(): Promise<HostsList> {
      const all = await loadAllHosts();
      const hosts: HostSummary[] = all.map((h) => ({
        host: h.host,
        os_pretty_name: h.os_release.pretty_name,
        kernel_version: h.kernel_version,
        triaged: h.triaged,
        last_scanned: h.last_scanned,
        package_count: h.package_count,
        package_set_sha: h.package_set_sha,
        counts: h.counts,
        findings_total: h.findings.length,
      }));
      hosts.sort((a, b) => a.host.localeCompare(b.host));
      return { hosts };
    },

    async host(urlName: string, filter: HostDetailFilter): Promise<HostDetailResponse | null> {
      if (!isSafeBasename(urlName)) return null;
      const path = join(hostsDir, `${urlName}.json`);
      let raw: string;
      try {
        raw = await fs.readFile(path, "utf8");
      } catch {
        return null;
      }
      let parsed: HostScanOutput;
      try {
        parsed = JSON.parse(raw) as HostScanOutput;
      } catch {
        return null;
      }
      if (parsed.kind !== "host") return null;

      const sevSet = filter.severity ? new Set(filter.severity) : null;
      const catSet = filter.category ? new Set(filter.category) : null;
      const pkgQ = filter.pkg ? filter.pkg.toLowerCase() : null;

      const matched: Finding[] = [];
      for (const f of parsed.findings) {
        if (sevSet && !sevSet.has(f.severity)) continue;
        if (catSet && !catSet.has(f.category)) continue;
        if (pkgQ) {
          const pkg = (f.package ?? "").toLowerCase();
          if (!pkg.includes(pkgQ)) continue;
        }
        matched.push(f);
      }

      // Findings are already severity-sorted by sortFindings in the writer,
      // so ordering is stable across pages without re-sorting here.
      const offset = Math.max(0, Math.floor(filter.offset ?? 0));
      const requestedLimit = filter.limit ?? DEFAULT_HOST_FINDINGS_LIMIT;
      const limit = Math.min(Math.max(1, Math.floor(requestedLimit)), MAX_HOST_FINDINGS_LIMIT);
      const slice = matched.slice(offset, offset + limit);
      const truncated = offset + slice.length < matched.length;

      return {
        host: parsed.host,
        kind: "host",
        os_release: parsed.os_release,
        hostname_kernel: parsed.hostname_kernel,
        kernel_version: parsed.kernel_version,
        architecture: parsed.architecture,
        scanner_version: parsed.scanner_version,
        schema_version: parsed.schema_version,
        triaged: parsed.triaged,
        last_scanned: parsed.last_scanned,
        package_count: parsed.package_count,
        package_set_sha: parsed.package_set_sha,
        package_set_changed_since_previous: parsed.package_set_changed_since_previous,
        tools_run: parsed.tools_run,
        tools_failed: parsed.tools_failed,
        counts: parsed.counts,
        findings_total: parsed.findings.length,
        findings: slice,
        page: { offset, limit, matched: matched.length, truncated },
      };
    },

    async hostHistory(urlName: string, limit: number): Promise<HostHistoryResponse | null> {
      if (!isSafeBasename(urlName)) return null;
      // Same probe-prevention as project history: only return git log for
      // hosts that actually have a findings file on disk.
      const jsonPath = join(hostsDir, `${urlName}.json`);
      try {
        await fs.stat(jsonPath);
      } catch {
        return null;
      }
      const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 200);
      const args = [
        "log",
        `--max-count=${safeLimit}`,
        "--no-show-signature",
        "--format=%H%x09%cI%x09%s",
        "--",
        `${HOST_FINDINGS_SUBDIR}/${urlName}.json`,
        `${HOST_FINDINGS_SUBDIR}/${urlName}.md`,
      ];
      let stdout: string;
      try {
        stdout = await runGit(args, opts.findingsDir);
      } catch {
        return { history: [] };
      }
      const history: HostHistoryEntry[] = [];
      for (const line of stdout.split("\n")) {
        if (!line) continue;
        const tab1 = line.indexOf("\t");
        const tab2 = tab1 < 0 ? -1 : line.indexOf("\t", tab1 + 1);
        if (tab1 < 0 || tab2 < 0) continue;
        const commit = line.slice(0, tab1);
        const date = line.slice(tab1 + 1, tab2);
        const subject = line.slice(tab2 + 1);
        history.push({ commit, date, ...parseHostScanSubject(subject), raw_subject: subject });
      }
      return { history };
    },
  };
}

// Matches the host bot subject from scanner/run-host.ts → maybeCommitHost:
//   scan(host:<name>): <totals> @ <pkg-sha-7> [triaged|untriaged]
// The shape happens to match the project regex (which allows "host:" inside
// the parens), but a dedicated parser keeps the field naming honest:
// `package_sha` not `project_sha`.
const HOST_SCAN_SUBJECT_RE = /^scan\(host:[^)]+\): (.+) @ ([a-f0-9]+|no-pkg-sha) \[(triaged|untriaged)\]$/;

function parseHostScanSubject(subject: string): {
  package_sha: string | null;
  summary: string | null;
  triaged: boolean | null;
} {
  const m = HOST_SCAN_SUBJECT_RE.exec(subject);
  if (!m) return { package_sha: null, summary: null, triaged: null };
  const sha = m[2] === "no-pkg-sha" ? null : (m[2] ?? null);
  return { summary: m[1] ?? null, package_sha: sha, triaged: m[3] === "triaged" };
}

// Matches the subject we write in scanner/run.ts → maybeCommit:
//   scan(<key>): <summary> @ <project-sha> [triaged|untriaged]
const SCAN_SUBJECT_RE = /^scan\([^)]+\): (.+) @ ([a-f0-9]+) \[(triaged|untriaged)\]$/;

function parseScanSubject(subject: string): {
  project_sha: string | null;
  summary: string | null;
  triaged: boolean | null;
} {
  const m = SCAN_SUBJECT_RE.exec(subject);
  if (!m) return { project_sha: null, summary: null, triaged: null };
  return { summary: m[1] ?? null, project_sha: m[2] ?? null, triaged: m[3] === "triaged" };
}

function runGit(args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", args, { cwd });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => out.push(b));
    child.stderr.on("data", (b: Buffer) => err.push(b));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve(Buffer.concat(out).toString("utf8"));
      else reject(new Error(`git ${args[0]} exited ${code}: ${Buffer.concat(err).toString("utf8").trim()}`));
    });
  });
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function severityThenLocation(a: FindingWithProject, b: FindingWithProject): number {
  const s = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (s !== 0) return s;
  const p = a.project.localeCompare(b.project);
  if (p !== 0) return p;
  const f = (a.file ?? "").localeCompare(b.file ?? "");
  if (f !== 0) return f;
  return (a.line ?? 0) - (b.line ?? 0);
}
