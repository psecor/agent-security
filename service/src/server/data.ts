// Data access for the server. Reads findings/<key>.json from FINDINGS_DIR
// on demand. No in-memory cache for v1 — files are small, reads are cheap.
//
// Multi-root keys contain "/" in JSON but use "__" in file basenames (see
// scanner/apply.ts → findingsPath). The URL :name param is the on-disk form
// (with "__"); the JSON shows the canonical projectKey.

import { promises as fs } from "node:fs";
import { join } from "node:path";
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

export interface DataLayer {
  projects(): Promise<ProjectsList>;
  project(urlName: string): Promise<ScanOutput | null>;
  findings(filter: FindingsFilter): Promise<FindingsRollup>;
}

export interface DataLayerOptions {
  findingsDir: string;
}

const DEFAULT_FINDINGS_LIMIT = 500;

export function createDataLayer(opts: DataLayerOptions): DataLayer {
  async function loadAll(): Promise<ScanOutput[]> {
    let entries: string[];
    try {
      entries = await fs.readdir(opts.findingsDir);
    } catch {
      return [];
    }
    const out: ScanOutput[] = [];
    for (const name of entries) {
      if (!name.endsWith(".json")) continue;
      try {
        const raw = await fs.readFile(join(opts.findingsDir, name), "utf8");
        out.push(JSON.parse(raw) as ScanOutput);
      } catch {
        // Skip malformed/partially-written files — never block a request on a
        // bad row. The next scan will overwrite them.
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
      const path = join(opts.findingsDir, `${urlName}.json`);
      try {
        const raw = await fs.readFile(path, "utf8");
        return JSON.parse(raw) as ScanOutput;
      } catch {
        return null;
      }
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
  };
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function severityThenLocation(a: FindingWithProject, b: FindingWithProject): number {
  const s = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (s !== 0) return s;
  const p = a.project.localeCompare(b.project);
  if (p !== 0) return p;
  const f = a.file.localeCompare(b.file);
  if (f !== 0) return f;
  return a.line - b.line;
}
