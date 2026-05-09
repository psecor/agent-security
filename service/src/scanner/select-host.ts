// Host-scan selector. Distinct from the project selector because the
// "did anything change" signal is different — a host's installed-package
// set replaces the project's git sha, and Trivy's CVE DB updating daily
// means even a fully static host is worth re-scanning.
//
// Rules (mirrors spec/host-scanning.md → "Selector"):
//   1. --force: always qualify.
//   2. No prior findings file: qualify (first scan).
//   3. package_set_sha changed since the prior scan: qualify.
//   4. last_scanned > 24h ago: qualify (daily floor).
//   5. Otherwise skip.
//
// Hosts where dpkg-query isn't available end up with package_set_sha = ""
// in HostInfo; rule 3 then never fires and the daily floor (rule 4) carries
// the cadence on its own. That's the same effective rate Trivy's DB
// publishes at, so non-dpkg distros are no worse off in v1.

import { readFileSync, statSync } from "node:fs";
import { hostFindingsPath } from "./apply.js";
import { gatherHostInfo, type HostInfo } from "./host-info.js";

const DAILY_FLOOR_MS = 24 * 60 * 60 * 1000;

export type HostSelectReason =
  | "forced"
  | "never-scanned"
  | "prior-unreadable"
  | "package-set-changed"
  | "daily-floor"
  | "skipped-no-change";

export interface HostSelection {
  hostName: string;
  info: HostInfo;
  qualifies: boolean;
  reason: HostSelectReason;
  prior_package_set_sha: string | null;
  prior_last_scanned: string | null;
}

export interface HostSelectOptions {
  hostName: string;
  findingsDir: string;
  force: boolean;
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void;
}

export function selectHost(opts: HostSelectOptions): HostSelection {
  const info = gatherHostInfo();
  const baseResult = (qualifies: boolean, reason: HostSelectReason,
                      priorSha: string | null, priorScanned: string | null): HostSelection =>
    ({ hostName: opts.hostName, info, qualifies, reason,
       prior_package_set_sha: priorSha, prior_last_scanned: priorScanned });

  if (opts.force) {
    return baseResult(true, "forced", null, null);
  }

  const jsonPath = hostFindingsPath(opts.findingsDir, opts.hostName, "json");
  try {
    statSync(jsonPath);
  } catch {
    return baseResult(true, "never-scanned", null, null);
  }

  let prior: { package_set_sha?: unknown; last_scanned?: unknown };
  try {
    prior = JSON.parse(readFileSync(jsonPath, "utf8"));
  } catch (err) {
    opts.log("warn", `host ${opts.hostName}: prior findings unreadable (${err instanceof Error ? err.message : String(err)}); scheduling full scan`);
    return baseResult(true, "prior-unreadable", null, null);
  }

  const priorSha = typeof prior.package_set_sha === "string" ? prior.package_set_sha : null;
  const priorScanned = typeof prior.last_scanned === "string" ? prior.last_scanned : null;

  if (priorSha && info.package_set_sha && priorSha !== info.package_set_sha) {
    return baseResult(true, "package-set-changed", priorSha, priorScanned);
  }
  if (priorScanned) {
    const ts = Date.parse(priorScanned);
    if (Number.isFinite(ts) && Date.now() - ts >= DAILY_FLOOR_MS) {
      return baseResult(true, "daily-floor", priorSha, priorScanned);
    }
  }
  return baseResult(false, "skipped-no-change", priorSha, priorScanned);
}
