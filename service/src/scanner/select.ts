// Project discovery + LOC-threshold selector.
//
// Discovery rule: a project is an immediate subdir of one of PROJECT_ROOTS
// that (a) is a git working tree and (b) contains an AGENTS.md. The
// AGENTS.md filter matches the .env.example contract and keeps the scanner
// from wandering into one-off repos the user isn't actively tracking.
//
// Multi-root behavior: in single-root mode, projectKey is the bare directory
// name. In multi-root mode (or when the same name appears under more than
// one root), projectKey is qualified as `<root-basename>/<name>`. The basename
// of the findings file flattens "/" to "__" — see apply.ts → findingsPath.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { findingsPath } from "./apply.js";
import { getLocChangedSince, isGitRepo } from "./git.js";

export interface DiscoveredProject {
  root: string;
  projectPath: string;
  name: string;          // bare directory name
  projectKey: string;    // bare or `<root-basename>/<name>` for collisions / multi-root
}

export interface SelectedProject extends DiscoveredProject {
  reason: SelectReason;
  loc_changed: number | null;
  prior_sha: string | null;
}

export type SelectReason =
  | "forced"
  | "never-scanned"
  | "prior-sha-unreachable"
  | "loc-threshold";

export interface SelectOptions {
  roots: string[];
  findingsDir: string;
  locThreshold: number;
  force: boolean;
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void;
}

export function discoverProjects(roots: string[]): DiscoveredProject[] {
  const found: Array<Omit<DiscoveredProject, "projectKey">> = [];
  for (const root of roots) {
    let entries: string[];
    try {
      entries = readdirSync(root);
    } catch {
      continue;
    }
    for (const name of entries) {
      const projectPath = join(root, name);
      try {
        if (!statSync(projectPath).isDirectory()) continue;
      } catch {
        continue;
      }
      if (!isGitRepo(projectPath)) continue;
      try {
        if (!statSync(join(projectPath, "AGENTS.md")).isFile()) continue;
      } catch {
        continue;
      }
      found.push({ root, projectPath, name });
    }
  }

  // Qualify keys whenever a name appears under more than one root, OR when
  // we're configured for multi-root scanning at all (so a name added to a
  // second root later doesn't silently collide with a prior-scanned bare key).
  const counts = new Map<string, number>();
  for (const p of found) counts.set(p.name, (counts.get(p.name) ?? 0) + 1);
  const multiRoot = roots.length > 1;
  return found.map((p) => ({
    ...p,
    projectKey: multiRoot || (counts.get(p.name) ?? 0) > 1
      ? `${basename(p.root)}/${p.name}`
      : p.name,
  })).sort((a, b) => a.projectKey.localeCompare(b.projectKey));
}

export function selectProjects(opts: SelectOptions): SelectedProject[] {
  const { roots, findingsDir, locThreshold, force, log } = opts;
  const all = discoverProjects(roots);
  log("debug", `discovered ${all.length} project(s) across ${roots.length} root(s)`);

  const out: SelectedProject[] = [];
  for (const p of all) {
    if (force) {
      out.push({ ...p, reason: "forced", loc_changed: null, prior_sha: null });
      continue;
    }
    const priorPath = findingsPath(findingsDir, p.projectKey, "json");
    let prior: { last_scanned_sha?: string } | null = null;
    try {
      prior = JSON.parse(readFileSync(priorPath, "utf8"));
    } catch {
      // No prior findings file — first-time scan.
    }
    const priorSha = prior?.last_scanned_sha ?? null;
    if (!priorSha) {
      out.push({ ...p, reason: "never-scanned", loc_changed: null, prior_sha: null });
      continue;
    }
    const changed = getLocChangedSince(p.projectPath, priorSha);
    if (changed === null) {
      log("warn", `${p.projectKey}: prior sha ${priorSha} unreachable, scheduling full scan`);
      out.push({ ...p, reason: "prior-sha-unreachable", loc_changed: null, prior_sha: priorSha });
      continue;
    }
    if (changed >= locThreshold) {
      out.push({ ...p, reason: "loc-threshold", loc_changed: changed, prior_sha: priorSha });
      continue;
    }
    log("debug", `skip ${p.projectKey}: ${changed} LOC changed since ${priorSha} (threshold ${locThreshold})`);
  }

  log("info", `selector: ${out.length}/${all.length} project(s) qualify`);
  return out;
}
