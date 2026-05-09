// Orchestrates one project's scan: resolve paths, run tools, triage,
// write findings/<project>.{json,md}.

import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, sep } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import {
  commitFindingsFiles,
  getHeadSha,
  getLocChangedSince,
  getTotalLoc,
  isGitRepo,
  isInsideWorkTree,
} from "./git.js";
import { GitleaksRunner } from "./tools/gitleaks.js";
import { SemgrepRunner } from "./tools/semgrep.js";
import type { ToolRunner, ToolRunRecord, RawFinding, ToolContext } from "./tools/types.js";
import { triage } from "./triage.js";
import {
  countSeverities,
  findingsPath,
  sortFindings,
  writeJson,
  writeMarkdown,
} from "./apply.js";
import type { ScanOutput, Severity } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

const SCANNER_VERSION = "0.1.0";
// schema_version 2 (May 2026): added `kind` discriminator and split
// findings/ into projects/ and hosts/ subdirs. See spec/findings-schema.md.
const SCHEMA_VERSION = 2;

export interface RunOptions {
  // Absolute path to the project's working tree.
  projectPath: string;
  // The root this project lives under (one of PROJECT_ROOTS).
  root: string;
  // Bare project name (single-root) or qualified key (multi-root).
  projectKey: string;
  // Where to write findings/<key>.{json,md}.
  findingsDir: string;
  // If true, print the JSON to stdout and skip the file write.
  dryRun: boolean;
  // Anthropic client for the triage layer. When null, triage falls back to
  // the milestone-1 naive mapping and the output is marked `triaged: false`.
  claudeClient: Anthropic | null;
  // Skip the bot-commit step after writing findings. Implied by dryRun.
  noCommit: boolean;
  // Optional: prior scan's HEAD sha, used to populate
  // loc_changed_since_previous. The selector usually has this already.
  priorSha?: string | null;
  // Logger.
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void;
}

export interface RunReport {
  projectKey: string;
  status: "ok" | "no-tools-ran" | "error";
  findingsCount: number;
  toolsRun: number;
  toolsFailed: number;
  outputPaths?: { json: string; md: string };
  commitSha?: string;       // set when bot-commit produced a new commit
  error?: string;
}

const REGISTERED_TOOLS: ToolRunner[] = [new SemgrepRunner(), new GitleaksRunner()];

export async function scanProject(opts: RunOptions): Promise<RunReport> {
  const { projectPath, projectKey, log } = opts;

  if (!statSync(projectPath, { throwIfNoEntry: false })?.isDirectory()) {
    return { projectKey, status: "error", findingsCount: 0, toolsRun: 0, toolsFailed: 0,
      error: `project path not found or not a directory: ${projectPath}` };
  }
  if (!isGitRepo(projectPath)) {
    return { projectKey, status: "error", findingsCount: 0, toolsRun: 0, toolsFailed: 0,
      error: `not a git repo: ${projectPath}` };
  }

  const sha = getHeadSha(projectPath);
  const scratchRoot = mkdtempSync(join(tmpdir(), "agent-security-"));
  try {
    const ctx: ToolContext = {
      sha,
      log,
      scratchDir: scratchRoot,
    };

    const toolsRun: ToolRunRecord[] = [];
    const toolsFailed: ToolRunRecord[] = [];
    const allRaw: RawFinding[] = [];

    for (const tool of REGISTERED_TOOLS) {
      log("info", `running ${tool.name}…`);
      const version = await tool.version();
      try {
        const findings = await tool.run(projectPath, ctx);
        log("info", `  ${tool.name}@${version ?? "?"}: ${findings.length} raw finding(s)`);
        toolsRun.push({ name: tool.name, version });
        allRaw.push(...findings);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log("error", `  ${tool.name} failed: ${msg}`);
        toolsFailed.push({ name: tool.name, version, error: msg });
      }
    }

    if (toolsRun.length === 0) {
      return { projectKey, status: "no-tools-ran", findingsCount: 0,
        toolsRun: 0, toolsFailed: toolsFailed.length,
        error: toolsFailed.map((t) => `${t.name}: ${t.error}`).join("; ") || undefined };
    }

    const triageResult = await triage({
      raws: allRaw,
      projectPath,
      projectKey,
      log,
      claudeClient: opts.claudeClient,
    });
    const findings = sortFindings(triageResult.findings);

    const counts = countSeverities(findings);
    const locAtScan = getTotalLoc(projectPath);
    const locChanged = opts.priorSha ? getLocChangedSince(projectPath, opts.priorSha) : null;

    const output: ScanOutput = {
      project: projectKey,
      kind: "project",
      root: opts.root,
      project_path: projectPath,
      scanner_version: SCANNER_VERSION,
      schema_version: SCHEMA_VERSION,
      triaged: triageResult.triaged,
      last_scanned: new Date().toISOString(),
      last_scanned_sha: sha,
      loc_at_scan: locAtScan,
      loc_changed_since_previous: locChanged,
      tools_run: toolsRun,
      tools_failed: toolsFailed,
      counts,
      findings,
    };

    const jsonPath = findingsPath(opts.findingsDir, projectKey, "json");
    const mdPath = findingsPath(opts.findingsDir, projectKey, "md");

    if (opts.dryRun) {
      log("info", `dry-run: would write ${jsonPath} and ${mdPath}`);
      process.stdout.write(JSON.stringify(output, null, 2) + "\n");
      return { projectKey, status: "ok", findingsCount: findings.length,
        toolsRun: toolsRun.length, toolsFailed: toolsFailed.length };
    }

    writeJson(jsonPath, output);
    writeMarkdown(mdPath, output);
    log("info", `wrote ${jsonPath}`);
    log("info", `wrote ${mdPath}`);

    let commitSha: string | undefined;
    if (!opts.noCommit) {
      commitSha = maybeCommit({
        findingsDir: opts.findingsDir,
        files: [jsonPath, mdPath],
        projectKey,
        sha,
        counts,
        triaged: triageResult.triaged,
        log,
      });
    }

    const report: RunReport = { projectKey, status: "ok", findingsCount: findings.length,
      toolsRun: toolsRun.length, toolsFailed: toolsFailed.length,
      outputPaths: { json: jsonPath, md: mdPath } };
    if (commitSha) report.commitSha = commitSha;
    return report;
  } finally {
    rmSync(scratchRoot, { recursive: true, force: true });
  }
}

function maybeCommit(opts: {
  findingsDir: string;
  files: string[];
  projectKey: string;
  sha: string;
  counts: Record<Severity, number>;
  triaged: boolean;
  log: RunOptions["log"];
}): string | undefined {
  const { findingsDir, files, projectKey, sha, counts, triaged, log } = opts;
  if (!isInsideWorkTree(findingsDir)) {
    log("warn", `findings dir is not inside a git work tree; skipping bot commit`);
    return undefined;
  }
  const totals = SEVERITY_ORDER
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`)
    .join(", ") || "0 findings";
  const triageTag = triaged ? "triaged" : "untriaged";
  const message = `scan(${projectKey}): ${totals} @ ${sha} [${triageTag}]`;
  try {
    const result = commitFindingsFiles({ repoCwd: findingsDir, files, message });
    if (result.committed) {
      log("info", `committed ${result.sha}: ${message}`);
      return result.sha;
    }
    log("info", `no findings change; skipping commit`);
    return undefined;
  } catch (err) {
    log("warn", `bot commit failed: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}

// Resolve a bare project name against the configured roots. Returns the
// first matching root + project_path. Throws if nothing matches.
export function resolveProject(roots: string[], name: string): { root: string; projectPath: string; projectKey: string } {
  const matches: Array<{ root: string; projectPath: string }> = [];
  for (const root of roots) {
    const candidate = join(root, name);
    if (statSync(candidate, { throwIfNoEntry: false })?.isDirectory()) {
      matches.push({ root, projectPath: candidate });
    }
  }
  if (matches.length === 0) {
    throw new Error(`project "${name}" not found under any of: ${roots.join(", ")}`);
  }
  if (matches.length > 1) {
    // Multi-root collision — caller must qualify with the root basename.
    const qualified = matches.map((m) => `${basename(m.root)}/${name}`).join(", ");
    throw new Error(`project "${name}" exists in multiple roots; qualify as one of: ${qualified}`);
  }
  // Single-root mode uses the bare name; multi-root would be qualified explicitly.
  const m = matches[0]!;
  const projectKey = roots.length === 1 ? name : `${basename(m.root)}${sep}${name}`;
  return { root: m.root, projectPath: m.projectPath, projectKey };
}
