// Orchestrates one project's scan: resolve paths, run tools, triage,
// write findings/<project>.{json,md}.

import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, sep } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import { getHeadSha, isGitRepo } from "./git.js";
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
import type { ScanOutput } from "./types.js";

const SCANNER_VERSION = "0.1.0";
const SCHEMA_VERSION = 1;

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
  error?: string;
}

const REGISTERED_TOOLS: ToolRunner[] = [new SemgrepRunner()];

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

    const output: ScanOutput = {
      project: projectKey,
      root: opts.root,
      project_path: projectPath,
      scanner_version: SCANNER_VERSION,
      schema_version: SCHEMA_VERSION,
      triaged: triageResult.triaged,
      last_scanned: new Date().toISOString(),
      last_scanned_sha: sha,
      loc_at_scan: 0, // populated by milestone 3 (LOC selector)
      loc_changed_since_previous: null,
      tools_run: toolsRun,
      tools_failed: toolsFailed,
      counts: countSeverities(findings),
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

    return { projectKey, status: "ok", findingsCount: findings.length,
      toolsRun: toolsRun.length, toolsFailed: toolsFailed.length,
      outputPaths: { json: jsonPath, md: mdPath } };
  } finally {
    rmSync(scratchRoot, { recursive: true, force: true });
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
