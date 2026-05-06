// Scanner CLI — milestone 3.
//
// Usage:
//   npm run scanner -- run --project rssreader              # one project; write+commit
//   npm run scanner -- run --project rssreader --dry-run    # print to stdout, no write
//   npm run scanner -- run --project rssreader --no-triage  # skip Claude (cheap re-run)
//   npm run scanner -- run --project rssreader --no-commit  # write findings, skip git commit
//   npm run scanner -- run --all                            # selector picks projects above LOC threshold
//   npm run scanner -- run --all --force                    # ignore threshold, scan every discovered project

import "dotenv/config";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import { makeAnthropicClient } from "./claude.js";
import { findingsPath } from "./apply.js";
import { resolveProject, scanProject, type RunReport } from "./run.js";
import { selectProjects, type SelectedProject } from "./select.js";

interface CliArgs {
  command: "run";
  project: string | null;
  all: boolean;
  force: boolean;
  dryRun: boolean;
  noTriage: boolean;
  noCommit: boolean;
}

function usage(): string {
  return [
    "usage: scanner run [--project <name> | --all] [--dry-run] [--no-triage] [--no-commit] [--force]",
    "",
    "  --project <name>   project directory name under one of PROJECT_ROOTS",
    "  --all              scan every project the selector qualifies (LOC threshold)",
    "  --force            with --all: ignore the LOC threshold and scan everything discovered",
    "  --dry-run          print findings JSON to stdout instead of writing (implies --no-commit)",
    "  --no-triage        skip the Claude triage layer (faster, untriaged output)",
    "  --no-commit        write findings to disk but don't auto-commit them",
    "",
    "env:",
    "  PROJECT_ROOTS      comma-separated absolute paths to project roots (required)",
    "  FINDINGS_DIR       output directory (default: <repo>/findings)",
    "  LOC_THRESHOLD      changed-LOC threshold for --all (default: 200)",
    "  ANTHROPIC_API_KEY  required unless --no-triage",
  ].join("\n");
}

function parseArgs(argv: string[]): CliArgs {
  if (argv.length === 0 || argv[0] !== "run") {
    throw new Error(usage());
  }
  let project: string | null = null;
  let all = false;
  let force = false;
  let dryRun = false;
  let noTriage = false;
  let noCommit = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--all") {
      all = true;
    } else if (a === "--force") {
      force = true;
    } else if (a === "--dry-run") {
      dryRun = true;
    } else if (a === "--no-triage") {
      noTriage = true;
    } else if (a === "--no-commit") {
      noCommit = true;
    } else if (a === "--project") {
      project = argv[++i] ?? null;
    } else if (a?.startsWith("--project=")) {
      project = a.slice("--project=".length);
    } else {
      throw new Error(`unknown arg: ${a}\n\n${usage()}`);
    }
  }
  if (!project && !all) {
    throw new Error(`one of --project or --all is required\n\n${usage()}`);
  }
  if (project && all) {
    throw new Error(`--project and --all are mutually exclusive\n\n${usage()}`);
  }
  if (force && !all) {
    throw new Error(`--force only applies with --all\n\n${usage()}`);
  }
  return { command: "run", project, all, force, dryRun, noTriage, noCommit };
}

function getProjectRoots(): string[] {
  const raw = process.env.PROJECT_ROOTS;
  if (!raw) {
    throw new Error(
      "PROJECT_ROOTS must be set — comma-separated absolute paths to the parent dirs " +
      "containing the projects you want to scan.",
    );
  }
  return raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
}

function getFindingsDir(): string {
  if (process.env.FINDINGS_DIR) return resolve(process.env.FINDINGS_DIR);
  // Default: <repo>/findings, where <repo> is two levels up from this file
  // (service/src/scanner/cli.ts → repo root).
  return resolve(new URL("../../../findings", import.meta.url).pathname);
}

function getLocThreshold(): number {
  const raw = process.env.LOC_THRESHOLD;
  if (!raw) return 200;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`invalid LOC_THRESHOLD: ${raw}`);
  }
  return n;
}

function logger(level: "debug" | "info" | "warn" | "error", msg: string): void {
  if (level === "debug" && process.env.SCANNER_DEBUG !== "1") return;
  const prefix = level === "info" ? "" : `[${level}] `;
  process.stderr.write(`${prefix}${msg}\n`);
}

// Read prior_sha from disk for a single-project --project run, so the scan
// output's loc_changed_since_previous can be populated even outside --all.
function readPriorSha(findingsDir: string, projectKey: string): string | null {
  const p = findingsPath(findingsDir, projectKey, "json");
  try {
    const j = JSON.parse(readFileSync(p, "utf8"));
    return typeof j.last_scanned_sha === "string" ? j.last_scanned_sha : null;
  } catch {
    return null;
  }
}

async function runOne(opts: {
  args: CliArgs;
  claudeClient: Anthropic | null;
  findingsDir: string;
  selected: SelectedProject | { root: string; projectPath: string; projectKey: string; prior_sha: string | null };
}): Promise<RunReport> {
  const { args, claudeClient, findingsDir, selected } = opts;
  logger("info", `scanning ${selected.projectKey} at ${selected.projectPath}`);
  return scanProject({
    projectPath: selected.projectPath,
    root: selected.root,
    projectKey: selected.projectKey,
    findingsDir,
    dryRun: args.dryRun,
    noCommit: args.dryRun || args.noCommit,
    claudeClient,
    priorSha: selected.prior_sha,
    log: logger,
  });
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const roots = getProjectRoots();
  const findingsDir = getFindingsDir();
  const locThreshold = getLocThreshold();

  logger("debug", `roots: ${roots.join(", ")}`);
  logger("debug", `findings dir: ${findingsDir}`);
  logger("debug", `LOC threshold: ${locThreshold}`);

  let claudeClient: Anthropic | null = null;
  if (!args.noTriage) {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error("ANTHROPIC_API_KEY not set; pass --no-triage to skip the triage layer");
    }
    claudeClient = makeAnthropicClient();
  }

  const targets: Array<SelectedProject | { root: string; projectPath: string; projectKey: string; prior_sha: string | null }> = [];
  if (args.all) {
    const selected = selectProjects({ roots, findingsDir, locThreshold, force: args.force, log: logger });
    if (selected.length === 0) {
      logger("info", "no projects qualify; nothing to do");
      return;
    }
    targets.push(...selected);
  } else {
    const { root, projectPath, projectKey } = resolveProject(roots, args.project!);
    targets.push({ root, projectPath, projectKey, prior_sha: readPriorSha(findingsDir, projectKey) });
  }

  let okCount = 0;
  let errCount = 0;
  const errors: string[] = [];
  for (const t of targets) {
    try {
      const report = await runOne({ args, claudeClient, findingsDir, selected: t });
      if (report.status === "ok") {
        okCount++;
        process.stderr.write(
          `done: ${report.projectKey}: ${report.findingsCount} findings, ` +
          `${report.toolsRun} tool(s) ran, ${report.toolsFailed} failed` +
          `${report.commitSha ? `, commit ${report.commitSha}` : ""}.\n`,
        );
      } else {
        errCount++;
        const detail = report.error ?? report.status;
        errors.push(`${report.projectKey}: ${detail}`);
        process.stderr.write(`error: ${report.projectKey}: ${detail}\n`);
      }
    } catch (err) {
      errCount++;
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${t.projectKey}: ${msg}`);
      process.stderr.write(`error: ${t.projectKey}: ${msg}\n`);
    }
  }

  if (targets.length > 1) {
    process.stderr.write(`summary: ${okCount} ok, ${errCount} failed\n`);
  }
  if (errCount > 0 && okCount === 0) process.exit(1);
  if (errCount > 0) process.exit(2);
}

main().catch((err) => {
  process.stderr.write(`scanner: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
