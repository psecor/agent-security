// Scanner CLI — milestone 2.
//
// Usage:
//   npm run scanner -- run --project rssreader              # scan + Claude triage; write findings/
//   npm run scanner -- run --project rssreader --dry-run    # print to stdout, no write
//   npm run scanner -- run --project rssreader --no-triage  # skip Claude (cheap re-run)
//
// Future milestones add: run --all (selector), --force, token mgmt.

import "dotenv/config";
import { resolve } from "node:path";
import { makeAnthropicClient } from "./claude.js";
import { resolveProject, scanProject } from "./run.js";

interface CliArgs {
  command: "run";
  project: string | null;
  dryRun: boolean;
  noTriage: boolean;
}

function usage(): string {
  return [
    "usage: scanner run --project <name> [--dry-run] [--no-triage]",
    "",
    "  --project <name>   project directory name under one of PROJECT_ROOTS",
    "  --dry-run          print findings JSON to stdout instead of writing",
    "  --no-triage        skip the Claude triage layer (faster, untriaged output)",
    "",
    "env:",
    "  PROJECT_ROOTS      comma-separated absolute paths (default: /home/secorp/termag/projects)",
    "  FINDINGS_DIR       output directory (default: <repo>/findings)",
    "  ANTHROPIC_API_KEY  required unless --no-triage",
  ].join("\n");
}

function parseArgs(argv: string[]): CliArgs {
  if (argv.length === 0 || argv[0] !== "run") {
    throw new Error(usage());
  }
  let project: string | null = null;
  let dryRun = false;
  let noTriage = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") {
      dryRun = true;
    } else if (a === "--no-triage") {
      noTriage = true;
    } else if (a === "--project") {
      project = argv[++i] ?? null;
    } else if (a?.startsWith("--project=")) {
      project = a.slice("--project=".length);
    } else {
      throw new Error(`unknown arg: ${a}\n\n${usage()}`);
    }
  }
  if (!project) throw new Error(`--project is required\n\n${usage()}`);
  return { command: "run", project, dryRun, noTriage };
}

function getProjectRoots(): string[] {
  const raw = process.env.PROJECT_ROOTS ?? "/home/secorp/termag/projects";
  return raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
}

function getFindingsDir(): string {
  if (process.env.FINDINGS_DIR) return resolve(process.env.FINDINGS_DIR);
  // Default: <repo>/findings, where <repo> is two levels up from this file
  // (service/src/scanner/cli.ts → repo root).
  return resolve(new URL("../../../findings", import.meta.url).pathname);
}

function logger(level: "debug" | "info" | "warn" | "error", msg: string): void {
  if (level === "debug" && process.env.SCANNER_DEBUG !== "1") return;
  const prefix = level === "info" ? "" : `[${level}] `;
  process.stderr.write(`${prefix}${msg}\n`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const roots = getProjectRoots();
  const findingsDir = getFindingsDir();

  logger("debug", `roots: ${roots.join(", ")}`);
  logger("debug", `findings dir: ${findingsDir}`);

  const { root, projectPath, projectKey } = resolveProject(roots, args.project!);
  logger("info", `scanning ${projectKey} at ${projectPath}`);

  let claudeClient = null;
  if (!args.noTriage) {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error("ANTHROPIC_API_KEY not set; pass --no-triage to skip the triage layer");
    }
    claudeClient = makeAnthropicClient();
  }

  const report = await scanProject({
    projectPath,
    root,
    projectKey,
    findingsDir,
    dryRun: args.dryRun,
    claudeClient,
    log: logger,
  });

  if (report.status === "error") {
    process.stderr.write(`error: ${report.error}\n`);
    process.exit(1);
  }
  if (report.status === "no-tools-ran") {
    process.stderr.write(`no tools ran successfully${report.error ? `: ${report.error}` : ""}\n`);
    process.exit(2);
  }
  process.stderr.write(
    `done: ${report.findingsCount} findings, ${report.toolsRun} tool(s) ran, ${report.toolsFailed} failed.\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`scanner: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
