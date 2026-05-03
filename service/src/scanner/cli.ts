// Scanner CLI — milestone 1.
//
// Usage:
//   npm run scanner -- run --project rssreader              # scan one project; write findings/
//   npm run scanner -- run --project rssreader --dry-run    # print to stdout, no write
//
// Future milestones add: run --all (selector), --force, token mgmt.

import "dotenv/config";
import { resolve } from "node:path";
import { resolveProject, scanProject } from "./run.js";

interface CliArgs {
  command: "run";
  project: string | null;
  dryRun: boolean;
}

function usage(): string {
  return [
    "usage: scanner run --project <name> [--dry-run]",
    "",
    "  --project <name>   project directory name under one of PROJECT_ROOTS",
    "  --dry-run          print findings JSON to stdout instead of writing",
    "",
    "env:",
    "  PROJECT_ROOTS      comma-separated absolute paths (default: /home/secorp/termag/projects)",
    "  FINDINGS_DIR       output directory (default: <repo>/findings)",
  ].join("\n");
}

function parseArgs(argv: string[]): CliArgs {
  if (argv.length === 0 || argv[0] !== "run") {
    throw new Error(usage());
  }
  let project: string | null = null;
  let dryRun = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") {
      dryRun = true;
    } else if (a === "--project") {
      project = argv[++i] ?? null;
    } else if (a?.startsWith("--project=")) {
      project = a.slice("--project=".length);
    } else {
      throw new Error(`unknown arg: ${a}\n\n${usage()}`);
    }
  }
  if (!project) throw new Error(`--project is required\n\n${usage()}`);
  return { command: "run", project, dryRun };
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

  const report = await scanProject({
    projectPath,
    root,
    projectKey,
    findingsDir,
    dryRun: args.dryRun,
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
