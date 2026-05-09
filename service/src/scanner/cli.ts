// Scanner CLI — milestone 3 + host scanning (task #42).
//
// Usage:
//   npm run scanner -- run --project rssreader              # one project; write+commit
//   npm run scanner -- run --project rssreader --dry-run    # print to stdout, no write
//   npm run scanner -- run --project rssreader --no-triage  # skip Claude (cheap re-run)
//   npm run scanner -- run --project rssreader --no-commit  # write findings, skip git commit
//   npm run scanner -- run --all                            # selector picks projects above LOC threshold
//   npm run scanner -- run --all --force                    # ignore threshold, scan every discovered project
//   npm run scanner -- run --host                           # scan this host's installed packages (Trivy)
//   npm run scanner -- run --host --force                   # bypass the host selector's daily floor

import "dotenv/config";
import { hostname as osHostname } from "node:os";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import { makeAnthropicClient } from "./claude.js";
import { findingsPath } from "./apply.js";
import { resolveProject, scanProject, type RunReport } from "./run.js";
import { selectProjects, type SelectedProject } from "./select.js";
import { scanHost, type HostRunReport } from "./run-host.js";
import { selectHost } from "./select-host.js";

interface CliArgs {
  command: "run";
  project: string | null;
  all: boolean;
  host: boolean;
  force: boolean;
  dryRun: boolean;
  noTriage: boolean;
  noCommit: boolean;
}

function usage(): string {
  return [
    "usage: scanner run [--project <name> | --all | --host] [--dry-run] [--no-triage] [--no-commit] [--force]",
    "",
    "  --project <name>   project directory name under one of PROJECT_ROOTS",
    "  --all              scan every project the selector qualifies (LOC threshold);",
    "                     also scans this host when SCAN_HOST=true",
    "  --host             scan this host's installed packages (Trivy → CVEs)",
    "  --force            with --all: ignore the LOC threshold and scan everything discovered;",
    "                     with --host: bypass the package-set / daily-floor selector",
    "  --dry-run          print findings JSON to stdout instead of writing (implies --no-commit)",
    "  --no-triage        skip the Claude triage layer (faster, untriaged output)",
    "  --no-commit        write findings to disk but don't auto-commit them",
    "",
    "env:",
    "  PROJECT_ROOTS      comma-separated absolute paths to project roots (required for --project/--all)",
    "  FINDINGS_DIR       output directory (default: <repo>/findings)",
    "  LOC_THRESHOLD      changed-LOC threshold for --all (default: 200)",
    "  HOST_NAME          identity used for findings/hosts/<name>.{json,md} (default: os.hostname())",
    "  SCAN_HOST          when true, --all also scans this host (default: false)",
    "  ANTHROPIC_API_KEY  required unless --no-triage",
  ].join("\n");
}

function parseArgs(argv: string[]): CliArgs {
  if (argv.length === 0 || argv[0] !== "run") {
    throw new Error(usage());
  }
  let project: string | null = null;
  let all = false;
  let host = false;
  let force = false;
  let dryRun = false;
  let noTriage = false;
  let noCommit = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--all") {
      all = true;
    } else if (a === "--host") {
      host = true;
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
  const modes = [project !== null, all, host].filter(Boolean).length;
  if (modes === 0) {
    throw new Error(`one of --project, --all, or --host is required\n\n${usage()}`);
  }
  if (modes > 1) {
    throw new Error(`--project, --all, and --host are mutually exclusive\n\n${usage()}`);
  }
  if (force && !all && !host) {
    throw new Error(`--force only applies with --all or --host\n\n${usage()}`);
  }
  return { command: "run", project, all, host, force, dryRun, noTriage, noCommit };
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

// HOST_NAME defaults to the kernel's view of the hostname (same as `uname -n`).
// Override when the OS hostname doesn't match how this machine is known to the
// findings repo — e.g. in a container that inherits its host's hostname.
function getHostName(): string {
  const raw = process.env.HOST_NAME;
  if (raw && raw.trim().length > 0) return raw.trim();
  return osHostname();
}

function getScanHost(): boolean {
  const raw = process.env.SCAN_HOST;
  if (!raw) return false;
  return raw === "1" || raw.toLowerCase() === "true" || raw.toLowerCase() === "yes";
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

async function runHost(opts: {
  args: CliArgs;
  claudeClient: Anthropic | null;
  findingsDir: string;
  hostName: string;
  // selector output: when present, gives us the prior package-set sha so the
  // output can populate package_set_changed_since_previous. When null, we're
  // forced (or this is a manual --host run) and we just scan unconditionally.
  selection: ReturnType<typeof selectHost> | null;
}): Promise<HostRunReport> {
  const { args, claudeClient, findingsDir, hostName, selection } = opts;
  logger("info", `scanning host ${hostName}${selection ? ` (${selection.reason})` : ""}`);
  const runOpts: Parameters<typeof scanHost>[0] = {
    hostName,
    findingsDir,
    rootfs: "/",
    dryRun: args.dryRun,
    noCommit: args.dryRun || args.noCommit,
    claudeClient,
    log: logger,
  };
  if (selection) {
    runOpts.info = selection.info;
    runOpts.priorPackageSetSha = selection.prior_package_set_sha;
  }
  return scanHost(runOpts);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const findingsDir = getFindingsDir();

  logger("debug", `findings dir: ${findingsDir}`);

  let claudeClient: Anthropic | null = null;
  if (!args.noTriage) {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error("ANTHROPIC_API_KEY not set; pass --no-triage to skip the triage layer");
    }
    claudeClient = makeAnthropicClient();
  }

  // ── Host-only path ─────────────────────────────────────────────────────────
  if (args.host) {
    const hostName = getHostName();
    const selection = selectHost({ hostName, findingsDir, force: args.force, log: logger });
    if (!selection.qualifies) {
      logger("info", `host ${hostName}: ${selection.reason}; skipping (use --force to override)`);
      return;
    }
    const report = await runHost({ args, claudeClient, findingsDir, hostName, selection });
    if (report.status === "ok") {
      process.stderr.write(
        `done: host:${report.hostName}: ${report.findingsCount} findings, ` +
        `${report.toolsRun} tool(s) ran, ${report.toolsFailed} failed` +
        `${report.commitSha ? `, commit ${report.commitSha}` : ""}.\n`,
      );
      return;
    }
    const detail = report.error ?? report.status;
    process.stderr.write(`error: host:${report.hostName}: ${detail}\n`);
    process.exit(1);
    return;
  }

  // ── Project paths (--project / --all) ──────────────────────────────────────
  const roots = getProjectRoots();
  const locThreshold = getLocThreshold();
  logger("debug", `roots: ${roots.join(", ")}`);
  logger("debug", `LOC threshold: ${locThreshold}`);

  const targets: Array<SelectedProject | { root: string; projectPath: string; projectKey: string; prior_sha: string | null }> = [];
  if (args.all) {
    const selected = selectProjects({ roots, findingsDir, locThreshold, force: args.force, log: logger });
    targets.push(...selected);
  } else {
    const { root, projectPath, projectKey } = resolveProject(roots, args.project!);
    targets.push({ root, projectPath, projectKey, prior_sha: readPriorSha(findingsDir, projectKey) });
  }

  // For --all, also schedule a host scan when SCAN_HOST=true. The selector
  // gates on package-set-sha + daily floor; --force passes through.
  let hostTask: { hostName: string; selection: ReturnType<typeof selectHost> } | null = null;
  if (args.all && getScanHost()) {
    const hostName = getHostName();
    const selection = selectHost({ hostName, findingsDir, force: args.force, log: logger });
    if (selection.qualifies) {
      hostTask = { hostName, selection };
    } else {
      logger("info", `host ${hostName}: ${selection.reason}; skipping`);
    }
  }

  if (targets.length === 0 && !hostTask) {
    logger("info", "nothing qualifies; nothing to do");
    return;
  }

  let okCount = 0;
  let errCount = 0;
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
        process.stderr.write(`error: ${report.projectKey}: ${detail}\n`);
      }
    } catch (err) {
      errCount++;
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`error: ${t.projectKey}: ${msg}\n`);
    }
  }

  if (hostTask) {
    try {
      const report = await runHost({
        args, claudeClient, findingsDir,
        hostName: hostTask.hostName,
        selection: hostTask.selection,
      });
      if (report.status === "ok") {
        okCount++;
        process.stderr.write(
          `done: host:${report.hostName}: ${report.findingsCount} findings, ` +
          `${report.toolsRun} tool(s) ran, ${report.toolsFailed} failed` +
          `${report.commitSha ? `, commit ${report.commitSha}` : ""}.\n`,
        );
      } else {
        errCount++;
        const detail = report.error ?? report.status;
        process.stderr.write(`error: host:${report.hostName}: ${detail}\n`);
      }
    } catch (err) {
      errCount++;
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`error: host:${hostTask.hostName}: ${msg}\n`);
    }
  }

  const total = targets.length + (hostTask ? 1 : 0);
  if (total > 1) {
    process.stderr.write(`summary: ${okCount} ok, ${errCount} failed\n`);
  }
  if (errCount > 0 && okCount === 0) process.exit(1);
  if (errCount > 0) process.exit(2);
}

main().catch((err) => {
  process.stderr.write(`scanner: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
