// Bundled Semgrep runner. Shells out to the `semgrep` binary, parses --json
// output, and yields RawFinding[]. See spec/tools.md for the contract.

import { spawn } from "node:child_process";
import { relative, isAbsolute, sep, posix } from "node:path";
import type { ToolRunner, ToolContext, RawFinding } from "./types.js";

// Default rulesets. Curated security packs that cover the languages in the
// workspace (JS/TS, Python, Go, Ruby, Java, etc.) plus secrets detection.
const DEFAULT_RULESETS = ["p/security-audit", "p/secrets"];

// Per-project timeout in milliseconds. Aligns with `--timeout` we'd pass to
// semgrep itself (which is per-rule), but applied at the process level.
const PROCESS_TIMEOUT_MS = 5 * 60 * 1000; // 5 min

// Shape of the records inside Semgrep's --json output.results[].
interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col?: number };
  end: { line: number; col?: number };
  extra: {
    message: string;
    severity: string; // ERROR | WARNING | INFO | INVENTORY | EXPERIMENT
    metadata?: {
      references?: string[];
      cwe?: string[] | string;
      owasp?: string[] | string;
    };
    lines?: string;
  };
}

interface SemgrepJsonOutput {
  version?: string;
  results: SemgrepResult[];
  errors?: Array<{ message?: string; type?: string }>;
}

interface SpawnResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

function spawnCapture(cmd: string, args: string[], opts: { cwd?: string; timeoutMs: number }): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, opts.timeoutMs);

    child.stdout.on("data", (b: Buffer) => stdout.push(b));
    child.stderr.on("data", (b: Buffer) => stderr.push(b));

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`semgrep exceeded ${opts.timeoutMs / 1000}s timeout`));
        return;
      }
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

function toPosixRelative(projectPath: string, p: string): string {
  // Semgrep emits paths relative to its CWD when run with cwd set; sometimes
  // absolute when run otherwise. Normalize both shapes.
  const rel = isAbsolute(p) ? relative(projectPath, p) : p;
  return rel.split(sep).join(posix.sep);
}

export class SemgrepRunner implements ToolRunner {
  readonly name = "semgrep";

  async version(): Promise<string | null> {
    try {
      const r = await spawnCapture("semgrep", ["--version"], { timeoutMs: 10_000 });
      if (r.code !== 0) return null;
      const v = r.stdout.trim();
      return v.length > 0 ? v : null;
    } catch {
      return null;
    }
  }

  async run(projectPath: string, ctx: ToolContext): Promise<RawFinding[]> {
    const args = ["--json", "--quiet", "--metrics=off"];
    for (const ruleset of DEFAULT_RULESETS) {
      args.push("--config", ruleset);
    }
    args.push(projectPath);

    ctx.log("debug", `semgrep ${args.join(" ")}`);

    let result: SpawnResult;
    try {
      result = await spawnCapture("semgrep", args, {
        cwd: projectPath,
        timeoutMs: PROCESS_TIMEOUT_MS,
      });
    } catch (err) {
      // ENOENT means the binary isn't installed.
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("ENOENT")) {
        throw new Error(
          "semgrep binary not found in PATH; install with 'pip install semgrep' " +
          "or see https://semgrep.dev/docs/getting-started/",
        );
      }
      throw new Error(`semgrep failed to spawn: ${msg}`);
    }

    // Exit codes:
    //   0 — clean, no findings
    //   1 — findings present (success path)
    //   2 — rule errors; partial results may still be in stdout
    //   other — fail hard
    if (result.code !== 0 && result.code !== 1 && result.code !== 2) {
      const tail = result.stderr.trim().split("\n").slice(-10).join("\n");
      throw new Error(`semgrep exited ${result.code}: ${tail || "(no stderr)"}`);
    }
    if (result.code === 2) {
      ctx.log("warn", `semgrep reported rule errors; parsing partial results. stderr tail:\n${result.stderr.trim().split("\n").slice(-5).join("\n")}`);
    }

    if (result.stdout.trim().length === 0) {
      // Exit 0 with no JSON — treat as zero findings.
      return [];
    }

    let parsed: SemgrepJsonOutput;
    try {
      parsed = JSON.parse(result.stdout) as SemgrepJsonOutput;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`semgrep JSON output unparseable: ${msg}`);
    }

    const findings: RawFinding[] = [];
    for (const r of parsed.results ?? []) {
      const links = r.extra.metadata?.references;
      const finding: RawFinding = {
        source: this.name,
        rule_id: r.check_id,
        severity: r.extra.severity,
        file: toPosixRelative(projectPath, r.path),
        line: r.start.line,
        message: (r.extra.message ?? "").trim(),
        raw: r,
      };
      if (r.end.line && r.end.line !== r.start.line) {
        finding.line_end = r.end.line;
      }
      if (links && links.length > 0) {
        finding.links = links;
      }
      findings.push(finding);
    }
    return findings;
  }
}
