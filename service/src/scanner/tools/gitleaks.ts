// Bundled Gitleaks runner. Shells out to the `gitleaks` binary, reads its
// JSON report file, and yields RawFinding[]. Net-new axis vs. semgrep:
// gitleaks scans git history by default, so a secret that was committed and
// later removed still surfaces. See spec/tools.md for the contract.

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { relative, isAbsolute, sep, posix, join } from "node:path";
import type { ToolRunner, ToolContext, RawFinding } from "./types.js";

const PROCESS_TIMEOUT_MS = 5 * 60 * 1000; // 5 min

// Shape of records inside gitleaks v8 --report-format json output (a JSON
// array — empty when no leaks). Field names are PascalCase per the binary.
interface GitleaksResult {
  Description: string;
  StartLine: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Secret?: string;
  File: string;
  SymlinkFile?: string;
  Commit?: string;
  Entropy?: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  Tags?: string[];
  RuleID: string;
  Fingerprint?: string;
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
        reject(new Error(`gitleaks exceeded ${opts.timeoutMs / 1000}s timeout`));
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
  const rel = isAbsolute(p) ? relative(projectPath, p) : p;
  return rel.split(sep).join(posix.sep);
}

export class GitleaksRunner implements ToolRunner {
  readonly name = "gitleaks";

  async version(): Promise<string | null> {
    try {
      const r = await spawnCapture("gitleaks", ["version"], { timeoutMs: 10_000 });
      if (r.code !== 0) return null;
      const v = r.stdout.trim();
      return v.length > 0 ? v : null;
    } catch {
      return null;
    }
  }

  async run(projectPath: string, ctx: ToolContext): Promise<RawFinding[]> {
    const reportPath = join(ctx.scratchDir, "gitleaks.json");
    const args = [
      "detect",
      "--source", projectPath,
      "--report-format", "json",
      "--report-path", reportPath,
      "--redact",      // mask secret values in the report so they don't land in findings/*.json
      "--no-banner",
      "--exit-code", "1",
    ];

    ctx.log("debug", `gitleaks ${args.join(" ")}`);

    let result: SpawnResult;
    try {
      result = await spawnCapture("gitleaks", args, {
        cwd: projectPath,
        timeoutMs: PROCESS_TIMEOUT_MS,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("ENOENT")) {
        throw new Error(
          "gitleaks binary not found in PATH; install from " +
          "https://github.com/gitleaks/gitleaks/releases (drop into ~/.local/bin or /usr/local/bin)",
        );
      }
      throw new Error(`gitleaks failed to spawn: ${msg}`);
    }

    // Exit codes:
    //   0 — no leaks
    //   1 — leaks found (success path; report still written)
    //   other — fail hard
    if (result.code !== 0 && result.code !== 1) {
      const tail = result.stderr.trim().split("\n").slice(-10).join("\n");
      throw new Error(`gitleaks exited ${result.code}: ${tail || "(no stderr)"}`);
    }

    let raw: string;
    try {
      raw = readFileSync(reportPath, "utf8");
    } catch (err) {
      // No report file means nothing to parse — clean run.
      if (result.code === 0) return [];
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`gitleaks reported leaks but report file unreadable: ${msg}`);
    }

    if (raw.trim().length === 0) return [];

    let parsed: GitleaksResult[];
    try {
      parsed = JSON.parse(raw) as GitleaksResult[];
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`gitleaks JSON output unparseable: ${msg}`);
    }
    if (!Array.isArray(parsed)) return [];

    const findings: RawFinding[] = [];
    for (const r of parsed) {
      // Gitleaks emits StartLine 0 when the leak is in a commit message rather
      // than a file body. Clamp to 1 so downstream line-based source slicing
      // doesn't choke; the message field still names the commit.
      const line = r.StartLine && r.StartLine > 0 ? r.StartLine : 1;
      const finding: RawFinding = {
        source: this.name,
        rule_id: r.RuleID,
        // Gitleaks has no per-finding severity. Synthesize "HIGH" — committed
        // secrets are by default a high-severity class; Claude can downgrade
        // during triage based on context (e.g. test fixtures, redacted strings).
        severity: "HIGH",
        file: toPosixRelative(projectPath, r.File),
        line,
        message: (r.Description ?? "").trim(),
        raw: r,
      };
      if (r.EndLine && r.EndLine !== r.StartLine) {
        finding.line_end = r.EndLine;
      }
      findings.push(finding);
    }
    return findings;
  }
}
