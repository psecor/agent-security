// Bundled Trufflehog runner. Shells out to the `trufflehog` binary, parses
// its NDJSON output, and yields RawFinding[]. Net-new axis vs. gitleaks:
// trufflehog has a much larger detector set (LaunchDarkly with no
// surrounding-context requirement, Snowflake credential-triplet detection,
// hundreds of others) plus live API verification — each finding carries a
// `Verified` flag set by the detector pinging the vendor API. We map
// verified leaks to HIGH and unverified to MEDIUM so Claude triage can
// downrank the noisy unverified bucket. Scans full git history, same as
// gitleaks — overlap on common rules (AWS, GitHub PAT, etc.) is expected
// and the triage layer dedupes near-duplicates. See spec/tools.md.

import { spawn } from "node:child_process";
import { relative, isAbsolute, sep, posix } from "node:path";
import type { ToolRunner, ToolContext, RawFinding } from "./types.js";

const PROCESS_TIMEOUT_MS = 10 * 60 * 1000; // 10 min — verification adds API latency

// Shape of one NDJSON record from `trufflehog git --json`. Field names are
// PascalCase per the binary's Go struct tags. Many fields are present only
// for some source/detector combinations; everything past DetectorName is
// optional in practice.
interface TrufflehogResult {
  SourceMetadata?: {
    Data?: {
      Git?: {
        commit?: string;
        file?: string;
        email?: string;
        repository?: string;
        timestamp?: string;
        line?: number;
      };
      Filesystem?: {
        file?: string;
        line?: number;
      };
    };
  };
  SourceID?: number;
  SourceType?: number;
  SourceName?: string;
  DetectorType?: number;
  DetectorName?: string;
  DecoderName?: string;
  Verified?: boolean;
  VerificationError?: string;
  Raw?: string;
  RawV2?: string;
  Redacted?: string;
  ExtraData?: Record<string, unknown> | null;
  StructuredData?: unknown;
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
        reject(new Error(`trufflehog exceeded ${opts.timeoutMs / 1000}s timeout`));
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

// Strip the actual secret material from a TrufflehogResult before stashing
// it in finding.raw — otherwise the secret lands in findings/projects/*.json
// (which is committed to the findings repo and very much should not contain
// live credentials). `Redacted` is the safe field trufflehog populates with
// a masked version.
function scrub(r: TrufflehogResult): TrufflehogResult {
  const { Raw: _Raw, RawV2: _RawV2, ...rest } = r;
  return rest;
}

export class TrufflehogRunner implements ToolRunner {
  readonly name = "trufflehog";

  async version(): Promise<string | null> {
    try {
      const r = await spawnCapture("trufflehog", ["--version"], { timeoutMs: 10_000 });
      // `trufflehog --version` writes to stderr in some builds, stdout in others.
      const v = (r.stdout.trim() || r.stderr.trim()).split("\n")[0]?.trim() ?? "";
      // Output looks like "trufflehog 3.x.y". Strip the leading name if present.
      const cleaned = v.replace(/^trufflehog\s+/i, "");
      return cleaned.length > 0 ? cleaned : null;
    } catch {
      return null;
    }
  }

  async run(projectPath: string, ctx: ToolContext): Promise<RawFinding[]> {
    const args = [
      "git",
      `file://${projectPath}`,
      "--json",
      "--no-update",
    ];

    ctx.log("debug", `trufflehog ${args.join(" ")}`);

    let result: SpawnResult;
    try {
      result = await spawnCapture("trufflehog", args, {
        cwd: projectPath,
        timeoutMs: PROCESS_TIMEOUT_MS,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("ENOENT")) {
        throw new Error(
          "trufflehog binary not found in PATH; install from " +
          "https://github.com/trufflesecurity/trufflehog/releases (drop into ~/.local/bin or /usr/local/bin)",
        );
      }
      throw new Error(`trufflehog failed to spawn: ${msg}`);
    }

    // trufflehog v3 exits 0 whether or not it found leaks (unless --fail is
    // passed). A non-zero code means the run itself failed.
    if (result.code !== 0) {
      const tail = result.stderr.trim().split("\n").slice(-10).join("\n");
      throw new Error(`trufflehog exited ${result.code}: ${tail || "(no stderr)"}`);
    }

    if (result.stdout.trim().length === 0) return [];

    // NDJSON: one JSON object per non-empty line. Trufflehog also writes
    // progress/log lines to stderr (not stdout), so stdout is clean.
    const findings: RawFinding[] = [];
    let parseFailures = 0;
    for (const ndjsonLine of result.stdout.split("\n")) {
      const trimmed = ndjsonLine.trim();
      if (trimmed.length === 0) continue;
      let r: TrufflehogResult;
      try {
        r = JSON.parse(trimmed) as TrufflehogResult;
      } catch {
        parseFailures++;
        continue;
      }
      // Defensive: require at minimum a detector name to consider this a finding.
      if (!r.DetectorName) continue;

      const git = r.SourceMetadata?.Data?.Git;
      const fs = r.SourceMetadata?.Data?.Filesystem;
      const rawFile = git?.file ?? fs?.file ?? "";
      const rawLine = git?.line ?? fs?.line ?? 1;
      const file = rawFile ? toPosixRelative(projectPath, rawFile) : "";
      const line = rawLine > 0 ? rawLine : 1;

      // Severity strategy: trufflehog's value is the verification signal. A
      // verified credential (the detector successfully authenticated against
      // the vendor API just now) is HIGH. An unverified pattern match is
      // MEDIUM — Claude triage can downrank further based on context (test
      // fixtures, sample configs, etc.). Verification errors (network blip,
      // 4xx that isn't 401) are treated as unverified for severity purposes.
      const severity = r.Verified === true ? "HIGH" : "MEDIUM";

      const verifiedTag = r.Verified === true
        ? "verified"
        : r.VerificationError
          ? `unverified (verification error: ${r.VerificationError})`
          : "unverified";

      const commitFrag = git?.commit ? ` @ ${git.commit.slice(0, 7)}` : "";
      const message = `${r.DetectorName} secret detected (${verifiedTag})${commitFrag}`;

      const finding: RawFinding = {
        source: this.name,
        rule_id: `trufflehog:${r.DetectorName}`,
        severity,
        file,
        line,
        message,
        raw: scrub(r),
      };
      findings.push(finding);
    }
    if (parseFailures > 0) {
      ctx.log("warn", `trufflehog: ${parseFailures} unparseable NDJSON line(s) skipped`);
    }
    return findings;
  }
}
