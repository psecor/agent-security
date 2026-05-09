// Bundled Trivy runner. Shells out to the `trivy` binary in rootfs scan
// mode (`trivy rootfs /`), parses --format json output, and yields
// RawFinding[] for OS-package CVEs. See spec/host-scanning.md.

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { HostContext, HostToolRunner } from "./host-types.js";
import type { RawFinding } from "./types.js";

// Per-host wall-clock timeout. A full rootfs walk over 1k+ packages takes
// longer than a per-project semgrep run, and includes a possible vuln-DB
// pull on cold hosts. Generously sized above trivy's own --timeout so we
// always see trivy's clean error message rather than a kill from us.
const PROCESS_TIMEOUT_MS = 25 * 60 * 1000; // 25 min

interface TrivyVulnerability {
  VulnerabilityID: string;     // "CVE-2026-31431"
  PkgID?: string;              // "openssl@3.0.2-0ubuntu1.18"
  PkgName: string;             // "openssl"
  InstalledVersion: string;    // "3.0.2-0ubuntu1.18"
  FixedVersion?: string;       // "3.0.2-0ubuntu1.19" — absent when no fix yet
  Status?: string;
  Severity: string;            // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  References?: string[];
}

interface TrivyResult {
  Target?: string;
  Class?: string;              // "os-pkgs" for the host scan
  Type?: string;               // "ubuntu", "debian", "alpine", ...
  Vulnerabilities?: TrivyVulnerability[];
}

interface TrivyOutput {
  SchemaVersion?: number;
  Results?: TrivyResult[];
}

interface TrivyVersionOutput {
  Version?: string;
  VulnerabilityDB?: {
    UpdatedAt?: string;        // ISO timestamp of the DB build we'd use
    DownloadedAt?: string;     // when this host pulled it
  };
}

interface SpawnResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

function spawnCapture(cmd: string, args: string[], timeoutMs: number): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args);
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (b: Buffer) => stdout.push(b));
    child.stderr.on("data", (b: Buffer) => stderr.push(b));

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`trivy exceeded ${timeoutMs / 1000}s timeout`));
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

export class TrivyRunner implements HostToolRunner {
  readonly name = "trivy";

  async version(): Promise<string | null> {
    try {
      const r = await spawnCapture("trivy", ["version", "--format", "json"], 10_000);
      if (r.code !== 0) return null;
      const v = parseVersionJson(r.stdout)?.Version;
      return v && v.length > 0 ? v : null;
    } catch {
      return null;
    }
  }

  async rulesVersion(): Promise<string | null> {
    try {
      const r = await spawnCapture("trivy", ["version", "--format", "json"], 10_000);
      if (r.code !== 0) return null;
      const ts = parseVersionJson(r.stdout)?.VulnerabilityDB?.UpdatedAt;
      return ts && ts.length > 0 ? `trivy-db@${ts}` : null;
    } catch {
      return null;
    }
  }

  async run(ctx: HostContext): Promise<RawFinding[]> {
    const reportPath = join(ctx.scratchDir, "trivy.json");
    const args = [
      "rootfs",
      ctx.rootfs,
      "--format", "json",
      "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
      "--quiet",
      // Let trivy manage the vuln-DB lifecycle. It caches the DB locally and
      // only re-downloads when stale (~24h), so back-to-back runs don't pay
      // a full pull, but a fresh install / a host that's been quiet for a
      // week refreshes automatically. Pinning `--skip-db-update` errors out
      // on first-run hosts ("--skip-db-update cannot be specified on the
      // first run") and would require us to bootstrap the DB out-of-band.
      //
      // `--scanners vuln` drops the default secret scanner — host findings
      // here are about OS-package CVEs, not in-tree secrets (Gitleaks owns
      // that on the project side). Without this, trivy walks the entire
      // rootfs reading file contents and routinely hits its own --timeout
      // on a workstation-sized filesystem.
      "--scanners", "vuln",
      // `--pkg-types os` is the modern replacement for the deprecated
      // `--vuln-type os` flag.
      "--pkg-types", "os",
      // Skip kernel pseudo-fs (where rootfs walks fail outright) and the
      // apt mirror cache (which has tens of thousands of small files that
      // contribute nothing to OS-package detection but dominate walk time).
      "--skip-dirs", "/proc,/sys,/dev,/var/lib/apt/lists,/var/cache",
      // Trivy's own internal scan timeout — distinct from PROCESS_TIMEOUT_MS
      // above, which is our wall-clock cap. Default is 5m, which a fresh DB
      // pull plus a slow rootfs walk can blow past on a workstation.
      "--timeout", "20m",
      "--output", reportPath,
    ];

    ctx.log("debug", `trivy ${args.join(" ")}`);

    let result: SpawnResult;
    try {
      result = await spawnCapture("trivy", args, PROCESS_TIMEOUT_MS);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("ENOENT")) {
        throw new Error(
          "trivy binary not found in PATH; install from " +
          "https://aquasecurity.github.io/trivy/ " +
          "(`apt install trivy` on Debian/Ubuntu after adding the Aqua repo)",
        );
      }
      throw new Error(`trivy failed to spawn: ${msg}`);
    }

    // Trivy exit codes:
    //   0 — clean, with or without findings (vulns land in the report file).
    //   other — actual error (DB missing, rootfs unreadable, etc.).
    if (result.code !== 0) {
      const tail = result.stderr.trim().split("\n").slice(-10).join("\n");
      throw new Error(`trivy exited ${result.code}: ${tail || "(no stderr)"}`);
    }

    let raw: string;
    try {
      raw = readFileSync(reportPath, "utf8");
    } catch (err) {
      // Trivy can exit 0 without producing a report when the rootfs has
      // nothing to scan (extremely minimal containers). Treat as zero
      // findings rather than failing the scan.
      ctx.log("debug", `trivy report not found at ${reportPath}: ${err instanceof Error ? err.message : String(err)}`);
      return [];
    }

    if (raw.trim().length === 0) return [];

    let parsed: TrivyOutput;
    try {
      parsed = JSON.parse(raw) as TrivyOutput;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`trivy JSON output unparseable: ${msg}`);
    }

    const findings: RawFinding[] = [];
    for (const r of parsed.Results ?? []) {
      // We only asked for `--vuln-type os`; ignore anything else Trivy might
      // have surfaced anyway (config audits, secret detection, etc.).
      if (r.Class && r.Class !== "os-pkgs") continue;
      for (const v of r.Vulnerabilities ?? []) {
        const links: string[] = [];
        if (v.PrimaryURL) links.push(v.PrimaryURL);
        const finding: RawFinding = {
          source: this.name,
          rule_id: v.VulnerabilityID,
          severity: v.Severity,
          message: (v.Title ?? v.Description ?? v.VulnerabilityID).trim().split("\n")[0]!,
          // file/line intentionally omitted for host findings — see spec.
          raw: v,
        };
        if (links.length > 0) finding.links = links;
        findings.push(finding);
      }
    }
    return findings;
  }
}

function parseVersionJson(stdout: string): TrivyVersionOutput | null {
  const trimmed = stdout.trim();
  if (trimmed.length === 0) return null;
  try {
    return JSON.parse(trimmed) as TrivyVersionOutput;
  } catch {
    return null;
  }
}
