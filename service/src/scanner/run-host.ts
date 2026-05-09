// Orchestrates one host scan. Mirrors run.ts → scanProject(): gather
// metadata, run registered host tools, triage, write findings, bot-commit.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import {
  countSeverities,
  hostFindingsPath,
  sortFindings,
  writeHostJson,
  writeHostMarkdown,
} from "./apply.js";
import { commitFindingsFiles, isInsideWorkTree } from "./git.js";
import { gatherHostInfo, type HostInfo } from "./host-info.js";
import type { HostScanOutput } from "./host-types.js";
import type { HostContext, HostToolRunner } from "./tools/host-types.js";
import { TrivyRunner } from "./tools/trivy.js";
import type { RawFinding, ToolRunRecord } from "./tools/types.js";
import { triageHost } from "./triage.js";
import type { Severity } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

const SCANNER_VERSION = "0.1.0";
const SCHEMA_VERSION = 2;

// Hardcoded for v1 — same shape as REGISTERED_TOOLS in run.ts. When a
// second host runner shows up (Lynis, debsecan), reconsider the YAML
// registry sketched in spec/tools.md.
const REGISTERED_HOST_TOOLS: HostToolRunner[] = [new TrivyRunner()];

export interface HostRunOptions {
  // Identity used for findings/hosts/<hostName>.{json,md}.
  hostName: string;
  findingsDir: string;
  // Rootfs to scan. Almost always "/", but threaded through so a test can
  // point at a fixture rootfs.
  rootfs: string;
  dryRun: boolean;
  noCommit: boolean;
  claudeClient: Anthropic | null;
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void;
  // Optional pre-fetched info (the selector reads it once and passes it
  // through so we don't re-shell-out to dpkg-query).
  info?: HostInfo;
  // Optional: prior scan's package_set_sha, so we can populate
  // package_set_changed_since_previous on the output.
  priorPackageSetSha?: string | null;
}

export interface HostRunReport {
  hostName: string;
  status: "ok" | "no-tools-ran" | "error";
  findingsCount: number;
  toolsRun: number;
  toolsFailed: number;
  outputPaths?: { json: string; md: string };
  commitSha?: string;
  error?: string;
}

export async function scanHost(opts: HostRunOptions): Promise<HostRunReport> {
  const { hostName, log } = opts;
  const info = opts.info ?? gatherHostInfo();

  const scratchRoot = mkdtempSync(join(tmpdir(), "agent-security-host-"));
  try {
    const ctx: HostContext = {
      rootfs: opts.rootfs,
      log,
      scratchDir: scratchRoot,
    };

    const toolsRun: ToolRunRecord[] = [];
    const toolsFailed: ToolRunRecord[] = [];
    const allRaw: RawFinding[] = [];

    for (const tool of REGISTERED_HOST_TOOLS) {
      log("info", `running ${tool.name}…`);
      const version = await tool.version();
      const rulesVersion = tool.rulesVersion ? await tool.rulesVersion() : null;
      try {
        const findings = await tool.run(ctx);
        log("info", `  ${tool.name}@${version ?? "?"}: ${findings.length} raw finding(s)`);
        const record: ToolRunRecord = { name: tool.name, version };
        if (rulesVersion) record.rules_version = rulesVersion;
        toolsRun.push(record);
        allRaw.push(...findings);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log("error", `  ${tool.name} failed: ${msg}`);
        const failed: ToolRunRecord = { name: tool.name, version, error: msg };
        if (rulesVersion) failed.rules_version = rulesVersion;
        toolsFailed.push(failed);
      }
    }

    if (toolsRun.length === 0) {
      return {
        hostName, status: "no-tools-ran", findingsCount: 0,
        toolsRun: 0, toolsFailed: toolsFailed.length,
        error: toolsFailed.map((t) => `${t.name}: ${t.error}`).join("; ") || undefined,
      };
    }

    const triageResult = await triageHost({
      raws: allRaw,
      hostName,
      osPrettyName: info.os_release.pretty_name,
      kernelVersion: info.kernel_version,
      architecture: info.architecture,
      packageCount: info.package_count,
      log,
      claudeClient: opts.claudeClient,
    });
    const findings = sortFindings(triageResult.findings);
    const counts = countSeverities(findings);

    let packageSetChanged: boolean | null = null;
    if (opts.priorPackageSetSha !== undefined && opts.priorPackageSetSha !== null) {
      packageSetChanged = info.package_set_sha !== opts.priorPackageSetSha;
    }

    const output: HostScanOutput = {
      host: hostName,
      kind: "host",
      hostname_kernel: info.hostname_kernel,
      os_release: info.os_release,
      kernel_version: info.kernel_version,
      architecture: info.architecture,
      scanner_version: SCANNER_VERSION,
      schema_version: SCHEMA_VERSION,
      triaged: triageResult.triaged,
      last_scanned: new Date().toISOString(),
      package_count: info.package_count,
      package_set_sha: info.package_set_sha,
      package_set_changed_since_previous: packageSetChanged,
      tools_run: toolsRun,
      tools_failed: toolsFailed,
      counts,
      findings,
    };

    const jsonPath = hostFindingsPath(opts.findingsDir, hostName, "json");
    const mdPath = hostFindingsPath(opts.findingsDir, hostName, "md");

    if (opts.dryRun) {
      log("info", `dry-run: would write ${jsonPath} and ${mdPath}`);
      process.stdout.write(JSON.stringify(output, null, 2) + "\n");
      return {
        hostName, status: "ok", findingsCount: findings.length,
        toolsRun: toolsRun.length, toolsFailed: toolsFailed.length,
      };
    }

    writeHostJson(jsonPath, output);
    writeHostMarkdown(mdPath, output);
    log("info", `wrote ${jsonPath}`);
    log("info", `wrote ${mdPath}`);

    let commitSha: string | undefined;
    if (!opts.noCommit) {
      commitSha = maybeCommitHost({
        findingsDir: opts.findingsDir,
        files: [jsonPath, mdPath],
        hostName,
        packageSetSha: info.package_set_sha,
        counts,
        triaged: triageResult.triaged,
        log,
      });
    }

    const report: HostRunReport = {
      hostName, status: "ok", findingsCount: findings.length,
      toolsRun: toolsRun.length, toolsFailed: toolsFailed.length,
      outputPaths: { json: jsonPath, md: mdPath },
    };
    if (commitSha) report.commitSha = commitSha;
    return report;
  } finally {
    rmSync(scratchRoot, { recursive: true, force: true });
  }
}

// Mirrors maybeCommit() in run.ts. Subject form:
//   scan(host:<name>): <totals> @ <pkg-sha-7> [triaged|untriaged]
function maybeCommitHost(opts: {
  findingsDir: string;
  files: string[];
  hostName: string;
  packageSetSha: string;
  counts: Record<Severity, number>;
  triaged: boolean;
  log: HostRunOptions["log"];
}): string | undefined {
  const { findingsDir, files, hostName, packageSetSha, counts, triaged, log } = opts;
  if (!isInsideWorkTree(findingsDir)) {
    log("warn", `findings dir is not inside a git work tree; skipping bot commit`);
    return undefined;
  }
  const totals = SEVERITY_ORDER
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`)
    .join(", ") || "0 findings";
  const triageTag = triaged ? "triaged" : "untriaged";
  const pkgShort = packageSetSha.slice(0, 7) || "no-pkg-sha";
  const message = `scan(host:${hostName}): ${totals} @ ${pkgShort} [${triageTag}]`;
  try {
    const result = commitFindingsFiles({ repoCwd: findingsDir, files, message });
    if (result.committed) {
      log("info", `committed ${result.sha}: ${message}`);
      return result.sha;
    }
    log("info", `no host findings change; skipping commit`);
    return undefined;
  } catch (err) {
    log("warn", `bot commit failed: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}
