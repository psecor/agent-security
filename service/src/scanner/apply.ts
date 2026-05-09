// JSON + Markdown writers for findings/projects/<project>.{json,md} and
// findings/hosts/<hostname>.{json,md}.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { HostScanOutput } from "./host-types.js";
import type { Finding, ScanOutput, Severity } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

// Subdirectories inside FINDINGS_DIR. The split exists so each scan target
// kind owns its own `git log` subtree and so a hostname can never collide
// with a project name. See spec/findings-schema.md and spec/host-scanning.md.
export const PROJECT_FINDINGS_SUBDIR = "projects";
export const HOST_FINDINGS_SUBDIR = "hosts";

export function findingsPath(findingsDir: string, projectKey: string, ext: "json" | "md"): string {
  // Multi-root qualified keys contain "/"; flatten to "__" for the basename.
  const basename = projectKey.replace(/\//g, "__");
  return join(findingsDir, PROJECT_FINDINGS_SUBDIR, `${basename}.${ext}`);
}

export function hostFindingsPath(findingsDir: string, hostName: string, ext: "json" | "md"): string {
  // Hostnames are normally filesystem-safe, but a misconfigured HOST_NAME
  // env value could escape findings/hosts/. Reject defensively.
  if (hostName.length === 0 || hostName.includes("/") || hostName.includes("..") || hostName.includes("\\")) {
    throw new Error(`invalid host name for findings path: ${JSON.stringify(hostName)}`);
  }
  return join(findingsDir, HOST_FINDINGS_SUBDIR, `${hostName}.${ext}`);
}

export function sortFindings(findings: Finding[]): Finding[] {
  const order: Record<Severity, number> = {
    critical: 0, high: 1, medium: 2, low: 3, info: 4,
  };
  return [...findings].sort((a, b) => {
    const s = order[a.severity] - order[b.severity];
    if (s !== 0) return s;
    const f = (a.file ?? "").localeCompare(b.file ?? "");
    if (f !== 0) return f;
    return (a.line ?? 0) - (b.line ?? 0);
  });
}

export function countSeverities(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function writeJson(path: string, output: ScanOutput): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(output, null, 2) + "\n", "utf8");
}

export function writeMarkdown(path: string, output: ScanOutput): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, renderMarkdown(output), "utf8");
}

export function writeHostJson(path: string, output: HostScanOutput): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(output, null, 2) + "\n", "utf8");
}

export function writeHostMarkdown(path: string, output: HostScanOutput): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, renderHostMarkdown(output), "utf8");
}

export function renderMarkdown(output: ScanOutput): string {
  const totals = totalsLine(output.counts, output.findings.length);
  const triageNote = output.triaged ? "" : " &nbsp;·&nbsp; _untriaged (milestone 1)_";
  const header =
    `_Last scanned ${output.last_scanned} at \`${output.last_scanned_sha}\`; ` +
    `${output.loc_at_scan} LOC; ${output.findings.length} findings (${totals})._${triageNote}`;
  return renderFindingsDoc(
    `Security findings — ${output.project}`,
    header,
    output.findings,
    output.last_scanned,
  );
}

export function renderHostMarkdown(output: HostScanOutput): string {
  const totals = totalsLine(output.counts, output.findings.length);
  const triageNote = output.triaged ? "" : " &nbsp;·&nbsp; _untriaged_";
  const header =
    `_Last scanned ${output.last_scanned}; ${output.os_release.pretty_name} ` +
    `kernel \`${output.kernel_version}\`; ${output.package_count} packages; ` +
    `${output.findings.length} findings (${totals})._${triageNote}`;
  return renderFindingsDoc(
    `Security findings — ${output.host} (host)`,
    header,
    output.findings,
    output.last_scanned,
  );
}

function totalsLine(counts: Record<Severity, number>, total: number): string {
  if (total === 0) return "0 findings";
  return SEVERITY_ORDER
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`)
    .join(", ") || "0 findings";
}

function renderFindingsDoc(
  title: string,
  headerLine: string,
  findings: Finding[],
  lastScanned: string,
): string {
  const lines: string[] = [];
  lines.push(`# ${title}`);
  lines.push("");
  lines.push(headerLine);
  lines.push("");

  if (findings.length === 0) {
    lines.push(`_No findings as of ${lastScanned}._`);
    lines.push("");
    return lines.join("\n");
  }

  for (const sev of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    lines.push(`## ${capitalize(sev)}`);
    lines.push("");
    for (const f of group) {
      lines.push(`### ${f.title}`);
      const meta: string[] = [];
      if (f.file) {
        const where = f.line_end && f.line_end !== f.line
          ? `${f.file}:${f.line}-${f.line_end}`
          : f.line !== undefined ? `${f.file}:${f.line}` : f.file;
        meta.push(`**File:** \`${where}\``);
      }
      if (f.package) {
        // Host findings: show the package + version transition. fixed_version
        // null means "advisory has no patched version yet" — meaningful, not
        // missing data.
        const installed = f.installed_version ?? "?";
        const pkg = f.fixed_version
          ? `\`${f.package}\` ${installed} → ${f.fixed_version}`
          : `\`${f.package}\` ${installed} _(no fix yet)_`;
        meta.push(`**Package:** ${pkg}`);
      }
      meta.push(`**Source:** \`${f.source}\``);
      meta.push(`**Rule:** \`${f.rule_id}\``);
      meta.push(`**Category:** \`${f.category}\``);
      lines.push(meta.join(" &nbsp; "));
      lines.push("");
      if (f.rationale) {
        lines.push(f.rationale);
        lines.push("");
      }
      if (f.links && f.links.length > 0) {
        lines.push("References:");
        for (const l of f.links) lines.push(`- ${l}`);
        lines.push("");
      }
    }
  }
  return lines.join("\n");
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
