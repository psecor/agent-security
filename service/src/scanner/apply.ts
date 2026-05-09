// JSON + Markdown writers for findings/projects/<project>.{json,md}.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding, ScanOutput, Severity } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

// Subdirectory inside FINDINGS_DIR where project scan output lives.
// Host scan output lives alongside this in `hosts/` — see spec/host-scanning.md.
export const PROJECT_FINDINGS_SUBDIR = "projects";

export function findingsPath(findingsDir: string, projectKey: string, ext: "json" | "md"): string {
  // Multi-root qualified keys contain "/"; flatten to "__" for the basename.
  const basename = projectKey.replace(/\//g, "__");
  return join(findingsDir, PROJECT_FINDINGS_SUBDIR, `${basename}.${ext}`);
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

export function renderMarkdown(output: ScanOutput): string {
  const lines: string[] = [];
  lines.push(`# Security findings — ${output.project}`);
  lines.push("");

  const totals = SEVERITY_ORDER
    .filter((s) => output.counts[s] > 0)
    .map((s) => `${output.counts[s]} ${s}`)
    .join(", ") || "0 findings";

  const triageNote = output.triaged ? "" : " &nbsp;·&nbsp; _untriaged (milestone 1)_";
  lines.push(
    `_Last scanned ${output.last_scanned} at \`${output.last_scanned_sha}\`; ` +
    `${output.loc_at_scan} LOC; ${output.findings.length} findings (${totals})._${triageNote}`,
  );
  lines.push("");

  if (output.findings.length === 0) {
    lines.push(`_No findings as of ${output.last_scanned}._`);
    lines.push("");
    return lines.join("\n");
  }

  for (const sev of SEVERITY_ORDER) {
    const group = output.findings.filter((f) => f.severity === sev);
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
