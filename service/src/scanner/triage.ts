// Triage layer. Two modes:
//
//   - Claude (default in milestone 2+): a single API call ranks severity,
//     names the problem, writes a per-codebase rationale, and may collapse or
//     drop noisy raws. Sets `triaged: true` on the output.
//   - Naive (milestone 1, retained for --no-triage and as a fallback): straight
//     pass-through with mechanical severity mapping. Sets `triaged: false`.
//
// `deriveId` and the line-context formula are deliberately stable across both
// modes — Claude doesn't see ids; we compute them from `raw_indexes[0]` so a
// finding's id is the same whether it came from Claude or the naive fallback.

import { createHash } from "node:crypto";
import type Anthropic from "@anthropic-ai/sdk";
import type { RawFinding } from "./tools/types.js";
import type { Finding, Severity } from "./types.js";
import { triageWithClaude, type TriageUsage } from "./claude.js";
import { SourceReader, normalizedLineContext } from "./source.js";

export interface TriageInput {
  raws: RawFinding[];
  projectPath: string;
  projectKey: string;
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void;
  // When supplied, use Claude. When null, fall back to naive triage.
  claudeClient: Anthropic | null;
}

export interface TriageResult {
  findings: Finding[];
  triaged: boolean;
  usage: TriageUsage | null;
}

export async function triage(input: TriageInput): Promise<TriageResult> {
  const reader = new SourceReader(input.projectPath);
  if (input.raws.length === 0) {
    return { findings: [], triaged: input.claudeClient !== null, usage: null };
  }
  if (input.claudeClient) {
    const { parsed, usage } = await triageWithClaude({
      client: input.claudeClient,
      projectKey: input.projectKey,
      projectPath: input.projectPath,
      raws: input.raws,
      log: input.log,
    });
    return {
      findings: assembleFromClaude(parsed.findings, input.raws, reader, input.log),
      triaged: true,
      usage,
    };
  }
  return { findings: naiveTriage(input.raws, reader), triaged: false, usage: null };
}

export function deriveId(rule_id: string, file: string, lineContext: string): string {
  const h = createHash("sha256");
  h.update(rule_id);
  h.update("\n");
  h.update(file);
  h.update("\n");
  h.update(lineContext);
  return "sha256:" + h.digest("hex");
}

export function naiveMapSeverity(toolSeverity: string, source: string): Severity {
  const s = toolSeverity.toUpperCase();
  if (source === "semgrep") {
    if (s === "ERROR") return "high";
    if (s === "WARNING") return "medium";
    if (s === "INFO") return "low";
    return "info";
  }
  if (s === "CRITICAL") return "critical";
  if (s === "HIGH") return "high";
  if (s === "MEDIUM" || s === "MODERATE") return "medium";
  if (s === "LOW") return "low";
  return "info";
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1).trimEnd() + "…";
}

export function naiveTriage(raws: RawFinding[], reader: SourceReader): Finding[] {
  // Project-scan triage path: every project-side runner (Semgrep, Gitleaks)
  // populates file + line, so the ?? "" / ?? 0 fallbacks here are belt-and-
  // suspenders to satisfy the now-optional RawFinding shape rather than a
  // real expected case. Host findings go through a separate triage function.
  return raws.map((r): Finding => {
    const file = r.file ?? "";
    const line = r.line ?? 0;
    const lineContext = normalizedLineContext(reader, file, line);
    const id = deriveId(r.rule_id, file, lineContext);
    const title = truncate(r.message.replace(/\s+/g, " ").trim() || r.rule_id, 100);
    const finding: Finding = {
      id,
      severity: naiveMapSeverity(r.severity, r.source),
      category: "other",
      title,
      file,
      line,
      source: r.source,
      rule_id: r.rule_id,
      rationale: "",
    };
    if (r.line_end !== undefined) finding.line_end = r.line_end;
    if (r.links && r.links.length > 0) finding.links = r.links;
    return finding;
  });
}

interface ClaudeFinding {
  raw_indexes: number[];
  severity: Severity;
  category: string;
  title: string;
  rationale: string;
}

function assembleFromClaude(
  triaged: ClaudeFinding[],
  raws: RawFinding[],
  reader: SourceReader,
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void,
): Finding[] {
  const findings: Finding[] = [];
  const seenIndexes = new Set<number>();

  for (const t of triaged) {
    const validIndexes = t.raw_indexes.filter((i) => Number.isInteger(i) && i >= 0 && i < raws.length);
    if (validIndexes.length === 0) {
      log("warn", `claude: dropped triaged finding with no valid raw_indexes: ${t.title}`);
      continue;
    }
    for (const i of validIndexes) seenIndexes.add(i);

    // Canonical raw is the first listed index — its rule_id and file/line
    // anchor the id and the file:line shown in the report.
    const canonical = raws[validIndexes[0]!]!;
    const file = canonical.file ?? "";
    const line = canonical.line ?? 0;
    const lineContext = normalizedLineContext(reader, file, line);
    const id = deriveId(canonical.rule_id, file, lineContext);

    const finding: Finding = {
      id,
      severity: t.severity,
      category: t.category,
      title: t.title.replace(/\s+/g, " ").trim(),
      file,
      line,
      source: canonical.source,
      rule_id: canonical.rule_id,
      rationale: t.rationale.trim(),
    };
    if (canonical.line_end !== undefined) finding.line_end = canonical.line_end;
    if (canonical.links && canonical.links.length > 0) finding.links = canonical.links;
    findings.push(finding);
  }

  const dropped = raws.length - seenIndexes.size;
  if (dropped > 0) {
    log("info", `claude: dropped ${dropped} raw finding(s) as false positives or noise`);
  }
  return findings;
}
