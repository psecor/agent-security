// Milestone-1 placeholder triage: naive severity mapping, category=other,
// title from the tool's message, empty rationale. Stable id derivation is
// real and stays — milestone 2 swaps the rest with Claude-driven triage
// but keeps the same id formula so cross-version equality holds.

import { createHash } from "node:crypto";
import type { RawFinding } from "./tools/types.js";
import type { Finding, Severity } from "./types.js";

export function naiveMapSeverity(toolSeverity: string, source: string): Severity {
  const s = toolSeverity.toUpperCase();
  // Semgrep
  if (source === "semgrep") {
    if (s === "ERROR") return "high";
    if (s === "WARNING") return "medium";
    if (s === "INFO") return "low";
    return "info"; // INVENTORY, EXPERIMENT, unknown
  }
  // Generic fallback for tools using lower-case english labels.
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

export function deriveId(rule_id: string, file: string, lineContext: string): string {
  const h = createHash("sha256");
  h.update(rule_id);
  h.update("\n");
  h.update(file);
  h.update("\n");
  h.update(lineContext);
  return "sha256:" + h.digest("hex");
}

// Best-effort context extractor for stable IDs. For Semgrep, the `lines`
// field on the raw record already gives us the matched span; if the runner
// passed it through we use it. Otherwise we fall back to "file:line" so
// the id is at least project-stable, just less line-shift resistant.
export function extractLineContext(raw: RawFinding): string {
  const r = raw.raw as { extra?: { lines?: string } } | undefined;
  const lines = r?.extra?.lines;
  if (typeof lines === "string" && lines.length > 0) {
    return lines
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0)
      .join("\n");
  }
  return `${raw.file}:${raw.line}`;
}

export function naiveTriage(raw: RawFinding[]): Finding[] {
  return raw.map((r): Finding => {
    const severity = naiveMapSeverity(r.severity, r.source);
    const lineContext = extractLineContext(r);
    const id = deriveId(r.rule_id, r.file, lineContext);
    const title = truncate(r.message.replace(/\s+/g, " ").trim() || r.rule_id, 100);

    const finding: Finding = {
      id,
      severity,
      category: "other",
      title,
      file: r.file,
      line: r.line,
      source: r.source,
      rule_id: r.rule_id,
      rationale: "", // milestone 2 fills this in via Claude
    };
    if (r.line_end !== undefined) finding.line_end = r.line_end;
    if (r.links && r.links.length > 0) finding.links = r.links;
    return finding;
  });
}
