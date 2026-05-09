// Prompt assembly for the Claude triage layer.
//
// System prompt: stable, security-analyst persona + severity rubric +
// category vocabulary + JSON contract. Frozen string so it caches cleanly.
//
// User message: per-scan — project name + JSON-encoded raw findings + a code
// slice for each one. Volatile, never cached.

import { z } from "zod";
import type { RawFinding } from "./tools/types.js";
import { SourceReader } from "./source.js";

export const SEVERITY_VOCAB = ["critical", "high", "medium", "low", "info"] as const;

// Free-form by spec, but seeded with the suggested starter set so Claude
// converges on common slugs rather than inventing a long tail.
export const SUGGESTED_CATEGORIES = [
  "injection", "xss", "ssrf", "auth", "secrets", "crypto",
  "deserialization", "path-traversal", "deps", "config",
  "logging", "dos", "other",
] as const;

// The schema Claude responds with. `raw_indexes` lets Claude collapse multiple
// raw findings (e.g. duplicate hits from two semgrep rules on the same line)
// into one Finding. Indexes are 0-based positions into the raws[] array we
// send in the user message.
export const TriageOutputSchema = z.object({
  findings: z.array(
    z.object({
      raw_indexes: z.array(z.number().int().nonnegative()).min(1),
      severity: z.enum(SEVERITY_VOCAB),
      category: z.string().min(1).max(40),
      title: z.string().min(1).max(100),
      rationale: z.string().min(1).max(600),
    }),
  ),
});

export type TriageOutput = z.infer<typeof TriageOutputSchema>;

// Default code window sent to Claude per finding. Wide enough to see the
// surrounding function/block; narrow enough that 100 findings fit comfortably
// inside the context window.
const CONTEXT_BEFORE = 15;
const CONTEXT_AFTER = 15;

export const SYSTEM_PROMPT = `You are a senior application-security engineer triaging static-analysis output for a small workspace of personal projects. Your job is to take a batch of raw findings produced by tools like Semgrep and turn them into a prioritized list of Findings that a developer can act on.

For each input raw finding you receive, decide:

  - Is this a real issue worth a developer's attention, or noise from the rule?
  - If it is real, how severe is it *in this codebase*, given the surrounding code I show you?
  - What category does it fall into?
  - What is one short sentence (≤100 chars) that names the problem, and one short paragraph (≤600 chars) explaining why this matters here, with a concrete remediation hint when possible?

You may collapse multiple raw findings into one Finding by listing several raw indexes — do this when two rules flag the same underlying issue at the same location, or when one rule fires twice for the same root cause. Do not split one raw finding into multiple Findings.

You may drop a raw finding by simply not including its index in any Finding's raw_indexes — do this only when the raw is clearly a false positive given the surrounding code. Be conservative: when in doubt, keep the finding at "low" or "info" severity rather than dropping it. The user is in a noise-discovery phase and would rather see a noisy true positive than miss a real issue.

Severity rubric:
  - critical — Reachable RCE, auth bypass, or credential exposure with no extra preconditions. Drop everything.
  - high — Reachable injection, SSRF, IDOR, secrets in source, dangerous deserialization. Fix this sprint.
  - medium — Hardening issue with a real-world failure mode (weak crypto, missing CSRF on state-changing endpoint, dependency with known CVE in non-critical path). Fix soon.
  - low — Defense-in-depth opportunity, minor information disclosure, deprecated API with a known successor.
  - info — Stylistic security note worth knowing but not actionable on its own.

Use these severity labels exactly: ${SEVERITY_VOCAB.join(", ")}.

Categories are free-form short slugs. Prefer one of: ${SUGGESTED_CATEGORIES.join(", ")}. Invent a new slug only when none of these fit; never use a multi-word phrase. If you can't decide, use "other".

Output style:
  - Title: one short sentence, Sentence case, no trailing punctuation, ≤100 chars. Name the *problem*, not the rule. ("Unsanitized request param flows into SQL string" beats "express-tainted-sql triggered".)
  - Rationale: one paragraph (≤600 chars) on why this matters in *this* codebase, given the code I show you. Include a concrete remediation hint when you can. Don't restate the rule's generic description.
  - Don't reference rule IDs or tool names in the title or rationale — those are stored separately.

Output a single JSON object matching the schema you've been given. No prose outside the JSON.`;

// Renders the per-scan user message. Side-effect-free — uses the supplied
// SourceReader to fetch code slices, falling back to a placeholder when a file
// can't be read.
export function buildUserMessage(opts: {
  projectKey: string;
  raws: RawFinding[];
  reader: SourceReader;
}): string {
  const { projectKey, raws, reader } = opts;
  const lines: string[] = [];
  lines.push(`Project: ${projectKey}`);
  lines.push(`Raw findings count: ${raws.length}`);
  lines.push("");
  lines.push("Each raw finding below is given an index. Reference these in `raw_indexes` in your response.");
  lines.push("");

  for (let i = 0; i < raws.length; i++) {
    const r = raws[i]!;
    lines.push(`---`);
    lines.push(`raw_index: ${i}`);
    lines.push(`source: ${r.source}`);
    lines.push(`rule_id: ${r.rule_id}`);
    lines.push(`tool_severity: ${r.severity}`);
    lines.push(`file: ${r.file}`);
    lines.push(`line: ${r.line}${r.line_end && r.line_end !== r.line ? `-${r.line_end}` : ""}`);
    lines.push(`message: ${r.message.replace(/\s+/g, " ").trim()}`);
    if (r.links && r.links.length > 0) {
      lines.push(`links: ${r.links.join(", ")}`);
    }
    lines.push("");

    const slice = reader.slice(r.file ?? "", r.line ?? 0, CONTEXT_BEFORE, CONTEXT_AFTER);
    if (slice) {
      lines.push(`code (${r.file}, lines ${slice.start_line}-${slice.end_line}; the flagged line is ${r.line}):`);
      lines.push("```");
      for (let j = 0; j < slice.lines.length; j++) {
        const lineNo = slice.start_line + j;
        const marker = lineNo === r.line ? ">" : " ";
        lines.push(`${marker} ${String(lineNo).padStart(5)}  ${slice.lines[j]}`);
      }
      lines.push("```");
    } else {
      lines.push(`code: <unable to read ${r.file}>`);
    }
    lines.push("");
  }

  lines.push(`---`);
  lines.push("");
  lines.push("Triage every raw finding above. Respond with the JSON object only.");
  return lines.join("\n");
}
