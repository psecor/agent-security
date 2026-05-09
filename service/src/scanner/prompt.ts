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

// Host-side category vocab. spec/host-scanning.md → "Categories" introduces
// these three slugs to keep "different fix routes for different categories"
// legible (apt upgrade vs. kernel reboot vs. /etc edit). `host-config` is
// reserved for future Lynis-style audit findings; v1 only emits
// `package-cve` and `kernel-cve` from Trivy.
export const HOST_SUGGESTED_CATEGORIES = [
  "package-cve", "kernel-cve", "host-config", "other",
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

// Host triage system prompt. Mirrors SYSTEM_PROMPT's structure but tuned for
// CVE-vs-installed-package decisions: severity is about reachability on this
// specific host (running services, exposed surface), and rationale must end
// with the operator-actionable fix route (`apt upgrade …`, kernel reboot,
// `/etc` edit). Frozen string so it caches cleanly across daily runs.
export const HOST_SYSTEM_PROMPT = `You are a senior security engineer triaging host-vulnerability scanner output for a small fleet of personal-use Linux hosts. Each input describes a CVE that a tool like Trivy has matched against an installed OS package on a specific host. Your job is to turn that batch into a prioritized list of Findings the operator can act on.

You will be given:
  - Host metadata: hostname, OS pretty-name, kernel version, architecture, package count.
  - One entry per CVE. Each entry lists every installed package the CVE matched, with installed and fixed versions, the tool's severity band, and the advisory URL when available.

For each input CVE you receive, decide:
  - How severe is this *on this host*, given what's running there and which packages are affected? A CVE in a kernel module that the host actually loads is more severe than the same CVE in a header package shipped only as build-time scaffolding.
  - What category does it fall into?
  - One short sentence (≤100 chars) that names the problem.
  - One short paragraph (≤600 chars) explaining why it matters here, and ending with the specific operator command(s) to fix it.

You may collapse multiple input CVEs into one Finding by listing several raw indexes — do this when two CVE IDs describe the same underlying flaw (same root cause, same fix). Do not split one input into multiple Findings.

You may drop an input CVE by simply not including its index in any Finding's raw_indexes — do this only when the CVE is clearly inapplicable to this host (e.g. tagged "will_not_fix" upstream and the affected component is not actually used). Be conservative: when in doubt, keep at "low" rather than dropping.

Severity rubric for hosts:
  - critical — Reachable RCE or auth bypass against a network-exposed service or the kernel; no preconditions. Treat as page-now.
  - high — Reachable exploit against a service the host runs (kernel, sshd, openssl, apache, postgres, etc.) or against the host's TLS/auth chain. Patch this week.
  - medium — Real CVE in an installed package, but reachability is limited (the package is installed but the vulnerable code path requires a non-default config, or the service isn't network-exposed). Patch on next maintenance window.
  - low — Latent: the affected component is a build-time-only header, an unused locale, or a documentation/i18n package; or the CVE is purely informational ("hardening" CVEs with no exploit path).
  - info — Advisory note, no exploit, no fix needed.

Use these severity labels exactly: ${SEVERITY_VOCAB.join(", ")}.

Categories — pick one of these short slugs:
${HOST_SUGGESTED_CATEGORIES.map((c) => `  - ${c}`).join("\n")}
  - kernel-cve when every affected package is in the linux-* family (linux-image, linux-headers-*, linux-modules-*, linux-firmware, …) — fix is "apt upgrade linux-image-* and reboot".
  - package-cve when the affected package is a normal userspace package (openssl, libxml2, curl, …) — fix is "apt upgrade <pkg>" plus restarting any service that links the library.
  - host-config for Lynis-style audit findings (ssh weak ciphers, world-writable /etc, etc.) — not produced by Trivy, but reserved.
  - other only if none of the above fit.

If you can't decide, use "other". Never use a multi-word phrase.

Output style:
  - Title: one sentence, Sentence case, no trailing punctuation, ≤100 chars. Name the *problem* concretely. Include the package name when it disambiguates ("openssl: TLS handshake DoS via malformed extension"). Do NOT just paste the CVE ID — that's stored separately.
  - Rationale: one paragraph (≤600 chars). Open with reachability on this host (what's exposed, what runs). Close with the exact remediation command. Examples:
      "Reachable from any TLS-terminating service on this host (Apache :443, agent-security :3046 behind it). Fix: \`sudo apt upgrade openssl libssl3\` then \`sudo systemctl restart apache2\`."
      "Affects the running 6.8.0-107-generic kernel. The flawed code path is in the io_uring subsystem, which this host's user-mode services do not use. Fix on next maintenance window: \`sudo apt upgrade linux-image-generic && sudo reboot\`."
  - Don't reference CVE IDs, rule IDs, or tool names in the title or rationale — those are stored separately on each materialized Finding.

Output a single JSON object matching the schema you've been given. No prose outside the JSON.`;

// One entry per CVE that we send to Claude. Multiple raw findings on the
// same CVE (e.g. CVE-2024-XXXX hitting linux-headers-A, linux-headers-B, …)
// collapse into one CveGroup so Claude analyses each CVE once and we
// fan-out the verdict across all the per-package raws afterwards.
export interface CveGroup {
  cve: string;
  // Trivy's tool-native severity for the group. All raws in a group should
  // share this since they're keyed off the same CVE record; we still pass
  // it through so Claude can ground its verdict in what the tool said.
  tool_severity: string;
  primary_url: string | null;
  // The first raw's `message` (Trivy's `Title` field). Same caveat as
  // tool_severity — same CVE, same advisory, same title across packages.
  advisory_title: string | null;
  // Every (package, installed_version, fixed_version) tuple under this CVE.
  // The list length is the kernel-headers-explosion fanout: a single CVE
  // can land here with 50 entries when it hits every linux-headers-* on
  // a box.
  affected: Array<{
    package: string;
    installed_version: string;
    fixed_version: string | null;
  }>;
}

export interface HostUserMessageOpts {
  hostName: string;
  osPrettyName: string;
  kernelVersion: string;
  architecture: string;
  packageCount: number;
  groups: CveGroup[];
}

export function buildHostUserMessage(opts: HostUserMessageOpts): string {
  const lines: string[] = [];
  lines.push(`Host: ${opts.hostName}`);
  lines.push(`OS: ${opts.osPrettyName}`);
  lines.push(`Kernel: ${opts.kernelVersion} (${opts.architecture})`);
  lines.push(`Installed packages: ${opts.packageCount}`);
  lines.push(`CVE groups: ${opts.groups.length}`);
  lines.push("");
  lines.push("Each CVE group below is given an index. Reference these in `raw_indexes` in your response.");
  lines.push("");

  for (let i = 0; i < opts.groups.length; i++) {
    const g = opts.groups[i]!;
    lines.push(`---`);
    lines.push(`raw_index: ${i}`);
    lines.push(`cve: ${g.cve}`);
    lines.push(`tool_severity: ${g.tool_severity}`);
    if (g.advisory_title) lines.push(`advisory_title: ${g.advisory_title}`);
    if (g.primary_url) lines.push(`primary_url: ${g.primary_url}`);
    lines.push(`affected_packages: ${g.affected.length}`);
    // Cap the per-CVE package list so a kernel-CVE with 50 linux-headers-*
    // entries doesn't blow the prompt budget. The first ~10 are enough for
    // Claude to recognise the pattern.
    const PKG_DISPLAY_CAP = 10;
    const display = g.affected.slice(0, PKG_DISPLAY_CAP);
    for (const a of display) {
      const fix = a.fixed_version === null
        ? "no fix yet"
        : `→ ${a.fixed_version}`;
      lines.push(`  - ${a.package} ${a.installed_version} ${fix}`);
    }
    if (g.affected.length > PKG_DISPLAY_CAP) {
      lines.push(`  … and ${g.affected.length - PKG_DISPLAY_CAP} more (mostly linux-headers-* siblings)`);
    }
    lines.push("");
  }

  lines.push(`---`);
  lines.push("");
  lines.push("Triage every CVE group above. Respond with the JSON object only.");
  return lines.join("\n");
}
