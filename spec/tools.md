# Tools spec — v1

Defines the `ToolRunner` interface for **project** scans, the `RawFinding` shape that all runners emit (project- or host-side), and how a user adds their own tools to the scan pipeline. Three project runners are bundled today — Semgrep (static analysis on the working tree), Gitleaks (pattern-based secret detection across full git history), and Trufflehog (broader detector set with live API verification, also across full git history); all implement the same interface, so adding a fourth is the same shape.

Host scans use a parallel `HostToolRunner` interface defined in `host-scanning.md`. The bundled host runner is Trivy. Both interfaces produce the same `RawFinding[]` shape — only the input context differs (project working tree vs. host rootfs).

The triage layer (Claude) is **not** a tool in this sense. Tools are deterministic detectors that produce `RawFinding[]`; the triage layer consumes them, dedups, ranks, writes rationale, and emits the final `Finding[]` defined in `findings-schema.md`.

---

## ToolRunner interface

```ts
export interface ToolRunner {
  // Stable identifier. Lowercase, no spaces. Used in `RawFinding.source` and
  // in `tools_run[]` in the output. Examples: "semgrep", "gitleaks", "bandit".
  readonly name: string;

  // Best-effort version string. Returned by shelling out to the underlying
  // tool, or hardcoded for in-process runners. Surfaces in `tools_run[]` so
  // findings history captures detector drift. May return null if the tool
  // can't report its version.
  version(): Promise<string | null>;

  // Run against a project's working tree. `projectPath` is an absolute path
  // to the project root (the directory containing AGENTS.md / .git).
  // Implementations may write to a temp dir but must not mutate projectPath.
  // Should resolve even when the underlying tool exits non-zero because of
  // findings — only reject when the tool itself failed (binary missing,
  // config invalid, OOM, etc.).
  run(projectPath: string, ctx: ToolContext): Promise<RawFinding[]>;
}

export interface ToolContext {
  // The repo HEAD short sha at scan start. Tools that scan diffs (e.g. a
  // future "only-touched-files" mode) use this; most tools ignore it.
  sha: string;
  // Logger surface so tool runners don't import a global logger.
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void;
  // Where to put intermediate artifacts (cleaned up after the scan).
  // Tool-specific subdirectories should be created on demand.
  scratchDir: string;
}
```

### RawFinding shape

```ts
export interface RawFinding {
  // Tool name (matches the runner's `name`).
  source: string;
  // Tool-native rule identifier. Required — the triage layer uses it for
  // dedup and the stable-id derivation. If a tool has no concept of rules,
  // synthesize one from the message kind (e.g. "gitleaks:aws-access-key").
  rule_id: string;
  // Tool-native severity, verbatim. The triage layer remaps this; runners
  // do not normalize. Common values: "ERROR" | "WARNING" | "INFO" (semgrep),
  // "high" | "medium" | "low" (others). Free string.
  severity: string;
  // Project-relative POSIX path. The runner is responsible for stripping
  // the projectPath prefix and normalizing slashes.
  file: string;
  // 1-based line. If the tool reports a range, use the start line.
  line: number;
  // Optional end of a range; omit for single-line findings.
  line_end?: number;
  // One-line tool message. Not shown directly to humans — the triage layer
  // rewrites it as a contextual title — but kept verbatim for debug output.
  message: string;
  // Optional reference URLs from the tool (rule docs, CWE links).
  links?: string[];
  // Optional pass-through of the tool's raw record for debugging. Not
  // serialized into findings/*.json; only used during triage.
  raw?: unknown;
}
```

### Errors

A `ToolRunner.run()` rejection is caught by the orchestrator and recorded in `tools_failed[]` in the output. The scan continues with whatever other tools succeeded — one failing tool does not abort the whole project's scan.

Common failure modes runners should handle gracefully (resolve with `[]`, not reject):

- The tool produced no findings.
- The tool found syntax errors or unsupported files (skip and continue).
- The tool's config file is missing — fall back to the tool's defaults.

Reject only when the tool fundamentally cannot run: binary not found, OOM, JSON output unparseable, etc. The rejection's `Error.message` is what shows up in `tools_failed[].error`.

---

## Tool registry

Today: hardcoded. `service/src/scanner/run.ts` exports `REGISTERED_TOOLS: ToolRunner[]`, currently `[new SemgrepRunner(), new GitleaksRunner(), new TrufflehogRunner()]`. Add a fourth by importing the runner module and appending the instance to that array.

A YAML-driven registry (workspace `service/agent-security.config.yml` + per-project `.agent-security.yml` overrides, with a generic `command` adapter for shell-out tools) was sketched out as the v1 design but deferred. With three bundled tools and zero user-supplied additions, the indirection still has no users to fit. When a per-user tool shows up, the abstraction will have a real shape to take. Until then, hardcoding keeps the registration site greppable and the failure modes obvious.

---

## Bundled runner: Semgrep

`scanner/tools/semgrep.ts` shells out to the `semgrep` binary in the host's PATH and parses `--json` output.

Defaults (overridable via tool config):

- Ruleset: `p/security-audit` plus `p/secrets`. These are Semgrep's curated security packs and cover the languages in the workspace.
- Severity mapping (tool-native → kept verbatim in RawFinding): `ERROR | WARNING | INFO`.
- Excludes: Semgrep's defaults (`node_modules`, `vendor`, `dist`, `build`, `__pycache__`, etc.) plus an automatic `.semgrepignore` if present at the project root.
- Timeout: 300s per project, configurable.

Failure modes:

- `semgrep` binary not in PATH → reject with `"semgrep binary not found in PATH; install with 'pip install semgrep' or see https://semgrep.dev/docs/getting-started/"`. The orchestrator records this in `tools_failed[]` and the rest of the scan continues.
- Semgrep exit code 1 means "findings present" → success path.
- Semgrep exit code 2 means "rule errors" → log a warning, parse whatever results came through.
- Other exit codes → reject with the captured stderr.

Version pinning: see Gotcha #5 in the project AGENTS.md. We record the binary version in `tools_run[].version` so finding history shows when the detector itself drifted.

---

## Bundled runner: Gitleaks

`scanner/tools/gitleaks.ts` shells out to the `gitleaks` binary in the host's PATH and parses its `--report-format json` output file. Unlike Semgrep (which scans the working tree), Gitleaks walks the **full git history** by default — a credential committed and later removed still surfaces, which is the entire reason it earns its slot.

Defaults:

- Command: `gitleaks detect --source <projectPath> --report-format json --report-path <scratchDir>/gitleaks.json --redact --no-banner --exit-code 1`.
- Rules: gitleaks' built-in default ruleset (~150 patterns covering AWS, GCP, Slack, GitHub, Stripe, generic high-entropy strings, etc.). No custom config is shipped.
- `--redact`: secret values are masked in the JSON report, so they never land in `findings/*.json` even when a finding fires.
- Severity mapping: gitleaks has no per-finding severity, so the runner synthesizes `"HIGH"`. The triage layer can downgrade based on context (test fixtures, demo strings, etc.).
- Timeout: 300s per project.

Failure modes:

- `gitleaks` binary not in PATH → reject with an install hint pointing at `https://github.com/gitleaks/gitleaks/releases`.
- Exit code 0 → no leaks (success path, may produce no report file).
- Exit code 1 → leaks found, parse the report file (success path).
- Other exit codes → reject with the captured stderr tail.

`StartLine: 0` (gitleaks emits this for leaks inside commit messages rather than file bodies) is clamped to 1 so downstream source-slicing doesn't choke; the commit SHA is still preserved in `raw.Commit` for triage context.

---

## Bundled runner: Trufflehog

`scanner/tools/trufflehog.ts` shells out to the `trufflehog` binary in the host's PATH and parses its NDJSON output (one JSON object per stdout line). Like Gitleaks, it walks the **full git history** — but its detector set is broader (hundreds of vendor-specific patterns, including LaunchDarkly without surrounding-context requirement and Snowflake credential triplets that Gitleaks misses), and detectors carry a `Verified` field set by pinging the vendor API during the scan. Overlap with Gitleaks on common detectors (AWS, GitHub PATs, Stripe, etc.) is expected; the triage layer dedupes near-duplicates.

Defaults:

- Command: `trufflehog git file://<projectPath> --json --no-update`.
- Verification is on by default. Each finding's `Verified: true/false` indicates whether the detector successfully authenticated against the vendor's API. This is the killer feature — verified credentials are guaranteed live, not pattern false positives.
- Severity mapping: `Verified: true` → `"HIGH"`, anything else (`false` or verification error) → `"MEDIUM"`. The triage layer can downgrade verified findings if context warrants and can downrank the unverified bucket aggressively.
- Secret scrubbing: the runner strips `Raw` and `RawV2` from the stashed `raw` payload before it reaches `findings/projects/*.json`, since those fields contain the actual secret value. The masked `Redacted` field (when present) survives.
- Timeout: 600s per project (verification adds API latency over the gitleaks/semgrep baseline).

Failure modes:

- `trufflehog` binary not in PATH → reject with an install hint pointing at `https://github.com/trufflesecurity/trufflehog/releases`.
- Exit code 0 → success path, regardless of whether any leaks were found (trufflehog v3 only exits non-zero with `--fail`, which we don't pass).
- Any non-zero exit code → reject with the captured stderr tail.

NDJSON parse failures on individual lines are logged and skipped rather than aborting the whole run, since trufflehog occasionally emits stray non-JSON lines (e.g. when a detector itself crashes mid-scan).

---

## Adding a new tool

Today: implement `ToolRunner` in `service/src/scanner/tools/<name>.ts`, then append `new YourRunner()` to `REGISTERED_TOOLS` in `service/src/scanner/run.ts`. That's it — the orchestrator does the rest (version recording, error capture into `tools_failed[]`, raw-finding aggregation into the triage layer).

When the third or fourth tool gets added — especially a per-user one — reconsider the YAML-driven registry. The current arrangement is intentional: two tools don't need a config schema.

---

## Versioning

`tools-spec-version: 1` today. Bump when:

- The `ToolRunner` interface changes shape (added required methods, renamed fields).
- The `RawFinding` shape changes incompatibly.
- The registry config schema changes.

Pure additions (new optional fields, new bundled runners) don't bump.
