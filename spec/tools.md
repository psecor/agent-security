# Tools spec — v1

Defines the `ToolRunner` interface, the `RawFinding` shape that runners emit, and how a user adds their own tools to the scan pipeline. The bundled implementation is Semgrep; everything else plugs in through the same interface.

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

Tools are discovered in this order, last write wins:

1. **Bundled** — `semgrep` is registered automatically.
2. **Workspace config** — `service/agent-security.config.yml` (gitignored) lists additional tools.
3. **Per-project override** — `<project>/.agent-security.yml` enables, disables, or replaces tools just for that project.

Config shape (workspace level):

```yaml
tools:
  - name: semgrep
    enabled: true
    # Tool-specific config is passed through to the runner verbatim.
    config:
      rulesets:
        - p/security-audit
        - p/secrets

  - name: gitleaks
    # Custom command-style runner. Built-in adapter ("command") parses output
    # according to `format` and synthesizes RawFindings from a path mapping.
    runner: command
    command: "gitleaks detect --source {{projectPath}} --report-format json --report-path {{out}} --no-git"
    format: gitleaks-json
    # rule_id_template and severity defaults can be overridden here.

  - name: my-custom
    # Module path — anything that exports `default: ToolRunner` is fine.
    runner: module
    module: ./extensions/my-custom-tool.js
```

Per-project config can disable a workspace tool (`enabled: false`) or override its config block. It cannot widen tool reach beyond what's registered at the workspace level — adding a brand-new tool from a per-project file is rejected, because the project repo is untrusted relative to the scanner host.

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

## Adding a new tool

For an in-process runner (preferred when you have a TypeScript wrapper):

1. Implement `ToolRunner` in a module under `service/src/scanner/tools/extensions/`.
2. Add a registry entry to `service/agent-security.config.yml`:
   ```yaml
   - name: my-tool
     runner: module
     module: ./extensions/my-tool.js
   ```
3. Re-run the scanner. The runner is picked up on next `--all` or any explicit `--project` run.

For a shell-out tool with JSON output, prefer the bundled `command` runner (config-only, no code). It handles a small set of well-known JSON shapes (`gitleaks-json`, `semgrep-json`, `bandit-json`, `npm-audit-json`); add a new `format` mapping if your tool's output isn't already covered.

If the tool requires more than a JSON adapter (e.g. multiple subprocess calls, post-processing), write an in-process runner.

---

## Versioning

`tools-spec-version: 1` today. Bump when:

- The `ToolRunner` interface changes shape (added required methods, renamed fields).
- The `RawFinding` shape changes incompatibly.
- The registry config schema changes.

Pure additions (new optional fields, new bundled runners) don't bump.
