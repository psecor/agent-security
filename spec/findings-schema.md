# Findings schema — v2

Defines the on-disk shape of `findings/projects/<project>.json` and its human-readable mirror `findings/projects/<project>.md`, plus the host-scan output at `findings/hosts/<hostname>.{json,md}`. The JSON file is the canonical record; the API and UI read it directly and the `.md` is regenerated from it on every scan.

Each scan **fully overwrites** both files. There is no merge or accumulation in v1.

This document covers the shared `Finding` shape and severity vocabulary used by both project and host scans. The project-scan top-level wrapper is described below; the host-scan wrapper lives in `host-scanning.md`.

---

## File layout

```
agent-security/findings/
├── projects/
│   ├── <project>.json      canonical, machine-readable
│   └── <project>.md        human-readable mirror
└── hosts/
    ├── <hostname>.json     see host-scanning.md
    └── <hostname>.md
```

The `projects/` and `hosts/` subdirectories were introduced in schema v2 to give each kind of scan target its own `git log` history and to make name collisions impossible. Schema v1 wrote project findings flat under `findings/<project>.{json,md}`; the v1→v2 migration was a one-shot `git mv` plus a scanner write-path update.

For multi-root project setups (see `PROJECT_ROOTS`), the basename is the qualified project key with `/` replaced by `__`. So a project at `/other-root/foo` whose qualified key is `other-root/foo` writes to `findings/projects/other-root__foo.{json,md}`. Single-root projects use the bare name.

---

## JSON schema

```jsonc
{
  // Project identity
  "project": "rssreader",                              // bare name (or qualified key for multi-root)
  "kind": "project",                                   // discriminator; "host" for host scans (see host-scanning.md)
  "root": "/path/to/projects",                         // absolute path to the root this project lives under
  "project_path": "/path/to/projects/rssreader",

  // Scan metadata
  "scanner_version": "0.1.0",                          // agent-security package version at scan time
  "schema_version": 2,                                 // this document
  "last_scanned": "2026-05-02T03:30:00Z",              // ISO 8601 UTC
  "last_scanned_sha": "abc1234",                       // short SHA of HEAD at scan time
  "loc_at_scan": 4231,                                 // total tracked LOC (cloc-style; semgrep -- counts the same files)
  "loc_changed_since_previous": 312,                   // 0 on first scan; null if previous sha is gone

  // What ran
  "tools_run": [                                       // every tool that produced findings or ran cleanly
    { "name": "semgrep", "version": "1.84.1", "rules_version": "p/security-audit@2026-04-15" }
  ],
  "tools_failed": [],                                  // tools that errored; same shape with an `error` field

  // Aggregate counts (post-triage). Always present even if zero.
  "counts": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 9,
    "info": 4
  },

  // The findings themselves, sorted by severity (critical first), then file:line.
  "findings": [
    {
      "id": "sha256:f4a1...",                          // see "Stable IDs" below
      "severity": "high",                              // critical | high | medium | low | info
      "category": "injection",                         // see "Categories"
      "title": "Unsanitized user input flows into SQL query",
      "file": "src/server/routes/feed.ts",             // project-relative POSIX path; optional for host findings
      "line": 42,                                      // 1-based; optional for host findings
      "line_end": 47,                                  // optional; omit for single-line findings
      "source": "semgrep",                             // which tool surfaced the underlying signal
      "rule_id": "javascript.express.security.audit.express-tainted-sql",
      "rationale": "User input from req.params.id is concatenated directly into a SQL string passed to db.query(). Express handlers see untrusted client input by default; in this codebase the same route is mounted publicly under /api/feed, so this is reachable without auth. Use a parameterized query (db.query(sql, [id])) or the existing util in src/server/db/safe-query.ts.",
      "links": [],                                     // optional: ["https://owasp.org/...", ...]

      // Host-finding-only fields (omitted for project findings):
      "cve": null,                                     // e.g. "CVE-2026-31431"
      "package": null,                                 // e.g. "openssl"
      "installed_version": null,                       // e.g. "3.0.2-0ubuntu1.18"
      "fixed_version": null                            // e.g. "3.0.2-0ubuntu1.19"; null if no fix available yet
    }
  ]
}
```

### Field rules

- All fields shown above are **required** unless explicitly noted as optional.
- Unknown fields are tolerated for forward compatibility — readers should not error on extras, but should round-trip them only if they're rewriting the file (the scanner does not).
- `findings[].title` is one short sentence (≤ 100 chars), Sentence case, no trailing punctuation.
- `findings[].rationale` is one paragraph (≤ 600 chars), explaining *why this matters in this codebase / on this host*. Generic rule descriptions belong in the rule docs (`links`), not here.
- Paths are POSIX-style and relative to `project_path`. The scanner normalizes Windows-style or absolute paths to this form before writing.
- `findings[].file` and `findings[].line` are required for project findings and **optional** for host findings (a CVE attached to an installed package has no source line). When present in a host finding, `file` should point at a meaningful absolute path (e.g. `/usr/sbin/sshd` for an sshd config issue); `line` may be 1 if the file is binary. Prefer omitting both rather than inventing sentinel values.
- `findings[].cve | package | installed_version | fixed_version` are populated **only** for host findings sourced from CVE-matching tools (Trivy, debsecan, etc.). They are omitted on project findings; readers should treat them as `null` when absent. `fixed_version` is `null` when the upstream advisory has no patched version yet — this is meaningful information, not missing data.

### Stable IDs

`id` is `sha256:` + the hex digest of:

```
<rule_id> "\n" <project_relative_file> "\n" <normalized_line_context>
```

`normalized_line_context` is the line at `line` plus the two lines above and below, with leading/trailing whitespace trimmed per line and lines joined with `\n`. Whitespace-only lines are dropped.

This is intentionally not just `(rule_id, file, line)` — line numbers shift when code above is added or removed, but the surrounding context usually doesn't. The same logical issue across runs should hash to the same id even after an unrelated edit.

For findings sourced from Claude (no `rule_id`), use `claude:<short-slug-of-title>` as the rule_id input. Tool authors may override the id derivation if they have a better stable identifier (e.g. a CWE + canonical sink location). The host runner overrides this entirely — see `host-scanning.md` for the CVE-keyed id derivation.

v1 does not consume `id` cross-scan; it is recorded so the future dismissals layer can reference findings stably.

### Severity

Five levels: `critical | high | medium | low | info`. Claude does the final ranking; tool-native severities are inputs only. Rough definitions:

- **critical** — Reachable RCE, auth bypass, or credential exposure with no extra preconditions. Drop everything.
- **high** — Reachable injection, SSRF, IDOR, secrets in source, dangerous deserialization. Fix this sprint.
- **medium** — Hardening issue with a real-world failure mode (e.g. weak crypto, missing CSRF on state-changing endpoint, dependency with known CVE in a non-critical path). Fix soon.
- **low** — Defense-in-depth opportunity, minor information disclosure, deprecated API with a known successor.
- **info** — Stylistic security note worth knowing but not actionable on its own (e.g. "this directory has no .gitignore for `.env`").

### Categories

Free-form short slugs. The API exposes them for filtering; the scanner does **not** enforce an enum yet so we can learn what categories actually surface. Suggested starter set:

Project findings:
`injection | xss | ssrf | auth | secrets | crypto | deserialization | path-traversal | deps | config | logging | dos | other`

Host findings:
`package-cve | kernel-cve | host-config`

The two sets coexist in the same `category` field — there is no separate enum per `kind`. The split is editorial: a host finding tagged `injection` would be confusing, and a project finding tagged `package-cve` would be misleading (a vulnerable npm dep is `deps`, not `package-cve`, since the fix is `npm update` in source rather than `apt upgrade` on the host). The triage prompt enforces this split.

If a finding genuinely spans two categories, pick the one a developer would search for first. Don't invent a new category for a single finding — fall back to `other` and let the next sweep see if a pattern emerges.

---

## Markdown mirror

`findings/<project>.md` is regenerated from the JSON every scan. Authors should never edit it by hand. Shape:

```markdown
# Security findings — <project>

_Last scanned <ISO date> at <short sha>; <loc> LOC; <N> findings (<critical> critical, <high> high, ...)._

## Critical

### <title>
**File:** `<file>:<line>` &nbsp; **Source:** `<source>` &nbsp; **Rule:** `<rule_id>`

<rationale>

---

## High

...

## Medium

...
```

Severity sections with no findings are omitted. The mirror is a courtesy for humans browsing the repo; the JSON is authoritative and the API/UI ignores the markdown entirely.

---

## Empty findings

When a scan completes cleanly with zero findings, the JSON is still written:

```json
{
  "project": "rssreader",
  "...": "...",
  "counts": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "findings": []
}
```

The markdown mirror is also written, with a body of `_No findings as of <date>._`.

---

## Versioning

`schema_version: 2` today. Bump when:

- A required field is renamed, added, or removed.
- A severity or category is removed (additions are non-breaking).
- The id derivation changes in a way that breaks cross-version equality.

Breaking changes get a one-shot migration in the scanner that rewrites every `findings/**/*.json` to the new shape and commits the result.

**v1 → v2** (this version): introduced the `kind` discriminator, the `findings/projects/` and `findings/hosts/` subdirectory split, optional host-finding fields (`cve`, `package`, `installed_version`, `fixed_version`), and made `file`/`line` optional for host findings. Migration was a one-shot `git mv findings/*.{json,md} findings/projects/`, a scanner write-path update, and an in-place `kind: "project"` injection on existing project files at next scan.
