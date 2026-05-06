# Findings schema — v1

Defines the on-disk shape of `findings/<project>.json` and its human-readable mirror `findings/<project>.md`. The JSON file is the canonical record; the API and UI read it directly and the `.md` is regenerated from it on every scan.

Each scan **fully overwrites** both files. There is no merge or accumulation in v1.

---

## File layout

```
agent-security/findings/
├── <project>.json          canonical, machine-readable
└── <project>.md            human-readable mirror
```

For multi-root setups (see `PROJECT_ROOTS`), the basename is the qualified project key with `/` replaced by `__`. So a project at `/other-root/foo` whose qualified key is `other-root/foo` writes to `findings/other-root__foo.{json,md}`. Single-root projects use the bare name.

---

## JSON schema

```jsonc
{
  // Project identity
  "project": "rssreader",                              // bare name (or qualified key for multi-root)
  "root": "/path/to/projects",                         // absolute path to the root this project lives under
  "project_path": "/path/to/projects/rssreader",

  // Scan metadata
  "scanner_version": "0.1.0",                          // agent-security package version at scan time
  "schema_version": 1,                                 // this document
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
      "file": "src/server/routes/feed.ts",             // project-relative POSIX path
      "line": 42,                                      // 1-based; the most relevant line if a range
      "line_end": 47,                                  // optional; omit for single-line findings
      "source": "semgrep",                             // which tool surfaced the underlying signal
      "rule_id": "javascript.express.security.audit.express-tainted-sql",
      "rationale": "User input from req.params.id is concatenated directly into a SQL string passed to db.query(). Express handlers see untrusted client input by default; in this codebase the same route is mounted publicly under /api/feed, so this is reachable without auth. Use a parameterized query (db.query(sql, [id])) or the existing util in src/server/db/safe-query.ts.",
      "links": []                                      // optional: ["https://owasp.org/...", ...]
    }
  ]
}
```

### Field rules

- All fields shown above are **required** unless explicitly noted as optional.
- Unknown fields are tolerated for forward compatibility — readers should not error on extras, but should round-trip them only if they're rewriting the file (the scanner does not).
- `findings[].title` is one short sentence (≤ 100 chars), Sentence case, no trailing punctuation.
- `findings[].rationale` is one paragraph (≤ 600 chars), explaining *why this matters in this codebase*. Generic rule descriptions belong in the rule docs (`links`), not here.
- Paths are POSIX-style and relative to `project_path`. The scanner normalizes Windows-style or absolute paths to this form before writing.

### Stable IDs

`id` is `sha256:` + the hex digest of:

```
<rule_id> "\n" <project_relative_file> "\n" <normalized_line_context>
```

`normalized_line_context` is the line at `line` plus the two lines above and below, with leading/trailing whitespace trimmed per line and lines joined with `\n`. Whitespace-only lines are dropped.

This is intentionally not just `(rule_id, file, line)` — line numbers shift when code above is added or removed, but the surrounding context usually doesn't. The same logical issue across runs should hash to the same id even after an unrelated edit.

For findings sourced from Claude (no `rule_id`), use `claude:<short-slug-of-title>` as the rule_id input. Tool authors may override the id derivation if they have a better stable identifier (e.g. a CWE + canonical sink location).

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

`injection | xss | ssrf | auth | secrets | crypto | deserialization | path-traversal | deps | config | logging | dos | other`

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

`schema_version: 1` today. Bump when:

- A required field is renamed, added, or removed.
- A severity or category is removed (additions are non-breaking).
- The id derivation changes in a way that breaks cross-version equality.

Breaking changes get a one-shot migration in the scanner that rewrites every `findings/*.json` to the new shape and commits the result.
