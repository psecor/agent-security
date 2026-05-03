---
project: agent-security
status: in-progress
status_description: "Milestones 1–4 done: scanner skeleton, Claude triage layer, LOC-threshold selector with multi-root + --all + bot-commit-on-write, and the Express server (OAuth + bearer-token JSON API on port 3046). UI and deploy not yet built."
last_updated: 2026-05-03
last_updated_by:
  - agent:claude-opus-4-7
  - human:secorp
  - agent:sweeper-claude-opus-4-7
wiki_schema_version: 1
---

# AGENTS.md — agent-security

## What This Is

A periodic, work-amount, or on-demand security analyst for the workspace. Walks configured project roots (default `~/termag/projects`), runs static analysis (Semgrep bundled, others pluggable), feeds raw findings + relevant source slices to Claude for triage and prioritization, and writes structured findings into this repo at `findings/<project>.{json,md}`. A small Express service exposes the rollup at `https://secorp.net/security` (Apache → 127.0.0.1:3046) for humans (Google OAuth allowlist) and machines (bearer tokens, e.g. Jira / ticketing scripts).

## Status

**In progress.** Milestones 1–4 of the build order are landed: scanner skeleton with bundled Semgrep runner, Claude triage layer writing `findings/<project>.{json,md}`, the LOC-threshold selector + multi-root + `--all` + bot-commit-on-write, and the Express server with Google OAuth (humans) + bearer-token (machines) auth and the JSON API. The scanner is self-driving — `npm run scanner -- run --all` discovers AGENTS.md-marked projects under `PROJECT_ROOTS`, picks ones with ≥`LOC_THRESHOLD` (default 200) LOC changed since `last_scanned_sha`, scans them, and commits the findings as `agent-security[bot]`. The server (`npm run server` → `127.0.0.1:3046`, mounted at `/security`) reads `findings/*.json` on demand and serves the rollup at `GET /security/api/{health,projects,projects/:name,findings}`; `npm run cli -- token create --name <name>` mints bearer tokens stored hashed in `service/api-tokens.json`. No UI, no deploy yet.

Decided:

- Standalone repo (not a module of agent-wiki). Rationale: security findings have a different lifecycle (open/regress/dismiss) than docs (drift), and a dedicated prompt/cadence reads cleaner than a multi-purpose sweeper.
- Hybrid analysis: Semgrep bundled as the default static pass; Claude does triage, prioritization, severity ranking, and rationale. Tool runner is pluggable so `gitleaks`, `bandit`, `npm audit`, etc. can be added per-user.
- Findings live centrally in this repo at `findings/<project>.{json,md}`, committed by a bot identity each scan. v1 does **not** write back into project AGENTS.md files; the wiki UI links across to `/security/projects/<name>` instead.
- Triggers: daily systemd timer at 03:30 (offset from agent-wiki's 03:00) plus LOC-threshold selector (default 200 LOC changed since `last_scanned_sha`). Manual CLI for on-demand. Stop-hook deferred.
- No dismissals in v1. Each scan fully replaces the findings file. Add `dismissals/<project>.json` later if noise warrants.
- Report-only in v1. PR / patch suggestions deferred.
- Multi-root supported from day one (`PROJECT_ROOTS` is a list); collisions qualified by root.

Build order:

1. ✅ Spec (`spec/findings-schema.md`, `spec/tools.md`) + scanner skeleton (`ToolRunner` interface, Semgrep runner, single-project CLI writing `findings/<project>.json`).
2. ✅ Claude triage layer (prompt, API wrapper, `findings/<project>.md` writer).
3. ✅ Selector (LOC threshold) + multi-root + `--all` + bot-commit-on-write.
4. ✅ Express server: OAuth + bearer-token middleware + JSON API (no UI yet — Jira can integrate at this point).
5. React + Vite UI at `/security/`.
6. Deploy: systemd web unit + scanner unit + timer + Apache splice.
7. Future: dismissals, PR suggestions, Stop-hook trigger, AGENTS.md summary block.

## Repository Layout

```
agent-security/
├── AGENTS.md                  this file
├── CLAUDE.md                  one-line @AGENTS.md stub
├── README.md                  human-facing intro (TBD)
├── spec/
│   ├── findings-schema.md     JSON shape, severities, categories
│   └── tools.md               ToolRunner interface + how to register extra tools
├── findings/                  central rollup, one set per project, committed
│   ├── <project>.json         structured (drives API/UI)
│   └── <project>.md           human-readable mirror
├── service/
│   ├── package.json
│   ├── tsconfig.json
│   ├── .env.example
│   └── src/
│       ├── scanner/
│       │   ├── cli.ts         run | run --project | --dry-run | --force (--all TBD)
│       │   ├── run.ts         orchestrates one project's scan
│       │   ├── tools/
│       │   │   ├── types.ts   ToolRunner interface + RawFinding shape
│       │   │   ├── semgrep.ts bundled default
│       │   │   └── registry.ts loads user-configured extras (TBD)
│       │   ├── prompt.ts      security-analyst prompt + tool-output assembly
│       │   ├── claude.ts      Anthropic API wrapper
│       │   ├── triage.ts      runs Claude over RawFindings → Finding[]
│       │   ├── source.ts      reads source slices around finding lines for the prompt
│       │   ├── apply.ts       writes findings/<project>.{json,md} + commits
│       │   ├── git.ts         per-project diff stats, sha, commit-on-write
│       │   ├── select.ts      LOC-threshold + force/all logic (TBD)
│       │   └── types.ts
│       └── server/            (TBD — none of this exists yet)
│           ├── index.ts       Express entry; mounts /security on :3046
│           ├── config.ts
│           ├── auth.ts        Passport OAuth (humans) + bearer middleware (machines)
│           ├── tokens.ts      mint / verify; hashed at rest
│           ├── api.ts         JSON endpoints under /security/api
│           └── data.ts        reads findings/*.json
├── ui/                        React + Vite SPA, served by backend at /security/ (TBD)
└── deploy/                    (TBD)
    ├── agent-security.service           systemd unit for the web service
    ├── agent-security-scanner.service   user-mode oneshot invoked by timer
    ├── agent-security-scanner.timer     daily 03:30 fan-out
    ├── run-daily.sh                     timer entrypoint: scanner --all
    ├── apache.conf                      ProxyPass /security → 127.0.0.1:3046
    └── setup.md                         install walkthrough
```

Note: `triage.ts` and `source.ts` weren't in the original sketch. `triage.ts` owns the Claude pass over `RawFinding[]`; `source.ts` reads the source-window slices that get embedded in the prompt. `prompt.ts` assembles, `claude.ts` is just the API wrapper.

## Architecture

```
                   ┌──────────────────────────────────────────────────┐
                   │             agent-security scanner               │
Daily timer ──────▶│                                                  │
LOC-threshold ────▶│  select projects ──▶ for each project:           │
Manual CLI ───────▶│      run ToolRunners (semgrep + user-configured) │
                   │      → RawFindings[]                             │
                   │      assemble prompt (tool output + source)      │
                   │      Claude API: triage, rank, dedup, rationale  │
                   │      → Finding[] (severity, category, file:line) │
                   │      write findings/<project>.{json,md}          │
                   │      git add + commit (bot identity) + push      │
                   └──────────────────────────────────────────────────┘
                                    │
                          findings/*.json (committed)
                                    │
                                    ▼
Browser ──https──▶ Apache (:443, /security/*) ──http──▶ Express (:3046, /security/*)
Jira/scripts ─────Bearer token───────────────────────▶  ├── /security/auth/*  Passport (Google OAuth, allowlist)
                                                        ├── /security/api/*   JSON (projects, findings, health)
                                                        └── /security/*       SPA from ui/dist
```

**Trade-off: standalone repo vs. extending agent-wiki** — chose standalone. The sweeper-vs-scanner code overlap (sources walker, Express + OAuth scaffolding) is real but thin. The two need different prompts, different cadences, different output shapes, and have different failure modes. Bundling them would force one prompt to do two jobs and entangle release cycles.

**Trade-off: central findings repo vs. in-tree files in each project** — chose central. (a) `git log findings/<project>.json` here is the security history of that project, no per-project archaeology required. (b) High-churn machine output doesn't pollute project-repo PRs and history. (c) The wiki sweeper and the security scanner never fight over the same file. Cost: the project repo doesn't show findings to a developer just by `ls`, so the wiki UI grows a cross-link.

**Trade-off: hybrid (Semgrep + Claude) vs. pure-LLM scanning** — chose hybrid. Semgrep gives deterministic, reproducible findings tied to named rules with known precision/recall, runs locally for free, and covers all the languages in the workspace. Pure-LLM scans are noisy, expensive, and unstable across runs. Claude's job is triage and contextual prioritization, not pattern detection.

**Trade-off: bundled tool vs. fully pluggable** — chose "one bundled, others pluggable." A zero-config default makes the tool useful out of the box; the registry lets a user add `gitleaks`, `bandit`, `npm audit`, etc. without forking. Each tool's output is normalized to a common `RawFinding` shape before triage.

**Trade-off: report-only vs. propose-patches in v1** — chose report-only. Patch generation needs branch hygiene, signing, and a review loop that's worth its own iteration. Findings-first lets us learn what the noise floor looks like before automating fixes.

**Trade-off: scan output replaces vs. accumulates** — chose full replacement (no dismissals in v1). Simpler state, no ID stability requirement, no ack store. The cost is no "won't fix" memory — if a true false positive resurfaces every scan, that's the signal to add dismissals, with stable IDs hashed from `(rule_id, file, normalized_line_context)`.

**Trade-off: dual auth vs. OAuth-only** — chose dual. Humans get OAuth like the wiki; machines (Jira, ticketing scripts) get bearer tokens minted via CLI and stored hashed (`service/api-tokens.json`, gitignored). Same endpoints, two authenticators.

## Data & Schema

`findings/<project>.json` is the canonical structured record. Each scan fully overwrites it.

```json
{
  "project": "rssreader",
  "root": "/home/secorp/termag/projects",
  "last_scanned": "2026-05-02T03:30:00Z",
  "last_scanned_sha": "abc1234",
  "loc_at_scan": 4231,
  "loc_changed_since_previous": 312,
  "tools_run": ["semgrep@1.x"],
  "counts": { "critical": 0, "high": 2, "medium": 5, "low": 9, "info": 4 },
  "findings": [
    {
      "id": "sha256:...",
      "severity": "high",
      "category": "injection",
      "title": "Unsanitized user input flows into SQL query",
      "file": "src/server/routes/feed.ts",
      "line": 42,
      "source": "semgrep",
      "rule_id": "javascript.express.security.audit.express-tainted-sql",
      "rationale": "One paragraph from Claude on why this matters in this codebase."
    }
  ]
}
```

Severity vocabulary: `critical | high | medium | low | info`. Claude does final ranking; tool-native severities (Semgrep `ERROR`/`WARNING`/`INFO`) are inputs only. Categories are free-form short slugs (`injection`, `secrets`, `auth`, `deps`, `crypto`, `xss`, `ssrf`, `config`, `other`); the API surfaces them for filtering but doesn't enforce an enum yet.

`findings/<project>.md` is a human-readable mirror, generated from the JSON: severity-grouped headings with file:line, rule, rationale.

`id` is a stable hash to support a future dismissals layer. Today nothing reads it cross-scan.

## Configuration

Service config is environment-driven via `service/.env` (gitignored). Required:

| Var | Notes |
|-----|-------|
| `BASE_URL` | `https://secorp.net` in prod, `http://localhost:3046` for local |
| `PATH_PREFIX` | `/security` (default). All routes mount under this. |
| `SESSION_SECRET` | Long random hex; rotating invalidates all human sessions |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth client; redirect URI is `${BASE_URL}${PATH_PREFIX}/auth/google/callback` |
| `ALLOWED_EMAILS` | Comma-separated allowlist (default: `secorp@gmail.com`) |
| `PROJECT_ROOTS` | Comma-separated absolute paths (default: `/home/secorp/termag/projects`) |
| `FINDINGS_DIR` | Where the scanner writes findings (default: `<repo>/findings`) |
| `LOC_THRESHOLD` | LOC-changed threshold for selector (default: `200`) |
| `ANTHROPIC_API_KEY` | For the triage layer |
| `UI_DIST` | Built UI bundle (default: `<repo>/ui/dist`) |

Per-project overrides (e.g. a stricter LOC threshold) live in a `.agent-security.yml` checked into the project repo. Detailed schema TBD in `spec/tools.md`.

API tokens for machine clients live in `service/api-tokens.json` (gitignored), populated via `npm run cli -- token create --name jira`. The plaintext is shown once at creation.

## Build, Run, Deploy

**Local dev:**

```bash
# backend
cd service
npm install
npm run scanner -- run --project rssreader --dry-run   # one project, no commit (works today)
npm run server                                          # tsx → :3046 (TBD — server not built)

# UI dev with HMR (TBD)
cd ui
npm install
npm run dev                                             # vite → :5173, proxies /security/{api,auth} → :3046
```

**Scanner CLI:**

```bash
npm run scanner -- run --project rssreader              # scan one project, write+commit (works)
npm run scanner -- run --project foo --dry-run          # show diff without writing or committing (works)
npm run scanner -- run --project foo --force            # ignore selector (works; selector is the no-op default today)
npm run scanner -- run --all                            # selector decides which projects qualify (TBD)
npm run cli -- token create --name jira                 # mint a bearer token for a machine client (TBD)
```

**Production deploy** (TBD): mirrors agent-wiki — `deploy/agent-security.service` runs the web process on `127.0.0.1:3046`; Apache splice in `deploy/apache.conf` proxies `/security`. Daily fan-out via `agent-security-scanner.timer` at 03:30. Walkthrough will land in `deploy/setup.md`.

## Observability & Maintenance

- `journalctl --user -u agent-security-scanner` for scanner runs; `journalctl -u agent-security` for the web service.
- `GET /security/api/health` for an unauthenticated liveness probe.
- Findings history is just `git log findings/<project>.json` in this repo — the bot commits give a per-scan timeline.
- Token revocation: delete the row from `service/api-tokens.json` and restart the service.
- File-based sessions live in `service/.sessions/` (gitignored). Deleting the directory force-logs all human users out.

## Integration Surfaces

JSON API, intentionally small. All endpoints accept either a session cookie (humans) or `Authorization: Bearer <token>` (machines), except `/health` and the OAuth dance.

| Endpoint | Returns |
|----------|---------|
| `GET /security/api/projects` | List of projects with `last_scanned`, severity counts, `loc_at_scan` |
| `GET /security/api/projects/:name` | Full findings for one project |
| `GET /security/api/findings?severity=high&category=injection&since=2026-05-01` | Cross-project rollup with filters; capped |
| `GET /security/api/health` | `{ ok: true }` (unauthenticated) |
| `POST /security/api/tokens` | (admin only) mint a new bearer token; plaintext returned once |
| `DELETE /security/api/tokens/:name` | revoke |
| `GET /security/auth/google` | OAuth start |
| `POST /security/auth/logout` | destroy session |

A Jira / ticketing integration looks like: scheduled job hits `/security/api/findings?severity=high` with a bearer token, diffs against the previous response, opens tickets for new entries. The scanner does not push to Jira itself — the integration owns its own state and policy.

## Gotchas

1. **Findings files are bot-owned** — every scan fully replaces `findings/<project>.json` and commits as `bot:agent-security`. Hand-editing them between scans will be blown away on the next run. If you need a finding to stop appearing, the v2 dismissals layer is the right place; until then, fix the underlying issue.

2. **`last_scanned_sha` drives the LOC selector** — if you delete or hand-edit `findings/<project>.json`, the next selector run treats the project as never-scanned and full-scans it. Usually fine; just be aware why the daily ran longer than expected.

3. **No dismissals in v1** — a true false positive from Semgrep will reappear every scan. That's intentional for the noise-discovery phase. Track the pattern; if it's painful, that's the signal to build dismissals (stable `id` is already in the JSON for this).

4. **Port 3046, prefix `/security`** — must agree across `PATH_PREFIX` env, `vite.config.ts` (`base: '/security/'`), `BrowserRouter` (`basename="/security"`), the systemd unit, and the Apache snippet. Changing the prefix requires touching all five.

5. **Bundled tool is Semgrep — version pinning matters** — Semgrep rule packs change. Pin a Semgrep version in `service/package.json` (or a Docker image) so finding IDs are reproducible. A rule pack upgrade is itself a sweep-worthy event; bumping it should be a deliberate commit, not a transitive dep float.

6. **Multi-root name collisions** — two roots can both contain `foo/`. The scanner qualifies findings by root index (`projects/foo`, `other-root/foo`). The UI shows the qualified name; bare `foo` is ambiguous and rejected in API queries.

## Related

**Other projects:**
- [agent-wiki](../agent-wiki/AGENTS.md) — same architecture pattern (Express + OAuth + Vite UI + systemd timer + Claude API sweeper). agent-security borrows scaffolding shape and deploy convention; the wiki UI will link out to `/security/projects/<name>` per project.

**Topics:** none yet.

<!-- agent-wiki:backlinks-start -->
_No incoming links yet._
<!-- agent-wiki:backlinks-end -->
