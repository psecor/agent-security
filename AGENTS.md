---
project: agent-security
status: in-progress
status_description: "Milestones 1–6 complete plus Gitleaks bundling and per-project scan history viewer; scanner, triage, selector, Express server (OAuth + bearer JSON API on port 3046), React + Vite UI at /security/, and the deploy bundle are all landed, the second end-to-end --all run committed findings for ~17 projects, and the daily systemd timer is now firing on schedule in production."
last_updated: 2026-05-06
last_updated_by:
  - agent:claude-opus-4-7
  - human:secorp
  - agent:sweeper-claude-opus-4-7
  - agent:claude-opus-4-7
wiki_schema_version: 1
---

# AGENTS.md — agent-security

## What This Is

A periodic, work-amount, or on-demand security analyst for the workspace. Walks configured project roots, runs static analysis (Semgrep + Gitleaks bundled, others pluggable), feeds raw findings + relevant source slices to Claude for triage and prioritization, and writes structured findings into this repo at `findings/<project>.{json,md}`. A small Express service exposes the rollup behind a reverse proxy (Apache → 127.0.0.1:3046) for humans (Google OAuth allowlist) and machines (bearer tokens, e.g. Jira / ticketing scripts).

## Status

**In progress, but functionally complete for v1.** Milestones 1–6 of the build order are landed, plus two follow-ups: Gitleaks was added as the second bundled tool runner, and a per-project scan history viewer shipped on top of the existing UI. The scanner has been run end-to-end across the workspace twice, and the daily systemd timer has since been observed firing in production (May 4 self-scan, May 5 termag rescan), so the deploy is exercised end-to-end and not just at install time. `findings/*.{json,md}` exist for ~17 projects (rssreader and claude-code-proxy-bot have triaged highs; everything else came back clean). Scanner skeleton with bundled Semgrep + Gitleaks runners, Claude triage layer writing `findings/<project>.{json,md}`, the LOC-threshold selector + multi-root + `--all` + bot-commit-on-write, the Express server with Google OAuth (humans) + bearer-token (machines) auth + JSON API, the React + Vite SPA at `/security/`, and the deploy bundle (systemd web unit `deploy/agent-security.service`, oneshot scanner unit `deploy/agent-security-scanner.service`, daily 03:30 timer `deploy/agent-security-scanner.timer`, `deploy/run-daily.sh` entry script, `deploy/apache.conf` proxy snippet, and `deploy/setup.md` walkthrough) are all in place. The scanner is self-driving — `npm run scanner -- run --all` discovers AGENTS.md-marked projects under `PROJECT_ROOTS`, picks ones with ≥`LOC_THRESHOLD` (default 200) LOC changed since `last_scanned_sha`, scans them, and commits the findings as `agent-security[bot]`. The server (`npm run server` → `127.0.0.1:3046`, mounted at `/security`) reads `findings/*.json` on demand, serves the rollup at `GET /security/api/{health,projects,projects/:name,projects/:name/history,findings}`, and hosts the UI bundle from `ui/dist`. `npm run cli -- token create --name <name>` mints bearer tokens stored hashed in `service/api-tokens.json`. The UI has Home (projects table with severity chips), Project (full findings grouped by severity, with a per-project scan-history view derived from `git log findings/<project>.json`), and Findings (cross-project rollup with severity + category filters). The Apache splice is live at `https://secorp.net/security`, reusing the agent-wiki OAuth client. First-run shook out two real bugs (PATH not set for systemd user units, unborn-repo crash on freshly-`git init`'d projects), both fixed in `a3cf5cc`; subsequent timer-driven runs have been clean.

Decided:

- Standalone repo (not a module of agent-wiki). Rationale: security findings have a different lifecycle (open/regress/dismiss) than docs (drift), and a dedicated prompt/cadence reads cleaner than a multi-purpose sweeper.
- Hybrid analysis: Semgrep (working-tree static analysis) and Gitleaks (full-history secret detection) bundled as default tool runners; Claude does triage, prioritization, severity ranking, and rationale. The `ToolRunner` interface is small enough that adding `bandit`, `npm audit`, etc. is a TS file plus a one-line registration in `run.ts`.
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
5. ✅ React + Vite UI at `/security/`.
6. ✅ Deploy: systemd web unit + scanner unit + timer + Apache splice. Apache splice is live, unit files installed, and the timer has now fired cleanly on its own schedule.
7. ✅ Gitleaks bundled as second tool runner (full-history secret detection alongside Semgrep's working-tree static analysis).
8. ✅ Per-project scan history viewer (UI + `/security/api/projects/:name/history`, derived from `git log findings/<project>.json`).
9. Future: dismissals, PR suggestions, Stop-hook trigger, AGENTS.md summary block.

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
│       ├── cli/
│       │   └── index.ts       admin CLI: `token create|list|revoke`
│       ├── scanner/
│       │   ├── cli.ts         run | run --project | --all | --dry-run | --force
│       │   ├── run.ts         orchestrates one project's scan
│       │   ├── tools/
│       │   │   ├── types.ts    ToolRunner interface + RawFinding shape
│       │   │   ├── semgrep.ts  bundled: working-tree static analysis
│       │   │   └── gitleaks.ts bundled: full-history secret detection
│       │   ├── prompt.ts      security-analyst prompt + tool-output assembly
│       │   ├── claude.ts      Anthropic API wrapper
│       │   ├── triage.ts      runs Claude over RawFindings → Finding[]
│       │   ├── source.ts      reads source slices around finding lines for the prompt
│       │   ├── apply.ts       writes findings/<project>.{json,md} + commits
│       │   ├── git.ts         per-project diff stats, sha, commit-on-write
│       │   ├── select.ts      LOC-threshold + force/all logic
│       │   └── types.ts
│       └── server/            Express service on 127.0.0.1:3046
│           ├── index.ts       Express entry; mounts /security on :3046
│           ├── config.ts      env loader
│           ├── auth.ts        Passport OAuth (humans) + bearer middleware (machines)
│           ├── tokens.ts      mint / verify; hashed at rest in api-tokens.json
│           ├── api.ts         JSON endpoints under /security/api
│           └── data.ts        reads findings/*.json
├── ui/                        React + Vite SPA, served by backend at /security/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts         base: '/security/', dev proxy to :3046
│   ├── tsconfig.json
│   └── src/
│       ├── main.tsx           BrowserRouter basename='/security'
│       ├── App.tsx            routes: Home, Project, Findings, Login
│       ├── api.ts             fetch wrappers for /security/api/*
│       ├── styles.css
│       ├── components/
│       │   ├── Layout.tsx     shell + nav
│       │   └── SeverityChip.tsx
│       └── pages/
│           ├── Home.tsx       projects table with severity chips
│           ├── Project.tsx    full findings grouped by severity
│           ├── Findings.tsx   cross-project rollup with severity + category filters
│           └── Login.tsx
└── deploy/
    ├── agent-security.service           systemd unit for the web service (ships with /opt placeholders — edit before installing)
    ├── agent-security-scanner.service   user-mode oneshot invoked by timer
    ├── agent-security-scanner.timer     daily 03:30 fan-out (offset from agent-wiki's 03:00)
    ├── run-daily.sh                     timer entrypoint: scanner --all + best-effort `git push origin`
    ├── apache.conf                      ProxyPass /security → 127.0.0.1:3046 (splice into your existing vhost)
    └── setup.md                         install walkthrough
```

Note: `triage.ts` and `source.ts` weren't in the original sketch. `triage.ts` owns the Claude pass over `RawFinding[]`; `source.ts` reads the source-window slices that get embedded in the prompt. `prompt.ts` assembles, `claude.ts` is just the API wrapper. The admin CLI lives at `service/src/cli/index.ts` (separate from the scanner CLI) and is the entry point for token management.

## Architecture

```
                   ┌──────────────────────────────────────────────────┐
                   │             agent-security scanner               │
Daily timer ──────▶│                                                  │
LOC-threshold ────▶│  select projects ──▶ for each project:           │
Manual CLI ───────▶│      run ToolRunners (semgrep + gitleaks + …)    │
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

**Trade-off: bundled tools vs. config-driven registry** — chose "two bundled, hardcoded for now." Semgrep covers working-tree static analysis; Gitleaks covers full-history secret detection — the two cheap-to-run, high-signal axes worth running on every project. A YAML registry that loads user-configured extras was sketched in `spec/tools.md` but deferred: with two tools and zero outside contributors, the indirection has no users to fit. Adding a third (e.g. `bandit`, `npm audit`) is one TS file plus a one-line append to `REGISTERED_TOOLS` in `run.ts`. Each tool's output is normalized to the common `RawFinding` shape before triage.

**Trade-off: report-only vs. propose-patches in v1** — chose report-only. Patch generation needs branch hygiene, signing, and a review loop that's worth its own iteration. Findings-first lets us learn what the noise floor looks like before automating fixes.

**Trade-off: scan output replaces vs. accumulates** — chose full replacement (no dismissals in v1). Simpler state, no ID stability requirement, no ack store. The cost is no "won't fix" memory — if a true false positive resurfaces every scan, that's the signal to add dismissals, with stable IDs hashed from `(rule_id, file, normalized_line_context)`.

**Trade-off: dual auth vs. OAuth-only** — chose dual. Humans get OAuth like the wiki; machines (Jira, ticketing scripts) get bearer tokens minted via CLI and stored hashed (`service/api-tokens.json`, gitignored). Same endpoints, two authenticators.

## Data & Schema

`findings/<project>.json` is the canonical structured record. Each scan fully overwrites it.

```json
{
  "project": "rssreader",
  "root": "/path/to/projects",
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
| `BASE_URL` | Public URL where the service is reachable (e.g. `https://example.com`) |
| `PATH_PREFIX` | `/security` (default). All routes mount under this. |
| `SESSION_SECRET` | Long random hex; rotating invalidates all human sessions |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth client; redirect URI is `${BASE_URL}${PATH_PREFIX}/auth/google/callback` |
| `ALLOWED_EMAILS` | Comma-separated allowlist (required) |
| `PROJECT_ROOTS` | Comma-separated absolute paths to project roots (required) |
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
npm run scanner -- run --project rssreader --dry-run   # one project, no commit
npm run server                                          # tsx → :3046

# UI dev with HMR
cd ui
npm install
npm run dev                                             # vite → :5173, proxies /security/{api,auth} → :3046
npm run build                                           # emits ui/dist/, served by backend in prod
```

**Scanner CLI:**

```bash
npm run scanner -- run --project rssreader              # scan one project, write+commit
npm run scanner -- run --project foo --dry-run          # show diff without writing or committing
npm run scanner -- run --project foo --force            # ignore selector
npm run scanner -- run --all                            # selector decides which projects qualify
```

**Admin CLI** (`service/src/cli/index.ts`):

```bash
npm run cli -- token create --name jira                 # mint a bearer token; plaintext shown once
npm run cli -- token list                               # list tokens by name + created-at
npm run cli -- token revoke --name jira                 # remove a token
```

**Production deploy:** mirrors agent-wiki. `deploy/agent-security.service` runs the compiled web process (`node dist/server/index.js`) on `127.0.0.1:3046` under a hardened systemd unit (`ProtectHome=read-only`, `ReadWritePaths` for `service/.sessions`). The committed unit ships with `/opt/agent-security/...` placeholders — edit `User`, `Group`, `WorkingDirectory`, `EnvironmentFile`, and `ReadWritePaths` to match your install before `sudo cp`-ing into `/etc/systemd/system/`. The Apache splice in `deploy/apache.conf` proxies `/security` — add it inside your existing HTTPS `*:443` vhost. Daily fan-out is `deploy/agent-security-scanner.timer` (03:30 local, offset from agent-wiki's 03:00) firing `agent-security-scanner.service` (user-mode oneshot) which runs `deploy/run-daily.sh`: that script loads `service/.env`, runs `node dist/scanner/cli.js run --all`, then best-effort `git push origin` if a remote is configured. Output is tee'd to `~/.local/state/agent-security/last-run.log`. Full step-by-step in `deploy/setup.md`.

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
| `GET /security/api/projects/:name/history` | Per-scan history for one project, derived from `git log findings/<project>.json` (commit sha, scan timestamp, severity counts) |
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

5. **Bundled tools are version-sensitive** — Semgrep rule packs and Gitleaks default rules both evolve, and a rule update can flip a project from "0 findings" to "10 findings" with no actual code change. Both tool versions are recorded in `tools_run[].version` in every `findings/<project>.json` so you can correlate a regression to a tool bump rather than a code change. Bumping either is a deliberate commit, not a transitive dep float — and worth a sweep-worthy review of the diffs that the new rules surface.

6. **Multi-root name collisions** — two roots can both contain `foo/`. The scanner qualifies findings by root index (`projects/foo`, `other-root/foo`). The UI shows the qualified name; bare `foo` is ambiguous and rejected in API queries.

7. **systemd user units start with an empty `PATH`** — `npx`, `node`, `git`, and `semgrep` all need to resolve, and a user-mode service unit doesn't inherit your login shell's environment. `run-daily.sh` exports a sensible `PATH` (including `~/.nvm`/`~/.local/bin`) before invoking the scanner; don't bypass it by calling `node dist/scanner/cli.js` directly from the unit. Symptom on first deploy was a silent exit with `npx: command not found` in `last-run.log`.

8. **Unborn repos crash `git rev-parse HEAD`** — a freshly-`git init`'d project with no commits has no `HEAD`, and the scanner used to die there. `select.ts` / `git.ts` now treat unborn repos as "never scanned, no diff stats" and skip them cleanly. If you add a new git wrapper, mirror that defense — `git symbolic-ref -q HEAD` succeeds on an unborn repo but `rev-parse HEAD` does not.

## Related

**Other projects:**
- [agent-wiki](../agent-wiki/AGENTS.md) — same architecture pattern (Express + OAuth + Vite UI + systemd timer + Claude API sweeper). agent-security borrows scaffolding shape and deploy convention; the wiki UI will link out to `/security/projects/<name>` per project.

**Topics:** none yet.

<!-- agent-wiki:backlinks-start -->
_No incoming links yet._
<!-- agent-wiki:backlinks-end -->
