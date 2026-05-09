---
project: agent-security
status: in-progress
status_description: "Open-sourced and in production for project scans (Semgrep + Gitleaks, Claude triage, Express + OAuth + bearer API on :3046, React UI at /security/, daily systemd timer); host-scanning is now end-to-end including API + UI surface and category-aware Claude triage of critical/high CVEs (schema v2, Trivy runner, hosts/ findings), with per-host daily-timer fan-out still pending (see spec/host-scanning.md)."
last_updated: 2026-05-09
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

**In progress, but functionally complete for v1.** Milestones 1–6 of the build order are landed, plus follow-ups: Gitleaks was added as the second bundled tool runner, a per-project scan history viewer shipped on top of the existing UI, and the repo had an open-source prep pass — LICENSE + README added, in-tree default paths parameterized out of `service/src/server/config.ts` and `service/.env.example`, and the bundled `findings/` snapshot dropped (kept as `findings/.gitkeep` so the directory survives a fresh clone). Project findings now live under a `findings/projects/` subdirectory (was `findings/<project>.{json,md}` flat) so a future host-scanning peer can sit alongside at `findings/hosts/` without colliding. `run-daily.sh` commits and pushes from the `FINDINGS_DIR` repo when that points outside the code repo, so a deployment can keep its findings in a separate (often private) repo from the open-source code. The scanner has been run end-to-end across the workspace twice, and the daily systemd timer has been observed firing in production (May 4 self-scan, May 5 termag rescan), so the deploy is exercised end-to-end and not just at install time. Scanner skeleton with bundled Semgrep + Gitleaks runners, Claude triage layer writing `findings/projects/<project>.{json,md}`, the LOC-threshold selector + multi-root + `--all` + bot-commit-on-write, the Express server with Google OAuth (humans) + bearer-token (machines) auth + JSON API, the React + Vite SPA at `/security/`, and the deploy bundle (systemd web unit `deploy/agent-security.service`, oneshot scanner unit `deploy/agent-security-scanner.service`, daily 03:30 timer `deploy/agent-security-scanner.timer`, `deploy/run-daily.sh` entry script, `deploy/apache.conf` proxy snippet, and `deploy/setup.md` walkthrough) are all in place. The scanner is self-driving — `npm run scanner -- run --all` discovers AGENTS.md-marked projects under `PROJECT_ROOTS`, picks ones with ≥`LOC_THRESHOLD` (default 200) LOC changed since `last_scanned_sha`, scans them, and commits the findings as `agent-security[bot]`. The server (`npm run server` → `127.0.0.1:3046`, mounted at `/security`) reads `findings/projects/*.json` on demand, serves the rollup at `GET /security/api/{health,projects,projects/:name,projects/:name/history,findings,hosts,hosts/:name,hosts/:name/history}`, and hosts the UI bundle from `ui/dist`. `npm run cli -- token create --name <name>` mints bearer tokens stored hashed in `service/api-tokens.json`. The UI has Home (projects table with severity chips), Project (full findings grouped by severity, with a per-project scan-history view), Findings (cross-project rollup with severity + category filters), Hosts (host rollup), and Host (per-host findings with history).

Host-scanning is now invokable end-to-end on the CLI **and surfaced in the API + UI**. The findings JSON schema bumped to v2 with a `kind: "project" | "host"` discriminator and optional CVE fields on findings, host scan output types live in `service/src/scanner/host-types.ts` with corresponding writers in `apply.ts`, and a `HostToolRunner` interface (parallel to `ToolRunner`) is in `service/src/scanner/tools/host-types.ts` with a bundled Trivy runner at `service/src/scanner/tools/trivy.ts` (scoped to OS-package vulns, with noisy dirs skipped). The CLI grew a `--host` mode (and `SCAN_HOST=true` opt-in for `--all`) that runs `gatherHostInfo` (uname + /etc/os-release + dpkg-query) → host selector (package-set sha + 24h daily floor) → `scanHost` orchestrator → category-aware Claude triage of critical/high raws (mediums/lows stay on the naive path with linux-* → kernel-cve, else package-cve) → `findings/hosts/<name>.{json,md}` → bot commit. The server now reads `findings/hosts/*.json`, exposes `/security/api/hosts*` endpoints, and the SPA has Hosts + Host pages. Not yet wired: per-host daily-timer deploy walkthrough (task #45) — broader scope in `spec/host-scanning.md`.

Decided:

- Standalone repo (not a module of agent-wiki). Rationale: security findings have a different lifecycle (open/regress/dismiss) than docs (drift), and a dedicated prompt/cadence reads cleaner than a multi-purpose sweeper.
- Hybrid analysis: Semgrep (working-tree static analysis) and Gitleaks (full-history secret detection) bundled as default tool runners; Claude does triage, prioritization, severity ranking, and rationale. The `ToolRunner` interface is small enough that adding `bandit`, `npm audit`, etc. is a TS file plus a one-line registration in `run.ts`.
- Findings live centrally at `${FINDINGS_DIR}/projects/<project>.{json,md}` and `${FINDINGS_DIR}/hosts/<host>.{json,md}`, committed by a bot identity each scan. `FINDINGS_DIR` defaults to this repo's `findings/` but can point at a separate (often private) findings repo so the open-source code repo doesn't accumulate workspace-specific findings. v1 does **not** write back into project AGENTS.md files; the wiki UI links across to `/security/projects/<name>` instead.
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
8. ✅ Per-project scan history viewer (UI + `/security/api/projects/:name/history`, derived from `git log findings/projects/<project>.json`).
9. ✅ Open-source prep: LICENSE + README, parameterized default paths, separable findings repo via `FINDINGS_DIR`, in-tree findings dropped.
10. ✅ Route findings through `findings/projects/<project>.{json,md}` to leave room for a `hosts/` peer.
11. ✅ Host scanning end-to-end: schema v2 with `kind` discriminator, host output types + writers, `HostToolRunner` interface, bundled Trivy runner, CLI/selector/orchestrator, hosts API + UI surface, and category-aware Claude triage of critical/high CVEs. Still to do: per-host daily-timer fan-out walkthrough (#45) — see `spec/host-scanning.md`.
12. Future: dismissals, PR suggestions, Stop-hook trigger, AGENTS.md summary block.

## Repository Layout

```
agent-security/
├── AGENTS.md                  this file
├── CLAUDE.md                  one-line @AGENTS.md stub
├── README.md                  human-facing intro
├── LICENSE
├── spec/
│   ├── findings-schema.md     JSON shape (v2: `kind` discriminator, optional CVE fields), severities, categories
│   ├── tools.md               ToolRunner + HostToolRunner interfaces; how to register extras
│   └── host-scanning.md       scoping doc for host scans as a peer to project scans (CLI + API + UI now wired; per-host timer fan-out still pending)
├── findings/                  default findings dir (override with FINDINGS_DIR)
│   ├── .gitkeep               keeps the directory in fresh clones; real findings
│   │                          typically live in a separate repo pointed to by FINDINGS_DIR
│   ├── projects/              per-project scan output (`<project>.{json,md}`)
│   └── hosts/                 per-host scan output (`<host>.{json,md}`); writers, CLI, API, and UI wired; daily-timer fan-out still pending
├── service/
│   ├── package.json
│   ├── tsconfig.json
│   ├── .env.example
│   └── src/
│       ├── cli/
│       │   └── index.ts       admin CLI: `token create|list|revoke`
│       ├── scanner/
│       │   ├── cli.ts         run | run --project | --all | --host | --dry-run | --force
│       │   ├── run.ts         orchestrates one project's scan
│       │   ├── run-host.ts    orchestrates one host's scan (gather → tools → triage → write)
│       │   ├── host-info.ts   gathers host identity: uname + /etc/os-release + dpkg-query
│       │   ├── select-host.ts host selector: package-set sha + 24h daily floor
│       │   ├── tools/
│       │   │   ├── types.ts        ToolRunner interface + RawFinding shape
│       │   │   ├── host-types.ts   HostToolRunner interface + host RawFinding shape
│       │   │   ├── semgrep.ts      bundled: working-tree static analysis
│       │   │   ├── gitleaks.ts     bundled: full-history secret detection
│       │   │   └── trivy.ts        bundled host-tool: OS-package CVE scan (skips noisy dirs)
│       │   ├── prompt.ts      security-analyst prompt + tool-output assembly
│       │   ├── claude.ts      Anthropic API wrapper
│       │   ├── triage.ts      runs Claude over RawFindings → Finding[] (project + host shapes; host path Claude-triages criticals/highs, naive for medium/low/info)
│       │   ├── source.ts      reads source slices around finding lines for the prompt
│       │   ├── apply.ts       writes findings/{projects,hosts}/<name>.{json,md} + commits
│       │   ├── git.ts         per-project diff stats, sha, commit-on-write
│       │   ├── select.ts      LOC-threshold + force/all logic
│       │   ├── types.ts       project scan types (kind: "project")
│       │   └── host-types.ts  host scan output types (kind: "host")
│       └── server/            Express service on 127.0.0.1:3046
│           ├── index.ts       Express entry; mounts /security on :3046
│           ├── config.ts      env loader (parameterized defaults)
│           ├── auth.ts        Passport OAuth (humans) + bearer middleware (machines)
│           ├── tokens.ts      mint / verify; hashed at rest in api-tokens.json
│           ├── api.ts         JSON endpoints under /security/api (projects + hosts)
│           └── data.ts        reads findings/projects/*.json and findings/hosts/*.json; branches on `kind`
├── ui/                        React + Vite SPA, served by backend at /security/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts         base: '/security/', dev proxy to :3046
│   ├── tsconfig.json
│   └── src/
│       ├── main.tsx           BrowserRouter basename='/security'
│       ├── App.tsx            routes: Home, Project, Findings, Hosts, Host, Login
│       ├── api.ts             fetch wrappers for /security/api/* (projects + hosts)
│       ├── styles.css
│       ├── components/
│       │   ├── Layout.tsx     shell + nav (Projects / Findings / Hosts)
│       │   └── SeverityChip.tsx
│       └── pages/
│           ├── Home.tsx       projects table with severity chips
│           ├── Project.tsx    full findings grouped by severity
│           ├── Findings.tsx   cross-project rollup with severity + category filters
│           ├── Hosts.tsx      hosts table with severity chips
│           ├── Host.tsx       per-host findings + scan history
│           └── Login.tsx
└── deploy/
    ├── agent-security.service           systemd unit for the web service (ships with /opt placeholders — edit before installing)
    ├── agent-security-scanner.service   user-mode oneshot invoked by timer
    ├── agent-security-scanner.timer     daily 03:30 fan-out (offset from agent-wiki's 03:00)
    ├── run-daily.sh                     timer entrypoint: scanner --all + best-effort `git push` from FINDINGS_DIR's repo
    ├── apache.conf                      ProxyPass /security → 127.0.0.1:3046 (splice into your existing vhost)
    └── setup.md                         install walkthrough
```

Note: `triage.ts` and `source.ts` weren't in the original sketch. `triage.ts` owns the Claude pass over `RawFinding[]` and handles both project and host scan shapes — for host scans it splits raws by tool-native severity, sends critical+high through Claude (with per-CVE grouping so the kernel-headers explosion collapses to one verdict per CVE), and leaves medium/low/info on a category-aware naive path; `source.ts` reads the source-window slices that get embedded in the prompt. `prompt.ts` assembles, `claude.ts` is just the API wrapper. The admin CLI lives at `service/src/cli/index.ts` (separate from the scanner CLI) and is the entry point for token management. Project findings live under `findings/projects/`; `findings/hosts/` is the peer for host scans — writers in `apply.ts`, the full CLI path (`host-info.ts` → `select-host.ts` → `run-host.ts`), and the API + UI surface are all wired, but daily-timer fan-out for hosts is still pending (see `spec/host-scanning.md`). Both `service/src/scanner/host-types.ts` (output schema) and `service/src/scanner/tools/host-types.ts` (runner interface) exist by design: one defines what a host scan *produces*, the other defines what a host *tool runner* must implement, mirroring the project-side `types.ts` / `tools/types.ts` split.

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
                   │      write findings/projects/<project>.{json,md} │
                   │      git add + commit (bot identity) + push      │
                   │                                                  │
Manual CLI ───────▶│  --host: gather host info → select-host →        │
(--all + SCAN_HOST)│      run HostToolRunners (trivy + …)             │
                   │      → RawFindings[] (with optional CVE fields)  │
                   │      Claude triage for critical/high CVEs        │
                   │      (per-CVE grouping; rationale ends in        │
                   │       `apt upgrade` / kernel-reboot hint)        │
                   │      naive path for medium/low/info              │
                   │      → Finding[] (kind: "host")                  │
                   │      write findings/hosts/<host>.{json,md}       │
                   └──────────────────────────────────────────────────┘
                                    │
                          findings/{projects,hosts}/*.json (committed)
                                    │
                                    ▼
Browser ──https──▶ Apache (:443, /security/*) ──http──▶ Express (:3046, /security/*)
Jira/scripts ─────Bearer token───────────────────────▶  ├── /security/auth/*  Passport (Google OAuth, allowlist)
                                                        ├── /security/api/*   JSON (projects, hosts, findings, health)
                                                        └── /security/*       SPA from ui/dist
```

**Trade-off: standalone repo vs. extending agent-wiki** — chose standalone. The sweeper-vs-scanner code overlap (sources walker, Express + OAuth scaffolding) is real but thin. The two need different prompts, different cadences, different output shapes, and have different failure modes. Bundling them would force one prompt to do two jobs and entangle release cycles.

**Trade-off: central findings repo vs. in-tree files in each project** — chose central. (a) `git log findings/<project>.json` here is the security history of that project, no per-project archaeology required. (b) High-churn machine output doesn't pollute project-repo PRs and history. (c) The wiki sweeper and the security scanner never fight over the same file. Cost: the project repo doesn't show findings to a developer just by `ls`, so the wiki UI grows a cross-link.

**Trade-off: hybrid (Semgrep + Claude) vs. pure-LLM scanning** — chose hybrid. Semgrep gives deterministic, reproducible findings tied to named rules with known precision/recall, runs locally for free, and covers all the languages in the workspace. Pure-LLM scans are noisy, expensive, and unstable across runs. Claude's job is triage and contextual prioritization, not pattern detection.

**Trade-off: bundled tools vs. config-driven registry** — chose "two bundled, hardcoded for now" on the project side, with Trivy bundled on the host side. Semgrep covers working-tree static analysis; Gitleaks covers full-history secret detection — the two cheap-to-run, high-signal axes worth running on every project. Trivy plays the same role for hosts (OS-package CVE scan, scoped to package vulns and skipping noisy dirs to keep runtime sane). A YAML registry that loads user-configured extras was sketched in `spec/tools.md` but deferred: with a small handful of bundled tools and zero outside contributors, the indirection has no users to fit. Adding a fourth (e.g. `bandit`, `npm audit`) is one TS file plus a one-line append to `REGISTERED_TOOLS` in `run.ts`. Each tool's output is normalized to the common `RawFinding` shape before triage.

**Trade-off: shared output type vs. parallel project/host hierarchies** — chose a shared envelope with a `kind: "project" | "host"` discriminator (schema v2) plus parallel `ToolRunner` / `HostToolRunner` interfaces. The discriminator lets one writer pipeline serve both modes (with optional CVE fields on findings for the host case), while two runner interfaces keep the *inputs* honest: project tools take a working tree + git history, host tools take a host identity + a way to reach it. Mashing both into one runner interface would have produced an awkward union of "this argument is sometimes set" parameters.

**Trade-off: triage every host raw vs. only critical/high** — chose a split. A workstation can produce 10k+ raw host findings, dominated by the same kernel CVE flagged across every `linux-headers-*` package; sending all of them through Claude was projected at ~$30/scan with most of the cost going to mediums the user can't act on without an `apt upgrade`/reboot anyway. The current split sends critical + high raws through a per-CVE-grouped Claude pass (≈$0.05/scan in practice — the kernel-headers explosion collapses to one verdict per CVE) and leaves medium/low/info on a naive path that derives `kernel-cve` vs `package-cve` from the package-name prefix. The user's default UI filter is critical+high, so the calibrated rationale lands exactly where attention goes; if a medium turns out to need the same rationale treatment, the split point is one constant in `triage.ts` (`HOST_CLAUDE_SEVERITIES`).

**Trade-off: report-only vs. propose-patches in v1** — chose report-only. Patch generation needs branch hygiene, signing, and a review loop that's worth its own iteration. Findings-first lets us learn what the noise floor looks like before automating fixes.

**Trade-off: scan output replaces vs. accumulates** — chose full replacement (no dismissals in v1). Simpler state, no ID stability requirement, no ack store. The cost is no "won't fix" memory — if a true false positive resurfaces every scan, that's the signal to add dismissals, with stable IDs hashed from `(rule_id, file, normalized_line_context)`.

**Trade-off: dual auth vs. OAuth-only** — chose dual. Humans get OAuth like the wiki; machines (Jira, ticketing scripts) get bearer tokens minted via CLI and stored hashed (`service/api-tokens.json`, gitignored). Same endpoints, two authenticators.

## Data & Schema

Findings JSON is now **schema v2**: a top-level `kind` discriminator (`"project" | "host"`) selects between project-scan and host-scan envelopes, and findings carry optional CVE fields (`cve`, `cvss`, `fixed_version`) for host/dependency scans. Each scan fully overwrites its file.

**Project scan** — `findings/projects/<project>.json`:

```json
{
  "kind": "project",
  "schema_version": 2,
  "project": "rssreader",
  "root": "/path/to/projects",
  "last_scanned": "2026-05-09T03:30:00Z",
  "last_scanned_sha": "abc1234",
  "loc_at_scan": 4231,
  "loc_changed_since_previous": 312,
  "tools_run": [{ "name": "semgrep", "version": "1.x" }],
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

**Host scan** — `findings/hosts/<host>.{json,md}` (writers landed; runner not yet wired into a CLI entry point):

```json
{
  "kind": "host",
  "schema_version": 2,
  "host": "web-01",
  "last_scanned": "2026-05-09T03:30:00Z",
  "tools_run": [{ "name": "trivy", "version": "0.x" }],
  "counts": { "critical": 1, "high": 4, "medium": 12, "low": 30, "info": 0 },
  "findings": [
    {
      "id": "sha256:...",
      "severity": "high",
      "category": "deps",
      "title": "openssl 3.0.x vulnerable to CVE-2024-XXXX",
      "package": "openssl",
      "installed_version": "3.0.2",
      "fixed_version": "3.0.13",
      "cve": "CVE-2024-XXXX",
      "cvss": 7.5,
      "source": "trivy",
      "rule_id": "trivy:CVE-2024-XXXX",
      "rationale": "Claude paragraph on exploitability in this host's context."
    }
  ]
}
```

Severity vocabulary: `critical | high | medium | low | info`. Claude does final ranking; tool-native severities (Semgrep `ERROR`/`WARNING`/`INFO`, Trivy CVSS bands) are inputs only. Categories are free-form short slugs (`injection`, `secrets`, `auth`, `deps`, `crypto`, `xss`, `ssrf`, `config`, `other`); the API surfaces them for filtering but doesn't enforce an enum yet.

`findings/{projects,hosts}/<name>.md` is a human-readable mirror, generated from the JSON: severity-grouped headings with file:line (or package@version for hosts), rule, rationale.

`id` is a stable hash to support a future dismissals layer. Today nothing reads it cross-scan.

The `findings/projects/` and `findings/hosts/` subdirectories prevent collisions between any project literally named `hosts` and the host-scan namespace, and keep the two scan modes cleanly separable for the eventual UI split. Full schema details, including the v1→v2 migration shape, live in `spec/findings-schema.md`; host-scan scope and lifecycle are in `spec/host-scanning.md`.

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
| `FINDINGS_DIR` | Where the scanner writes findings (default: `<repo>/findings`). Can point at a directory inside a *separate* git repo — `run-daily.sh` will commit + push from whichever repo owns `FINDINGS_DIR`. |
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
npm run scanner -- run --host                           # scan the local host (gather → trivy → triage → write findings/hosts/<host>.{json,md})
SCAN_HOST=true npm run scanner -- run --all             # opt host scan into the --all fan-out (selector: package-set sha + 24h floor)
```

**Admin CLI** (`service/src/cli/index.ts`):

```bash
npm run cli -- token create --name jira                 # mint a bearer token; plaintext shown once
npm run cli -- token list                               # list tokens by name + created-at
npm run cli -- token revoke --name jira                 # remove a token
```

**Production deploy:** mirrors agent-wiki. `deploy/agent-security.service` runs the compiled web process (`node dist/server/index.js`) on `127.0.0.1:3046` under a hardened systemd unit (`ProtectHome=read-only`, `ReadWritePaths` for `service/.sessions`). The committed unit ships with `/opt/agent-security/...` placeholders — edit `User`, `Group`, `WorkingDirectory`, `EnvironmentFile`, and `ReadWritePaths` to match your install before `sudo cp`-ing into `/etc/systemd/system/`. The Apache splice in `deploy/apache.conf` proxies `/security` — add it inside your existing HTTPS `*:443` vhost. Daily fan-out is `deploy/agent-security-scanner.timer` (03:30 local, offset from agent-wiki's 03:00) firing `agent-security-scanner.service` (user-mode oneshot) which runs `deploy/run-daily.sh`: that script loads `service/.env`, runs `node dist/scanner/cli.js run --all`, then best-effort `git push origin` from the repo that owns `FINDINGS_DIR` (which may be a different repo than the agent-security code repo). Output is tee'd to `~/.local/state/agent-security/last-run.log`. Setting `SCAN_HOST=true` in the env routes a host scan through the same `--all` fan-out (selector enforces a 24h daily floor), but a per-host timer walkthrough specifically for fanning out across multiple hosts (task #45) hasn't shipped. Full step-by-step in `deploy/setup.md`.

## Observability & Maintenance

- `journalctl --user -u agent-security-scanner` for scanner runs; `journalctl -u agent-security` for the web service.
- `GET /security/api/health` for an unauthenticated liveness probe.
- Findings history is just `git log findings/projects/<project>.json` in the repo that owns `FINDINGS_DIR` — the bot commits give a per-scan timeline.
- Token revocation: delete the row from `service/api-tokens.json` and restart the service.
- File-based sessions live in `service/.sessions/` (gitignored). Deleting the directory force-logs all human users out.

## Integration Surfaces

JSON API, intentionally small. All endpoints accept either a session cookie (humans) or `Authorization: Bearer <token>` (machines), except `/health` and the OAuth dance.

| Endpoint | Returns |
|----------|---------|
| `GET /security/api/projects` | List of projects with `last_scanned`, severity counts, `loc_at_scan` |
| `GET /security/api/projects/:name` | Full findings for one project |
| `GET /security/api/projects/:name/history` | Per-scan history for one project, derived from `git log findings/projects/<project>.json` (commit sha, scan timestamp, severity counts) |
| `GET /security/api/hosts` | List of hosts with `last_scanned`, severity counts, host identity (os, kernel) |
| `GET /security/api/hosts/:name` | Full findings for one host (kind: "host", with CVE fields where applicable) |
| `GET /security/api/hosts/:name/history` | Per-scan history for one host, derived from `git log findings/hosts/<host>.json` |
| `GET /security/api/findings?severity=high&category=injection&since=2026-05-01` | Cross-project rollup with filters; capped |
| `GET /security/api/health` | `{ ok: true }` (unauthenticated) |
| `POST /security/api/tokens` | (admin only) mint a new bearer token; plaintext returned once |
| `DELETE /security/api/tokens/:name` | revoke |
| `GET /security/auth/google` | OAuth start |
| `POST /security/auth/logout` | destroy session |

A Jira / ticketing integration looks like: scheduled job hits `/security/api/findings?severity=high` with a bearer token, diffs against the previous response, opens tickets for new entries. The scanner does not push to Jira itself — the integration owns its own state and policy.

## Gotchas

1. **Findings files are bot-owned** — every scan fully replaces `findings/projects/<project>.json` (or `findings/hosts/<host>.json`) and commits as `bot:agent-security`. Hand-editing them between scans will be blown away on the next run. If you need a finding to stop appearing, the v2 dismissals layer is the right place; until then, fix the underlying issue.

2. **`last_scanned_sha` drives the LOC selector** — if you delete or hand-edit `findings/projects/<project>.json`, the next selector run treats the project as never-scanned and full-scans it. Usually fine; just be aware why the daily ran longer than expected.

3. **No dismissals in v1** — a true false positive from Semgrep will reappear every scan. That's intentional for the noise-discovery phase. Track the pattern; if it's painful, that's the signal to build dismissals (stable `id` is already in the JSON for this).

4. **Port 3046, prefix `/security`** — must agree across `PATH_PREFIX` env, `vite.config.ts` (`base: '/security/'`), `BrowserRouter` (`basename="/security"`), the systemd unit, and the Apache snippet. Changing the prefix requires touching all five.

5. **Bundled tools are version-sensitive** — Semgrep rule packs, Gitleaks default rules, and Trivy's vuln DB all evolve, and a rule/DB update can flip a target from "0 findings" to "10 findings" with no actual code or host change. Tool versions are recorded in `tools_run[].version` in every output JSON so you can correlate a regression to a tool bump rather than a real change. Bumping any of them is a deliberate commit, not a transitive dep float — and worth a sweep-worthy review of the diffs that the new rules surface.

6. **Multi-root name collisions** — two roots can both contain `foo/`. The scanner qualifies findings by root index (`projects/foo`, `other-root/foo`). The UI shows the qualified name; bare `foo` is ambiguous and rejected in API queries.

7. **systemd user units start with an empty `PATH`** — `npx`, `node`, `git`, and `semgrep` all need to resolve, and a user-mode service unit doesn't inherit your login shell's environment. `run-daily.sh` exports a sensible `PATH` (including `~/.nvm`/`~/.local/bin`) before invoking the scanner; don't bypass it by calling `node dist/scanner/cli.js` directly from the unit. Symptom on first deploy was a silent exit with `npx: command not found` in `last-run.log`.

8. **Unborn repos crash `git rev-parse HEAD`** — a freshly-`git init`'d project with no commits has no `HEAD`, and the scanner used to die there. `select.ts` / `git.ts` now treat unborn repos as "never scanned, no diff stats" and skip them cleanly. If you add a new git wrapper, mirror that defense — `git symbolic-ref -q HEAD` succeeds on an unborn repo but `rev-parse HEAD` does not.

9. **`FINDINGS_DIR` may be a different repo than the code** — the open-source code repo ships an empty `findings/` (just `.gitkeep`), and a real deployment typically points `FINDINGS_DIR` at a separate (often private) git repo. `run-daily.sh` runs its `git add`/`commit`/`push` from whichever repo owns `FINDINGS_DIR`, *not* from the code repo. Consequence: bot commits and the scan-history view both come from the findings repo, so `git log findings/projects/<project>.json` is meaningful only there. If `FINDINGS_DIR` is set to a directory that isn't a git repo, the scanner still writes files but no history accrues.

10. **Project findings live under `findings/projects/`, not flat `findings/`** — recent rework moved per-project output into a `projects/` subdirectory so the host-scanning peer (`findings/hosts/`, scoped in `spec/host-scanning.md`) can sit alongside without colliding with a project literally named `hosts`. Anything that globs `findings/*.json` (old scripts, ad-hoc tooling, external integrations) needs to be updated to `findings/projects/*.json`.

11. **Findings JSON is now schema v2 with a `kind` discriminator** — every output file carries `kind: "project" | "host"` and `schema_version: 2`, and host findings can carry CVE fields (`cve`, `cvss`, `fixed_version`, `package`, `installed_version`) that project findings don't have. Anything reading the JSON should branch on `kind` before assuming project-shaped fields like `file`/`line` exist; `service/src/server/data.ts` does this branching internally so the project and host API endpoints don't cross-contaminate. Older v1 files (no `kind`, no `schema_version`) should be treated as `kind: "project"` for back-compat — the writers always emit v2 going forward, so a single re-scan migrates a file in place.

12. **Two host-side type files, by design** — `service/src/scanner/host-types.ts` defines what a host scan *produces* (output envelope, host finding shape), while `service/src/scanner/tools/host-types.ts` defines the `HostToolRunner` interface that bundled host tools (Trivy, future) must implement. They mirror the project-side `types.ts` / `tools/types.ts` split. Don't merge them — the symmetry is what keeps the runner contract from leaking output-format concerns and vice versa.

13. **Host triage is split: Claude for critical/high, naive for the rest** — `triage.ts` partitions host raws by tool-native severity. CRITICAL/HIGH go through a per-CVE-grouped Claude pass (one verdict per CVE, fanned back across all affected packages so the dashboard still shows one row per `(cve, package, host)`); MEDIUM/LOW/INFO take a naive pass-through that maps Trivy's bands directly and derives the category from the package name (`linux-*` → `kernel-cve`, else `package-cve`). The split is a cost call (10k+ raws per host would be ~$30/scan if all were Claude-triaged) and the threshold is `HOST_CLAUDE_SEVERITIES` in `triage.ts` if it ever needs to move. Severity counts on the output JSON are post-triage, so a CVE Claude downranks from HIGH→LOW lands in the `low` count even if Trivy called it HIGH.

14. **Host scans are CLI + API + UI but not yet on the daily timer** — `--host` and `SCAN_HOST=true ... --all` write `findings/hosts/<host>.{json,md}` and commit, the `/security/api/hosts*` endpoints serve them, and the SPA has Hosts + Host pages. What's *not* yet shipped is a per-host daily-timer fan-out walkthrough (task #45) — `SCAN_HOST=true` in the env will route the local host through `--all`, but scanning multiple hosts on a schedule still needs the deploy story documented in `spec/host-scanning.md`.

15. **Trivy is scoped to OS-package vulns and skips noisy dirs** — the bundled Trivy runner (commit `c2089f1`) drops `--skip-db-update`, restricts scanning to OS packages, and skips a curated set of noisy directories (caches, mounts, etc.) to keep host-scan runtime sane. If you're expecting Trivy to surface filesystem-secret or misconfig findings, it won't — that scope is intentionally out for v1. Bumping Trivy versions or changing the skip list is a deliberate commit; the version is recorded in `tools_run[].version` in each host JSON for regression correlation.

## Related

**Other projects:**
- [agent-wiki](../agent-wiki/AGENTS.md) — same architecture pattern (Express + OAuth + Vite UI + systemd timer + Claude API sweeper). agent-security borrows scaffolding shape and deploy convention; the wiki UI will link out to `/security/projects/<name>` per project.

**Topics:** none yet.

<!-- agent-wiki:backlinks-start -->
_No incoming links yet._
<!-- agent-wiki:backlinks-end -->
