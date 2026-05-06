# agent-security

A periodic, on-demand security analyst for a workspace of related projects. It walks configured project roots, runs static analysis (Semgrep + Gitleaks bundled, others pluggable), feeds raw findings plus surrounding source slices to Claude for triage and prioritization, and writes structured findings into this repo at `findings/<project>.{json,md}`. A small Express service exposes the rollup behind a reverse proxy for humans (Google OAuth allowlist) and machines (bearer tokens, e.g. Jira / ticketing scripts).

This repo holds:

- The **scanner** — discovers AGENTS.md-marked projects, runs tool runners, calls Claude for triage, writes findings, commits as a bot identity
- The **server** — Express + Passport + bearer-token auth, JSON API + React/Vite SPA at `/security/`
- The **deploy bundle** — systemd web unit, scanner timer + oneshot, run-daily entry script, Apache snippet, walkthrough
- The **spec** ([spec/findings-schema.md](spec/findings-schema.md), [spec/tools.md](spec/tools.md))

## Status

**v1 functionally complete.** Scanner, triage, selector, server, UI, and deploy bundle are all landed; the daily timer fires in production. See [AGENTS.md](AGENTS.md) for the full status writeup, architectural trade-offs, and gotchas.

The committed `findings/` directory is empty — populate it by running the scanner against your own project roots.

## Prerequisites

- **Node.js** 20+
- **Anthropic API key** for the triage layer (skip with `--no-triage` for raw tool output)
- **Semgrep** and **Gitleaks** on `PATH` for the bundled tool runners
- **Apache** (or another reverse proxy) — only if you want to serve the browser UI publicly behind HTTPS
- **Google OAuth client** — only if you want sign-in protection on the browser UI

## Quick start

```bash
cd service
cp .env.example .env       # fill in PROJECT_ROOTS, ALLOWED_EMAILS, etc.
npm install
npm run scanner -- run --project <name> --dry-run   # one project, no commit
npm run server                                       # tsx → :3046
```

See [AGENTS.md](AGENTS.md) and [deploy/setup.md](deploy/setup.md) for the production install walkthrough.

## How it fits with agent-wiki

[agent-wiki](https://github.com/psecor/agent-wiki) is the sister project: same architecture pattern (Express + OAuth + Vite UI + systemd timer + Claude API sweeper), but for documentation drift instead of security findings. agent-security borrows the deploy convention; the wiki UI links across to `/security/projects/<name>` per project.

## Related

- [AGENTS.md](AGENTS.md) — this repo's own agent-readable wiki
- [spec/findings-schema.md](spec/findings-schema.md) — JSON shape, severities, categories
- [spec/tools.md](spec/tools.md) — `ToolRunner` interface + how to register extra tools
- [deploy/setup.md](deploy/setup.md) — production install walkthrough
