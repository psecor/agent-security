---
title: agent-security deployment
---

# Deploying agent-security

agent-security runs as a single Express service on `127.0.0.1:3046`,
fronted by your reverse proxy (e.g. Apache) on a public HTTPS URL. It
hosts both the JSON API (under `<PATH_PREFIX>/api/*`) and the React UI
(built static assets) from the same Node process. Sessions are
file-backed (no DB). Bearer tokens for machine clients are stored
hashed in `service/api-tokens.json` (gitignored).

The scanner runs separately, on a daily user-mode systemd timer at
03:30 local. It walks every project under `PROJECT_ROOTS` that's
changed by ≥ `LOC_THRESHOLD` lines since its last scan, runs the
configured tool runners (Semgrep bundled), feeds raw output through
the Claude triage layer, and commits the resulting findings into the
agent-security repo as a bot identity.

This guide covers the one-time install. Day-to-day updates are just
`git pull && (cd service && npm install && npm run build) && (cd ui &&
npm install && npm run build) && sudo systemctl restart agent-security`.

## Prerequisites

- Node 20+ on the box.
- `semgrep` on `PATH` (`pipx install semgrep` is the easiest install).
- Git configured so the bot can commit (the scanner sets the bot
  identity per-commit via `-c user.name=… -c user.email=…`, so no
  global config change is required).
- A reverse proxy (Apache + `proxy`, `proxy_http`, `headers` modules;
  or Nginx, Caddy, etc.).
- An HTTPS cert covering the domain you're serving from.

## 1. Build server + UI

From the agent-security repo root:

```sh
cd service
npm install
npm run build          # tsc → dist/

cd ../ui
npm install
npm run build          # vite → dist/  (base: ${PATH_PREFIX}/)
```

Run the scanner once on a single project so `findings/<project>.json`
exists and the UI has something to render:

```sh
cd ../service
npm run scanner:built -- run --project <some-project>
```

## 2. Google OAuth client

You can either reuse an existing OAuth client (e.g. agent-wiki's) by
adding a second redirect URI to it, or create a new one. Either way,
type: **Web application**.

- Authorized redirect URI: `https://<your-domain>/<PATH_PREFIX>/auth/google/callback`
- Authorized JavaScript origin: `https://<your-domain>`

Note the client ID and secret — they go in `.env` next.

## 3. Service `.env`

Copy `service/.env.example` to `service/.env` and fill in:

```env
# Scanner
PROJECT_ROOTS=/path/to/your/projects
LOC_THRESHOLD=200
ANTHROPIC_API_KEY=<your key>

# Web service
PORT=3046
BASE_URL=https://your-domain.example.com
PATH_PREFIX=/security
SESSION_SECRET=<long random hex>
GOOGLE_CLIENT_ID=<from step 2>
GOOGLE_CLIENT_SECRET=<from step 2>
ALLOWED_EMAILS=you@example.com
```

A reasonable session secret:
```sh
openssl rand -hex 32
```

`.env` is gitignored — never commit it.

## 4. systemd unit (web service)

Edit `deploy/agent-security.service` to set `User`, `Group`,
`WorkingDirectory`, `EnvironmentFile`, and `ReadWritePaths` to match
your install (the file ships with `/opt/agent-security/...`
placeholders). Then:

```sh
sudo cp deploy/agent-security.service /etc/systemd/system/agent-security.service
sudo systemctl daemon-reload
sudo systemctl enable --now agent-security
sudo systemctl status agent-security
journalctl -u agent-security -f
```

You should see `[agent-security] listening on 127.0.0.1:3046, mounted
at <PATH_PREFIX>`.

## 5. Reverse proxy

For Apache, add the contents of `deploy/apache.conf` to the existing
HTTPS VirtualHost for your domain. Then:

```sh
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Browse to `https://<your-domain>/<PATH_PREFIX>/` and sign in with an
allowlisted Google account.

## 6. Daily scanner timer

A user-mode systemd timer runs `scanner --all` once a day at 03:30
local — offset from agent-wiki's 03:00 sweep so the two don't fight
for CPU or the Anthropic rate limit. Output goes to `journalctl --user`
**and** is tee'd to `~/.local/state/agent-security/last-run.log` for
quick review.

Edit `deploy/agent-security-scanner.service` so its `ExecStart` points
at your checkout's `deploy/run-daily.sh`. Then:

```sh
# Install the unit files into your user systemd config.
mkdir -p ~/.config/systemd/user
cp deploy/agent-security-scanner.service \
   deploy/agent-security-scanner.timer \
   ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable --now agent-security-scanner.timer

# So the timer fires even when you're not logged in:
sudo loginctl enable-linger "$USER"
```

The scanner needs `ANTHROPIC_API_KEY` set in `service/.env` — that's
how it pays for the Claude triage calls.

Verify and observe:

```sh
systemctl --user list-timers agent-security-scanner.timer
journalctl --user -u agent-security-scanner -n 200
cat ~/.local/state/agent-security/last-run.log
```

Trigger a manual run (useful for first-time validation):

```sh
systemctl --user start agent-security-scanner.service
# …or run the script directly outside of systemd:
deploy/run-daily.sh
```

If the agent-security repo has an `origin` remote configured, the
script also pushes the bot commits at the end so the central findings
rollup stays in sync off-host. The push is best-effort — a failed
push does not fail the run.

Edit the cadence by changing `OnCalendar=` in the `.timer` file and
re-running `systemctl --user daemon-reload`.

## 7. Bearer tokens for machine clients

Mint a token for each machine client (e.g. a Jira sync script):

```sh
cd service
npm run cli:built -- token create --name jira
# prints the plaintext token once; record it in your secret store now
```

The hashed token lands in `service/api-tokens.json` (gitignored, mode
`0600`). The server re-reads this file on every verification, so newly
minted or revoked tokens take effect without a restart.

List or revoke:

```sh
npm run cli:built -- token list
npm run cli:built -- token revoke --name jira
```

Use the token via `Authorization: Bearer <plaintext>` against any
`/security/api/*` endpoint.

## Troubleshooting

- **"GOOGLE_CLIENT_ID is required in environment"** — `.env` not
  present or systemd `EnvironmentFile=` path wrong. Check
  `journalctl -u agent-security`.
- **OAuth redirects back with `?error=denied`** — your email isn't in
  `ALLOWED_EMAILS`. Add it (comma-separated), restart the service.
- **Reverse proxy 503** — service isn't running.
  `sudo systemctl status agent-security`.
- **Scanner reports `semgrep: command not found`** — install Semgrep
  on the box (`pipx install semgrep`) and confirm it's on the PATH the
  systemd user session sees (`systemctl --user show-environment`).
- **Scanner runs but commits nothing** — most projects under your
  `PROJECT_ROOTS` haven't changed by ≥ `LOC_THRESHOLD` since their
  last scan. Lower the threshold, or run with `--force` to ignore it.
- **Push step fails in `run-daily.sh`** — the script logs the failure
  and continues; findings are already committed locally. Check that
  the user systemd session has the right SSH key / credential helper
  configured for your `origin` remote.
