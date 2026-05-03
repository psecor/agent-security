#!/usr/bin/env bash
# Daily agent-security maintenance: walk all configured PROJECT_ROOTS, run
# the scanner against every project that's changed by ≥ LOC_THRESHOLD lines
# since its last scan, and commit the resulting findings as the bot identity.
#
# Invoked by agent-security-scanner.service via the matching .timer. Output
# is captured by systemd's journal AND tee'd to
# ~/.local/state/agent-security/last-run.log for at-a-glance review without
# `journalctl` ceremony.
#
# If the agent-security repo has an `origin` remote configured, the script
# also pushes the bot commits at the end so the central findings rollup
# stays in sync off-host. The push step is best-effort — a failed push does
# not fail the run (findings are already on disk locally).
#
# Run interactively to dry-test:
#   <repo>/deploy/run-daily.sh

set -euo pipefail

# Resolve SERVICE_DIR + REPO_DIR relative to this script's location so the
# paths work regardless of where the repo is checked out.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SERVICE_DIR="${REPO_DIR}/service"
STATE_DIR="${HOME}/.local/state/agent-security"
LOG="${STATE_DIR}/last-run.log"

mkdir -p "${STATE_DIR}"

# Ensure pipx-installed tools (notably semgrep at ~/.local/bin/semgrep) are
# resolvable. Systemd user services don't source ~/.bashrc / ~/.profile, so
# PATH defaults to a minimal /usr/local/bin:/usr/bin:/bin and won't find
# anything under ~/.local/bin without this.
export PATH="${HOME}/.local/bin:${PATH}"

# Load .env so ANTHROPIC_API_KEY, PROJECT_ROOTS, LOC_THRESHOLD, etc. are
# available. The CLI also calls `dotenv/config`, so this is belt-and-suspenders
# for any subprocesses launched outside Node.
if [[ -f "${SERVICE_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${SERVICE_DIR}/.env"
  set +a
fi

cd "${SERVICE_DIR}"

{
  echo "=== agent-security daily run: $(date -Iseconds) ==="
  echo

  echo ">>> scanner run --all"
  /usr/bin/node dist/scanner/cli.js run --all
  echo

  if git -C "${REPO_DIR}" remote get-url origin >/dev/null 2>&1; then
    echo ">>> git push origin (best-effort)"
    if git -C "${REPO_DIR}" push origin HEAD; then
      echo "push ok"
    else
      echo "push failed — findings are committed locally; investigate later"
    fi
    echo
  fi

  echo "=== done: $(date -Iseconds) ==="
} 2>&1 | tee "${LOG}"
