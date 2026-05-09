# Host scanning — v1

Defines how the scanner treats a host (the OS / installed-package surface) as a scan target peer to a project. A host scan asks a different question — "are any installed packages or kernel versions vulnerable?" — and has a different remediation path (`apt upgrade`, kernel reboot, hardening config) than a project scan ("are there bugs in this source tree?"). Both still land in the same dashboard, share the same `Finding` shape, and go through the same Claude triage layer.

This document covers the host-specific pieces. The shared `Finding` schema and severity vocabulary live in `findings-schema.md`; the `RawFinding` and `ToolRunner` shapes live in `tools.md`. Read those first.

---

## What a host is

A host is anything addressable by hostname that runs the scanner against itself. v1 assumes:

- The scanner is **co-located** with the host it's scanning (no SSH-out, no agent-on-target). Each host runs its own `agent-security-scanner.timer`.
- Findings from every host are written to a **shared** `FINDINGS_DIR` (a single git repo that all hosts push to). The web UI on the central host reads everyone's findings from that repo.
- Hostname uniqueness is the operator's responsibility. The scanner uses `os.hostname()` by default; override with `HOST_NAME` env when the kernel hostname is generic ("ubuntu", "ip-10-0-0-5") or when multiple hosts would otherwise collide in the findings repo.

The "central host runs the UI, every host scans itself" split exists because giving the scanner SSH-out access to other boxes' filesystems is fragile (sudo, agent forwarding, key rotation), and `FINDINGS_DIR` has been a separable repo since the open-source prep pass — so the multi-writer story is already paid for.

---

## File layout

```
agent-security/findings/
├── projects/
│   ├── <name>.json
│   └── <name>.md
└── hosts/
    ├── <hostname>.json
    └── <hostname>.md
```

The `projects/` and `hosts/` split is on disk rather than via a `target_kind` field so that:

- `git log findings/hosts/<hostname>.json` is the security history of that host, identical in shape to the per-project history view.
- A reader pulling just project findings (or just host findings) can `git sparse-checkout` that subtree.
- Cross-target name collisions (a project named `secorp.net` next to a host named `secorp.net`) are impossible.

The flat `findings/<name>.{json,md}` layout from v0 was migrated to `findings/projects/<name>.{json,md}` in a one-shot rewrite when this spec landed.

Multi-root project name qualification (`other-root__foo.json`) is unchanged from `findings-schema.md`.

---

## Host scan output (JSON schema)

```jsonc
{
  // Host identity
  "host": "secorp.net",                           // matches the file basename
  "kind": "host",                                 // discriminator; "project" for project scans
  "hostname_kernel": "secorp",                    // raw `uname -n`, recorded for ops debugging
  "os_release": {                                 // parsed /etc/os-release, key fields only
    "id": "ubuntu",
    "version_id": "24.04",
    "pretty_name": "Ubuntu 24.04.1 LTS"
  },
  "kernel_version": "6.8.0-107-generic",          // `uname -r`
  "architecture": "x86_64",                       // `uname -m`

  // Scan metadata
  "scanner_version": "0.1.0",
  "schema_version": 2,                            // see findings-schema.md
  "last_scanned": "2026-05-09T03:32:00Z",
  "package_count": 2143,                          // dpkg -l | wc -l (for ops sanity-check)
  "package_set_sha": "a1b2c3d4...",               // see "Selector" below
  "package_set_changed_since_previous": true,     // null on first scan

  // What ran (same shape as project scans)
  "tools_run": [
    {
      "name": "trivy",
      "version": "0.51.4",
      "rules_version": "trivy-db@2026-05-08T18:00:00Z"   // CVE DB build timestamp
    }
  ],
  "tools_failed": [],

  // Aggregate counts (post-triage)
  "counts": { "critical": 0, "high": 3, "medium": 14, "low": 22, "info": 0 },

  // Findings — same `Finding` shape as projects; see findings-schema.md
  "findings": [
    {
      "id": "sha256:...",
      "severity": "high",
      "category": "package-cve",                  // see "Categories"
      "title": "openssl 3.0.2-0ubuntu1.18 has unpatched DoS in TLS handshake (CVE-2026-31431)",
      "source": "trivy",
      "rule_id": "CVE-2026-31431",
      "cve": "CVE-2026-31431",
      "package": "openssl",
      "installed_version": "3.0.2-0ubuntu1.18",
      "fixed_version": "3.0.2-0ubuntu1.19",
      "rationale": "Reachable from any TLS-terminating service on this host. Apache (443) and the agent-security node (3046, behind Apache) both link OpenSSL. Fix: `sudo apt upgrade openssl libssl3` then restart Apache.",
      "links": ["https://ubuntu.com/security/CVE-2026-31431"]
    }
  ]
}
```

### How this differs from project scan output

- `kind: "host"` instead of `kind: "project"` (the field is added to project scans too — see `findings-schema.md`).
- `host` replaces `project`; `os_release` / `kernel_version` / `architecture` replace `project_path` / `root`.
- `package_set_sha` / `package_set_changed_since_previous` replace `last_scanned_sha` / `loc_changed_since_previous` as the "did anything change" signal.
- `Finding.file` and `Finding.line` are **optional** for host findings (a CVE attached to a package has no line number). They remain required for project findings.
- New optional `Finding` fields populated for host findings: `cve`, `package`, `installed_version`, `fixed_version`. See `findings-schema.md` for the field-by-field rules.

The markdown mirror (`findings/hosts/<hostname>.md`) follows the same pattern as the project mirror, with one extra block at the top:

```markdown
# Security findings — secorp.net (host)

_Last scanned <ISO date>; <pretty-name> kernel <kernel-version>; <pkg-count> packages; <N> findings (...)._
```

---

## Categories

Hosts add three categories to the existing project set:

- `package-cve` — vulnerability in an installed OS package; fix is `apt upgrade <pkg>` (or distro equivalent).
- `kernel-cve` — vulnerability in the running kernel; fix is `apt upgrade linux-image-*` plus a reboot.
- `host-config` — hardening / config drift (Lynis-style audit findings); fix is editing `/etc/...` and reloading.

These coexist with the project categories (`injection`, `xss`, `secrets`, etc.). The cross-cutting `/findings` page mixes them; users can filter by category as today.

The triage prompt is category-aware: when it emits a `package-cve` finding, the rationale ends with an `apt upgrade` hint; when it emits an `injection` finding, the rationale references the source-level fix. This keeps "different fix routes for different categories" legible to humans without splitting the dashboard.

---

## Bundled runner: Trivy (host mode)

`scanner/tools/trivy.ts` shells out to the `trivy` binary in the host's PATH and parses `--format json` output. v1 only invokes Trivy's host-scan mode (`trivy rootfs /`) — the language-ecosystem and SBOM modes are out of scope until we have a project-side use case for them.

Defaults:

- Command: `trivy rootfs / --format json --severity LOW,MEDIUM,HIGH,CRITICAL --quiet --skip-db-update --vuln-type os --output <scratchDir>/trivy.json`.
- DB update: managed out-of-band by `run-daily.sh` (one `trivy --download-db-only` before the scan loop), so each scan starts with a known DB age and concurrent host scans don't fight for the lock.
- Severity mapping (Trivy → kept verbatim in `RawFinding.severity`): `CRITICAL | HIGH | MEDIUM | LOW`. The triage layer remaps as usual.
- `rule_id` is the CVE ID (e.g. `CVE-2026-31431`); `RawFinding.message` is Trivy's `Title`; `raw` carries the full Trivy record so the triage layer sees `PkgName`, `InstalledVersion`, `FixedVersion`, `PrimaryURL`.
- Timeout: 600s (Trivy's package walk over a full rootfs takes longer than a per-project scan).

Failure modes:

- `trivy` binary not in PATH → reject with an install hint pointing at `https://aquasecurity.github.io/trivy/`.
- Exit code 0 with non-empty results → success path.
- Exit code 0 with empty results → no findings (success path, `tools_run[]` still records the run).
- Other exit codes → reject with the captured stderr tail.

DB age handling: `tools_run[].rules_version` records the Trivy DB's build timestamp (extracted from `trivy version --format json`). A finding that suddenly appears across many hosts on the same day with no apt upgrades in between is almost certainly a DB bump, not a real regression — see Gotcha #5 in `AGENTS.md` for the version-pinning discipline.

### Stable IDs for host findings

The shared id derivation in `findings-schema.md` (`sha256(rule_id + file + normalized_line_context)`) doesn't fit a host finding — there's no source line. The host runner overrides it:

```
sha256:<hex of: cve_id + "\n" + package_name + "\n" + host_name>
```

The same CVE on the same package on the same host is the same finding across scans, regardless of whether the package version bumped between scans (the version is still in the body, but two different unfixed versions of the same CVE are the same problem). When the CVE is patched and disappears, so does the id — exactly the behavior we want.

---

## Selector

The project selector ("≥ LOC_THRESHOLD changed since `last_scanned_sha`") doesn't apply to hosts. The host selector instead is:

1. **Daily floor** — if the previous scan is more than 24h old, run. Trivy's CVE DB updates daily; even a fully-static host can flip to a vulnerable state because of a new advisory landing in the DB.
2. **Package-set delta** — if `sha256(dpkg-query -W -f='${Package} ${Version}\n' | sort)` differs from the previous scan's `package_set_sha`, run regardless of the daily floor.
3. **`--force`** — bypasses both, same as project scans.

`--all` discovers hosts in addition to projects. A host is "discovered" if `SCAN_HOST=true` is set in the scanner's env. The default is true on a host configured for self-scanning and false on a worker that should only scan projects under it.

---

## CLI

```bash
npm run scanner -- run --host                           # scan THIS host (one host per box, by design)
npm run scanner -- run --host --dry-run                 # show what would change without writing
npm run scanner -- run --host --force                   # bypass selector
npm run scanner -- run --all                            # selector decides projects + (if SCAN_HOST=true) the host
```

There is no `--host <name>` flavor: a scanner instance scans the box it's running on. Cross-host scanning is achieved by deploying the scanner to each host, not by passing a hostname.

---

## Deployment

Per-host install mirrors the existing scanner deploy:

1. Drop `deploy/agent-security-scanner.{service,timer}` into `~/.config/systemd/user/` on the new host.
2. Drop a minimal `service/.env` containing `FINDINGS_DIR` (pointing at the shared findings repo, cloned to a known path on the new host), `ANTHROPIC_API_KEY`, `HOST_NAME`, `SCAN_HOST=true`, and `PROJECT_ROOTS` (empty list is fine if the host doesn't run projects).
3. `systemctl --user enable --now agent-security-scanner.timer`.
4. The first run scans, writes `findings/hosts/<HOST_NAME>.{json,md}`, commits as `agent-security[bot]`, and pushes from the findings repo (same logic `run-daily.sh` already uses).

The web UI does **not** need to be installed on every host — it runs on one central host and reads everyone's findings from the shared repo via normal `git pull`. A small periodic pull of the findings repo on the UI host keeps the dashboard fresh; details in `deploy/setup.md`.

Trivy's CVE DB is downloaded into `~/.cache/trivy/` on each host. First-run cost is a ~700MB download; subsequent runs are incremental. `run-daily.sh` does one `trivy --download-db-only` before the scan loop, so a daily run incurs at most one DB delta even if multiple hosts share the same machine (they don't, in practice, but the discipline is the same).

---

## API surface

Three host endpoints mirror the project endpoints. All authenticated (session cookie or bearer token), all under `/security/api/`:

| Endpoint | Returns |
|----------|---------|
| `GET /api/hosts` | List of hosts with `last_scanned`, severity counts, `package_count` |
| `GET /api/hosts/:name` | Full findings for one host |
| `GET /api/hosts/:name/history` | Per-scan history derived from `git log findings/hosts/<name>.json` |

The cross-cutting `GET /api/findings` rollup picks up host findings too. A new optional `target_kind=project|host` query param filters to one kind; omitting it returns both, with each `FindingWithProject` (rename pending) carrying a `kind` field so the UI can route detail links correctly.

---

## UI surface

Top-nav: `Projects | Hosts | Findings`.

- `/security/hosts` — table of hosts, severity chips, last-scanned, package count. Same shape as the projects table.
- `/security/hosts/:name` — full findings grouped by severity, scan history at the bottom. Header shows OS pretty-name, kernel, package count instead of the project's `last_scanned_sha` / LOC.
- `/security/findings` — adds a target-kind filter alongside severity / category. A row in the rollup shows the target name and links to either the project or host detail view depending on its `kind`.

---

## Versioning

`host-spec-version: 1`. Bumps on the same triggers as `tools-spec-version`:

- New required fields in the host scan output, breaking renames, breaking changes to the package-set hash derivation.
- Pure additions (new optional fields, new bundled host runners like Lynis) don't bump.

A bump cascades to `schema_version` in the on-disk JSON only if the shared `Finding` shape changes. Host-only metadata changes (e.g. adding `architecture`) don't cascade.
