// Top-level host scan output. Mirrors spec/host-scanning.md.
//
// Distinct from ScanOutput (the project-scan top-level) because the metadata
// is fundamentally different — there's no project_path, root, LOC, or git
// sha for a host. The shared `Finding` shape and severity vocabulary live in
// types.ts; only the wrapper is host-specific.

import type { ToolRunRecord } from "./tools/types.js";
import type { Finding, Severity } from "./types.js";

export interface OsRelease {
  // Parsed from /etc/os-release. Three fields the UI/triage prompt actually
  // use; everything else stays in the file (we just don't surface it).
  id: string;          // e.g. "ubuntu", "debian", "fedora"
  version_id: string;  // e.g. "24.04"
  pretty_name: string; // e.g. "Ubuntu 24.04.1 LTS"
}

export interface HostScanOutput {
  host: string;                                    // matches the file basename
  kind: "host";
  hostname_kernel: string;                         // raw `uname -n`, kept for ops debugging
  os_release: OsRelease;
  kernel_version: string;                          // `uname -r`
  architecture: string;                            // `uname -m`

  scanner_version: string;
  schema_version: number;
  triaged: boolean;
  last_scanned: string;

  package_count: number;
  // sha256 of `dpkg-query -W -f='${Package} ${Version}\n' | sort` (or distro
  // equivalent). Functions as the "did anything change since last scan?"
  // signal — the host-scan equivalent of last_scanned_sha for projects.
  package_set_sha: string;
  // null on the first scan; otherwise true/false vs the previous scan's sha.
  package_set_changed_since_previous: boolean | null;

  tools_run: ToolRunRecord[];
  tools_failed: ToolRunRecord[];
  counts: Record<Severity, number>;
  findings: Finding[];
}
