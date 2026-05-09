// Top-level scan output types. Mirrors spec/findings-schema.md.

import type { ToolRunRecord } from "./tools/types.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  // Required for project findings; omitted for host findings (a CVE attached
  // to an installed package has no source line). See spec/findings-schema.md.
  file?: string;
  line?: number;
  line_end?: number;
  source: string;
  rule_id: string;
  rationale: string;
  links?: string[];
  // Host-finding-only fields (populated by CVE-matching tools like Trivy).
  cve?: string;
  package?: string;
  installed_version?: string;
  fixed_version?: string | null;
}

export interface ScanOutput {
  project: string;
  // Discriminator from schema v2. Host scans use a separate top-level shape
  // (HostScanOutput) — the field is here to make `kind: "project"` explicit
  // on disk so a generic reader can distinguish without sniffing other fields.
  kind: "project";
  root: string;
  project_path: string;
  scanner_version: string;
  schema_version: number;
  // True once the triage layer (Claude) has rewritten titles, rationale,
  // severity, and category. Milestone 1 emits `false` with naive mapping.
  triaged: boolean;
  last_scanned: string;
  last_scanned_sha: string;
  loc_at_scan: number;
  loc_changed_since_previous: number | null;
  tools_run: ToolRunRecord[];
  tools_failed: ToolRunRecord[];
  counts: Record<Severity, number>;
  findings: Finding[];
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
