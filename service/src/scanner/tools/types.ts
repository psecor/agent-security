// ToolRunner interface and the RawFinding shape that runners emit.
// See spec/tools.md for the full contract.

export interface ToolRunner {
  readonly name: string;
  version(): Promise<string | null>;
  run(projectPath: string, ctx: ToolContext): Promise<RawFinding[]>;
}

export interface ToolContext {
  sha: string;
  log: (level: LogLevel, msg: string) => void;
  scratchDir: string;
}

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface RawFinding {
  source: string;
  rule_id: string;
  severity: string;
  // Required for project findings; optional for host findings (a CVE attached
  // to an installed package has no source line). Project tools (Semgrep,
  // Gitleaks) always populate them; host tools (Trivy) leave them undefined
  // and the host triage path keys IDs off the CVE + package + hostname instead.
  file?: string;
  line?: number;
  line_end?: number;
  message: string;
  links?: string[];
  raw?: unknown;
}

// Per-tool entry in the scan output. `error` is set only when the runner rejected.
export interface ToolRunRecord {
  name: string;
  version: string | null;
  rules_version?: string;
  error?: string;
}
