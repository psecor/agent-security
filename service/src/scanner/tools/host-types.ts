// HostToolRunner — parallel to ToolRunner (in types.ts) but for tools that
// scan the host's rootfs / installed packages instead of a project working
// tree. See spec/host-scanning.md.
//
// Both interfaces produce the same RawFinding[] shape; only the input
// context differs.

import type { LogLevel, RawFinding } from "./types.js";

export interface HostToolRunner {
  // Stable identifier, lowercase. Used in `RawFinding.source` and in the
  // host scan output's `tools_run[]`. The bundled implementation is "trivy".
  readonly name: string;

  // Best-effort version string (the runner's binary version). Surfaces in
  // `tools_run[]`. Null when the binary is missing or doesn't report.
  version(): Promise<string | null>;

  // Optional best-effort identifier for the rules / CVE database the runner
  // is using (e.g. Trivy's DB build timestamp). Recorded as
  // `tools_run[].rules_version`. Returning null is fine — not every host
  // tool has a separable rules layer.
  rulesVersion?(): Promise<string | null>;

  // Run against the live host. Implementations must not mutate the rootfs;
  // any intermediate output goes under `ctx.scratchDir`. Resolve even when
  // the underlying tool exits non-zero because findings are present — only
  // reject when the tool itself failed (binary missing, OOM, output
  // unparseable, etc.).
  run(ctx: HostContext): Promise<RawFinding[]>;
}

export interface HostContext {
  // The rootfs to scan. v1 always passes "/", but threading it explicitly
  // keeps the runner testable against a fixture rootfs.
  rootfs: string;
  // Logger surface so runners don't import a global logger.
  log: (level: LogLevel, msg: string) => void;
  // Where to put intermediate artifacts (cleaned up after the scan).
  scratchDir: string;
}
