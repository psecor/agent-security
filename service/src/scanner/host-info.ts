// Reads host metadata used by the host scan output and the host selector.
//
// Sources:
//   - `uname -n/-r/-m` for hostname / kernel / arch
//   - /etc/os-release for distro identity
//   - dpkg-query for installed-package set + sha (Debian/Ubuntu only in v1;
//     non-dpkg hosts return an empty package_set_sha and the selector
//     degrades to the daily floor).

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { OsRelease } from "./host-types.js";

export interface HostInfo {
  hostname_kernel: string;
  os_release: OsRelease;
  kernel_version: string;
  architecture: string;
  package_count: number;
  package_set_sha: string;     // empty string when dpkg-query isn't available
}

export function gatherHostInfo(): HostInfo {
  const pkg = readPackageSet();
  return {
    hostname_kernel: readUname("-n"),
    os_release: readOsRelease(),
    kernel_version: readUname("-r"),
    architecture: readUname("-m"),
    package_count: pkg.count,
    package_set_sha: pkg.sha,
  };
}

function readUname(flag: string): string {
  const r = spawnSync("uname", [flag], { encoding: "utf8" });
  if (r.status !== 0) return "unknown";
  return r.stdout.trim() || "unknown";
}

function readOsRelease(): OsRelease {
  let raw: string;
  try {
    raw = readFileSync("/etc/os-release", "utf8");
  } catch {
    return { id: "unknown", version_id: "unknown", pretty_name: "unknown" };
  }
  const map = new Map<string, string>();
  for (const line of raw.split("\n")) {
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1).trim();
    if (v.startsWith("\"") && v.endsWith("\"")) v = v.slice(1, -1);
    map.set(k, v);
  }
  return {
    id: map.get("ID") ?? "unknown",
    version_id: map.get("VERSION_ID") ?? "unknown",
    pretty_name: map.get("PRETTY_NAME") ?? "unknown",
  };
}

function readPackageSet(): { count: number; sha: string } {
  // v1 only knows dpkg. When we add Fedora/Alpine, switch on os_release.id
  // and add rpm -qa / apk info parsers here. The selector treats an empty
  // sha as "no signal" and falls back to the 24h daily floor — so a non-dpkg
  // host will simply scan once a day, which is the same effective cadence
  // Trivy's DB updates on anyway.
  const r = spawnSync(
    "bash",
    ["-c", "command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package} ${Version}\\n' | LC_ALL=C sort"],
    { encoding: "utf8" },
  );
  if (r.status !== 0 || !r.stdout) return { count: 0, sha: "" };
  const lines = r.stdout.split("\n").filter((l) => l.length > 0);
  if (lines.length === 0) return { count: 0, sha: "" };
  const sha = createHash("sha256").update(lines.join("\n")).digest("hex");
  return { count: lines.length, sha };
}
