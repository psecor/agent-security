// Small git helpers. Kept minimal — the LOC selector in milestone 3 will
// extend this with diff-since-sha logic.

import { spawnSync } from "node:child_process";

function git(args: string[], cwd: string): { code: number; stdout: string; stderr: string } {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  return {
    code: r.status ?? -1,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
  };
}

export function getHeadSha(projectPath: string): string {
  const r = git(["rev-parse", "--short", "HEAD"], projectPath);
  if (r.code !== 0) {
    throw new Error(`git rev-parse failed in ${projectPath}: ${r.stderr.trim()}`);
  }
  return r.stdout.trim();
}

export function isGitRepo(projectPath: string): boolean {
  const r = git(["rev-parse", "--git-dir"], projectPath);
  return r.code === 0;
}
