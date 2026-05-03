// Git helpers used by the scanner. Two repos in play:
//
//   - The *project* being scanned: source of HEAD sha, LOC counts, and
//     diff-since-last-scan numbers used by the selector.
//   - The *agent-security* repo (where findings/ lives): target of the
//     bot commit each scan writes.

import { spawnSync } from "node:child_process";

const BOT_USER = "agent-security[bot]";
const BOT_EMAIL = "bot+agent-security@secorp.net";

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

// True when the repo has at least one commit reachable from HEAD. Unborn
// repos (`git init`'d but no commits yet) return false and are skipped by
// discovery — every per-scan path needs a HEAD sha (selector diff base,
// commit message tag, source slice resolution).
export function hasHead(projectPath: string): boolean {
  const r = git(["rev-parse", "--verify", "--quiet", "HEAD"], projectPath);
  return r.code === 0;
}

// Total tracked LOC in a project's working tree. Approximation: counts
// newlines across every file `git ls-files` reports. Binary files contribute
// their incidental newline count, which is a rounding error at the project
// scale we care about. Returns 0 on any failure rather than throwing — the
// scanner shouldn't fail because cloc-like math hiccupped.
export function getTotalLoc(projectPath: string): number {
  const r = spawnSync(
    "bash",
    ["-c", "git ls-files -z | xargs -0 cat 2>/dev/null | wc -l"],
    { cwd: projectPath, encoding: "utf8" },
  );
  if (r.status !== 0) return 0;
  return parseInt(r.stdout.trim(), 10) || 0;
}

// LOC added + deleted between `sinceSha` and HEAD on this project's working
// tree. Returns null if the sha is unreachable (force-pushed away, branch
// gone, etc.) so the selector can treat that as "needs a fresh scan."
export function getLocChangedSince(projectPath: string, sinceSha: string): number | null {
  const r = git(["diff", "--numstat", `${sinceSha}..HEAD`], projectPath);
  if (r.code !== 0) return null;
  let total = 0;
  for (const raw of r.stdout.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const added = parts[0];
    const deleted = parts[1];
    // Binary files report "-\t-\t<path>"; skip them rather than NaN.
    if (added === "-" || deleted === "-") continue;
    total += (parseInt(added ?? "0", 10) || 0) + (parseInt(deleted ?? "0", 10) || 0);
  }
  return total;
}

// Stage and commit the listed files in the agent-security repo with a bot
// identity. Cwd should be inside that repo (the findings dir works). The
// caller is expected to have just written the files; if `git add` finds no
// content change vs. HEAD, this returns false and skips the commit so we
// don't churn out empty commits.
export function commitFindingsFiles(opts: {
  repoCwd: string;
  files: string[];          // absolute paths
  message: string;
}): { committed: boolean; sha?: string } {
  const { repoCwd, files, message } = opts;
  if (files.length === 0) return { committed: false };

  const add = git(["add", "--", ...files], repoCwd);
  if (add.code !== 0) {
    throw new Error(`git add failed: ${add.stderr.trim()}`);
  }
  // `git diff --cached --quiet -- <files>` exits 0 when nothing is staged,
  // 1 when something is. We use the file list to ignore unrelated staged
  // changes that may already exist in the working tree.
  const diff = git(["diff", "--cached", "--quiet", "--", ...files], repoCwd);
  if (diff.code === 0) {
    return { committed: false };
  }

  const commit = spawnSync(
    "git",
    [
      "-c", `user.name=${BOT_USER}`,
      "-c", `user.email=${BOT_EMAIL}`,
      "commit",
      "-m", message,
      "--only",
      "--",
      ...files,
    ],
    { cwd: repoCwd, encoding: "utf8" },
  );
  if (commit.status !== 0) {
    throw new Error(`git commit failed: ${(commit.stderr || commit.stdout).trim()}`);
  }
  const sha = git(["rev-parse", "--short", "HEAD"], repoCwd).stdout.trim();
  return { committed: true, sha };
}

// True when `cwd` resolves into a git working tree. Used to skip auto-commit
// when findings live outside any repo (rare but possible via FINDINGS_DIR).
export function isInsideWorkTree(cwd: string): boolean {
  const r = git(["rev-parse", "--is-inside-work-tree"], cwd);
  return r.code === 0 && r.stdout.trim() === "true";
}
