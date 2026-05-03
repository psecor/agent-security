// Source-file slicer used by the triage layer.
//
// Two callers, two reasons:
//   1. ID derivation (spec/findings-schema.md → "Stable IDs"): the line at
//      `line` plus 2 above and 2 below, trimmed and joined with \n. Encodes
//      enough surrounding context that an unrelated edit above the finding
//      doesn't shift the id.
//   2. Claude triage prompt: a wider window (±20 by default) so Claude can
//      assess the actual code, not just the rule message.
//
// File reads are cached for the lifetime of one scan to avoid re-reading the
// same file once per finding.

import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface SourceSlice {
  start_line: number;       // 1-based
  end_line: number;         // 1-based, inclusive
  lines: string[];          // raw, no trim
}

export class SourceReader {
  private readonly cache = new Map<string, string[] | null>();
  constructor(private readonly projectPath: string) {}

  // `file` is project-relative; returns null if the file can't be read
  // (deleted, binary, outside project, etc.).
  private getLines(file: string): string[] | null {
    const cached = this.cache.get(file);
    if (cached !== undefined) return cached;
    let lines: string[] | null = null;
    try {
      const text = readFileSync(join(this.projectPath, file), "utf8");
      lines = text.split("\n");
    } catch {
      lines = null;
    }
    this.cache.set(file, lines);
    return lines;
  }

  slice(file: string, line: number, before: number, after: number): SourceSlice | null {
    const all = this.getLines(file);
    if (!all) return null;
    const start = Math.max(1, line - before);
    const end = Math.min(all.length, line + after);
    return {
      start_line: start,
      end_line: end,
      lines: all.slice(start - 1, end),
    };
  }
}

// The id-stability context per spec/findings-schema.md.
// Reads ±2 lines around `line`, trims each line, drops blank lines, joins with
// \n. Falls back to "file:line" when the source is unreadable so the id is at
// least project-stable.
export function normalizedLineContext(reader: SourceReader, file: string, line: number): string {
  const slice = reader.slice(file, line, 2, 2);
  if (!slice) return `${file}:${line}`;
  const trimmed = slice.lines.map((l) => l.trim()).filter((l) => l.length > 0);
  if (trimmed.length === 0) return `${file}:${line}`;
  return trimmed.join("\n");
}
