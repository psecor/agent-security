// JSON API for humans (UI) and machines (Jira / ticketing scripts).
//
// All routes mount at /api under PATH_PREFIX. /api/health is intentionally
// open for liveness probes; everything else flows through ensureAuth.

import express from "express";
import { ensureAdmin, makeEnsureAuth } from "./auth.js";
import type { DataLayer } from "./data.js";
import type { TokenStore } from "./tokens.js";
import type { Severity } from "../scanner/types.js";

const VALID_SEVERITIES: ReadonlySet<Severity> = new Set([
  "critical", "high", "medium", "low", "info",
]);

export function apiRoutes(deps: { data: DataLayer; tokens: TokenStore }): express.Router {
  const r = express.Router();
  const ensureAuth = makeEnsureAuth(deps.tokens);

  // Health is the only unauthenticated endpoint — register before the gate.
  r.get("/api/health", (_req, res) => res.json({ ok: true }));

  r.use("/api", ensureAuth);

  r.get("/api/projects", async (_req, res, next) => {
    try {
      res.json(await deps.data.projects());
    } catch (e) {
      next(e);
    }
  });

  r.get("/api/projects/:name", async (req, res, next) => {
    try {
      const scan = await deps.data.project(req.params.name);
      if (!scan) {
        res.status(404).json({ error: "not_found" });
        return;
      }
      res.json(scan);
    } catch (e) {
      next(e);
    }
  });

  r.get("/api/findings", async (req, res, next) => {
    try {
      const severity = parseList(req.query.severity).filter((s): s is Severity =>
        VALID_SEVERITIES.has(s as Severity),
      );
      const category = parseList(req.query.category);
      const since = typeof req.query.since === "string" ? req.query.since : undefined;
      const limitRaw = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : NaN;
      const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 2000) : undefined;

      const result = await deps.data.findings({
        severity: severity.length ? severity : undefined,
        category: category.length ? category : undefined,
        since,
        limit,
      });
      res.json(result);
    } catch (e) {
      next(e);
    }
  });

  // Token CRUD: admin (session-cookie users) only.
  r.get("/api/tokens", ensureAdmin, async (_req, res, next) => {
    try {
      const list = await deps.tokens.list();
      // Never return hashes.
      res.json({ tokens: list.map((t) => ({ name: t.name, created: t.created })) });
    } catch (e) {
      next(e);
    }
  });

  r.post("/api/tokens", ensureAdmin, async (req, res, next) => {
    try {
      const name = typeof req.body?.name === "string" ? req.body.name : "";
      const created = await deps.tokens.create(name);
      res.status(201).json({
        name: created.name,
        token: created.token,
        created: created.record.created,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      res.status(400).json({ error: msg });
    }
  });

  r.delete("/api/tokens/:name", ensureAdmin, async (req, res, next) => {
    try {
      const name = req.params.name;
      if (!name) {
        res.status(400).json({ error: "name_required" });
        return;
      }
      const ok = await deps.tokens.revoke(name);
      if (!ok) {
        res.status(404).json({ error: "not_found" });
        return;
      }
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  return r;
}

// Express parses repeated query params as string[]; collapse to a flat
// string[] regardless of whether the caller used ?severity=high,low or
// ?severity=high&severity=low.
function parseList(raw: unknown): string[] {
  if (raw == null) return [];
  const items = Array.isArray(raw) ? raw : [raw];
  const out: string[] = [];
  for (const item of items) {
    if (typeof item !== "string") continue;
    for (const part of item.split(",")) {
      const t = part.trim();
      if (t) out.push(t);
    }
  }
  return out;
}
