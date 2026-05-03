// Environment-driven server config. Fail fast on missing required values.
//
// ESM note: this package uses NodeNext, so __dirname doesn't exist. We resolve
// the repo root from import.meta.url instead.

import "dotenv/config";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required in environment`);
  return v;
}

function optional(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

// This file lives at service/src/server/config.ts (or dist/server/config.js
// after build). Either way, three levels up is the agent-security repo root.
const HERE = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(HERE, "../../../..");

export const config = {
  port: Number(optional("PORT", "3046")),
  baseUrl: required("BASE_URL"),
  pathPrefix: optional("PATH_PREFIX", "/security"),
  sessionSecret: required("SESSION_SECRET"),
  googleClientId: required("GOOGLE_CLIENT_ID"),
  googleClientSecret: required("GOOGLE_CLIENT_SECRET"),
  allowedEmails: optional("ALLOWED_EMAILS", "secorp@gmail.com")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
  findingsDir: optional("FINDINGS_DIR", resolve(REPO_ROOT, "findings")),
  uiDist: optional("UI_DIST", resolve(REPO_ROOT, "ui/dist")),
  // Sessions and the bearer-token store live alongside this file's package
  // by default. TOKENS_FILE override exists so the CLI and the server can be
  // pointed at the same scratch file in tests.
  sessionsDir: optional("SESSIONS_DIR", resolve(REPO_ROOT, "service/.sessions")),
  tokensFile: optional("TOKENS_FILE", resolve(REPO_ROOT, "service/api-tokens.json")),
};

export type Config = typeof config;

export function googleCallbackUrl(c: Config = config): string {
  return `${c.baseUrl}${c.pathPrefix}/auth/google/callback`;
}
