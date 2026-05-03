// Server entry. Express + session + Passport + static UI hosting.
//
// Path layout (everything under PATH_PREFIX, default /security):
//   /security/                     UI (React SPA, history fallback) — TBD
//   /security/auth/google          OAuth start
//   /security/auth/google/callback OAuth callback
//   /security/auth/logout          POST to log out
//   /security/api/*                JSON API (cookie OR bearer)
//   /security/api/health           open liveness probe

import express from "express";
import session from "express-session";
import FileStoreFactory from "session-file-store";
import passport from "passport";
import { promises as fs } from "node:fs";
import path from "node:path";
import { config } from "./config.js";
import { authRoutes } from "./auth.js";
import { apiRoutes } from "./api.js";
import { createDataLayer } from "./data.js";
import { createTokenStore } from "./tokens.js";

async function main(): Promise<void> {
  const FileStore = FileStoreFactory(session);
  const app = express();

  // Behind Apache reverse proxy.
  app.set("trust proxy", 1);

  app.use(express.json({ limit: "1mb" }));

  // Bare-root convenience for localhost dev. Registered before the session +
  // passport stack so it doesn't require a session in scope.
  app.get("/", (_req, res) => res.redirect(config.pathPrefix + "/"));

  app.use(
    session({
      store: new FileStore({ path: config.sessionsDir, ttl: 60 * 60 * 24 * 30 /* 30d */ }),
      secret: config.sessionSecret,
      name: "agentsecurity.sid",
      resave: false,
      saveUninitialized: false,
      cookie: {
        path: config.pathPrefix,
        httpOnly: true,
        secure: config.baseUrl.startsWith("https://"),
        maxAge: 1000 * 60 * 60 * 24 * 30,
        sameSite: "lax",
      },
    }),
  );

  app.use(passport.initialize());
  app.use(passport.session());

  const data = createDataLayer({ findingsDir: config.findingsDir });
  const tokens = createTokenStore(config.tokensFile);

  const router = express.Router();
  router.use(authRoutes(config.pathPrefix));
  router.use(apiRoutes({ data, tokens }));

  // Static UI + SPA fallback. UI not built yet (milestone 5); serve a
  // placeholder so localhost-without-build doesn't hard-crash.
  router.use(express.static(config.uiDist, { index: false }));
  router.get("*", async (req, res, next) => {
    if (req.path.startsWith("/api/") || req.path.startsWith("/auth/")) return next();
    const indexHtml = path.join(config.uiDist, "index.html");
    const exists = await fs.access(indexHtml).then(() => true).catch(() => false);
    if (!exists) {
      res.status(503).type("text").send(
        `agent-security UI not built (milestone 5).\n` +
        `JSON API is live at ${config.pathPrefix}/api/.\n` +
        `Expected UI bundle at: ${indexHtml}\n`,
      );
      return;
    }
    res.sendFile(indexHtml);
  });

  app.use(config.pathPrefix, router);

  // Error handler — last.
  app.use(((err, _req, res, _next) => {
    console.error("[server] error:", err);
    res.status(500).json({ error: "internal_error" });
  }) as express.ErrorRequestHandler);

  app.listen(config.port, "127.0.0.1", () => {
    console.log(
      `[agent-security] listening on 127.0.0.1:${config.port}, mounted at ${config.pathPrefix}`,
    );
    console.log(`[agent-security] allowed emails: ${config.allowedEmails.join(", ")}`);
    console.log(`[agent-security] reading findings from: ${config.findingsDir}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
