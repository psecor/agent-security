// Authentication: Google OAuth (humans, session cookie) + bearer token
// (machines). Both flow through ensureAuth — endpoints don't care which
// authenticator validated the request.

import express from "express";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { config, googleCallbackUrl } from "./config.js";
import type { TokenStore, TokenRecord } from "./tokens.js";

export interface SessionUser {
  email: string;
  name: string;
  picture?: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface User extends SessionUser {}
    interface Request {
      // Set by ensureAuth when a bearer token validates. Mutually exclusive
      // with req.user (the session-cookie path).
      bearer?: TokenRecord;
    }
  }
}

passport.use(
  new GoogleStrategy(
    {
      clientID: config.googleClientId,
      clientSecret: config.googleClientSecret,
      callbackURL: googleCallbackUrl(),
    },
    (_accessToken, _refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value?.toLowerCase();
      if (!email) return done(null, false);
      if (!config.allowedEmails.includes(email)) return done(null, false);
      const user: SessionUser = {
        email,
        name: profile.displayName,
        picture: profile.photos?.[0]?.value,
      };
      return done(null, user);
    },
  ),
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj: SessionUser, done) => done(null, obj));

// Authenticate by either an active session cookie OR a valid bearer token.
// Order: cookie first (cheaper, no disk read); bearer fallback.
export function makeEnsureAuth(tokens: TokenStore): express.RequestHandler {
  return async (req, res, next) => {
    if (req.isAuthenticated && req.isAuthenticated()) return next();
    const presented = extractBearer(req);
    if (presented) {
      try {
        const rec = await tokens.verify(presented);
        if (rec) {
          req.bearer = rec;
          return next();
        }
      } catch (err) {
        return next(err);
      }
    }
    res.status(401).json({ error: "unauthenticated" });
  };
}

// Admin-only: required for token CRUD over the API. Sessions only — we don't
// let a bearer token mint or revoke peer tokens.
export function ensureAdmin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  res.status(403).json({ error: "admin_required" });
}

function extractBearer(req: express.Request): string | null {
  const h = req.headers.authorization;
  if (!h) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(h);
  return m && m[1] ? m[1] : null;
}

export function authRoutes(prefix: string): express.Router {
  const r = express.Router();

  r.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] }),
  );

  r.get(
    "/auth/google/callback",
    passport.authenticate("google", {
      failureRedirect: `${prefix}/login?error=denied`,
    }),
    (_req, res) => res.redirect(`${prefix}/`),
  );

  r.post("/auth/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      req.session.destroy(() => res.json({ ok: true }));
    });
  });

  // UI-facing identity probe. Bearer clients get back which token they used.
  r.get("/api/auth/me", (req, res) => {
    if (req.isAuthenticated && req.isAuthenticated()) {
      res.json({ kind: "user", user: req.user });
    } else {
      res.status(401).json({ kind: null });
    }
  });

  return r;
}
