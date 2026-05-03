// Bearer-token store for machine clients (e.g. Jira pollers).
//
// Tokens are stored hashed (sha256) at rest. The plaintext is only ever
// returned at mint time — we have no way to recover a token, only to revoke
// and re-issue. File format is a JSON object keyed by token name:
//
//   { "jira": { "name": "jira", "hash": "<hex>", "created": "<iso>" }, ... }
//
// Single-writer assumption: the CLI mints/revokes; the server only reads.
// We re-read on every verify so CLI changes take effect without a restart.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname } from "node:path";

export interface TokenRecord {
  name: string;
  hash: string;
  created: string;
}

export interface TokenStoreFile {
  tokens: Record<string, TokenRecord>;
}

const TOKEN_PREFIX = "ags_";

export interface TokenStore {
  list(): Promise<TokenRecord[]>;
  create(name: string): Promise<{ name: string; token: string; record: TokenRecord }>;
  revoke(name: string): Promise<boolean>;
  verify(presentedToken: string): Promise<TokenRecord | null>;
}

export function createTokenStore(filePath: string): TokenStore {
  async function read(): Promise<TokenStoreFile> {
    try {
      const raw = await fs.readFile(filePath, "utf8");
      const parsed = JSON.parse(raw) as TokenStoreFile;
      if (!parsed.tokens) return { tokens: {} };
      return parsed;
    } catch (err: unknown) {
      if (isENOENT(err)) return { tokens: {} };
      throw err;
    }
  }

  async function write(data: TokenStoreFile): Promise<void> {
    await fs.mkdir(dirname(filePath), { recursive: true });
    // Restrict to user — these are credential hashes; file mode 0600.
    await fs.writeFile(filePath, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  }

  return {
    async list(): Promise<TokenRecord[]> {
      const data = await read();
      return Object.values(data.tokens).sort((a, b) => a.name.localeCompare(b.name));
    },

    async create(name: string): Promise<{ name: string; token: string; record: TokenRecord }> {
      if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(name)) {
        throw new Error(`invalid token name: must match /^[a-z0-9][a-z0-9_-]{0,63}$/i`);
      }
      const data = await read();
      if (data.tokens[name]) {
        throw new Error(`token "${name}" already exists; revoke it first`);
      }
      const secret = randomBytes(32).toString("hex");
      const token = `${TOKEN_PREFIX}${secret}`;
      const record: TokenRecord = {
        name,
        hash: hashToken(token),
        created: new Date().toISOString(),
      };
      data.tokens[name] = record;
      await write(data);
      return { name, token, record };
    },

    async revoke(name: string): Promise<boolean> {
      const data = await read();
      if (!data.tokens[name]) return false;
      delete data.tokens[name];
      await write(data);
      return true;
    },

    async verify(presentedToken: string): Promise<TokenRecord | null> {
      if (!presentedToken || !presentedToken.startsWith(TOKEN_PREFIX)) return null;
      const presentedHash = hashToken(presentedToken);
      const data = await read();
      // Constant-time compare against every stored hash to avoid leaking
      // which name is closest to the input via timing.
      let match: TokenRecord | null = null;
      for (const rec of Object.values(data.tokens)) {
        if (constantTimeEqualHex(rec.hash, presentedHash)) {
          match = rec;
        }
      }
      return match;
    },
  };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

function isENOENT(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "ENOENT";
}
