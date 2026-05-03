// Operator CLI: token mint / list / revoke for machine clients.
//
// Usage:
//   npm run cli -- token create --name jira
//   npm run cli -- token list
//   npm run cli -- token revoke --name jira
//
// The plaintext token is shown once at create time; we only store a sha256
// hash. To rotate: revoke and re-create.

import "dotenv/config";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createTokenStore } from "../server/tokens.js";

const HERE = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(HERE, "../../../..");
const DEFAULT_TOKENS_FILE = resolve(REPO_ROOT, "service/api-tokens.json");

function usage(): string {
  return [
    "usage: cli token <create|list|revoke> [--name <name>]",
    "",
    "  token create --name <name>   mint a new bearer token (plaintext printed once)",
    "  token list                   list token names + creation timestamps",
    "  token revoke --name <name>   delete a token from the store",
    "",
    "env:",
    "  TOKENS_FILE  override the store path (default: <repo>/service/api-tokens.json)",
  ].join("\n");
}

interface TokenArgs {
  sub: "create" | "list" | "revoke";
  name?: string;
}

function parseArgs(argv: string[]): TokenArgs {
  if (argv[0] !== "token") {
    throw new Error(`unknown command: ${argv[0] ?? "(none)"}\n\n${usage()}`);
  }
  const sub = argv[1];
  if (sub !== "create" && sub !== "list" && sub !== "revoke") {
    throw new Error(`unknown subcommand: ${sub ?? "(none)"}\n\n${usage()}`);
  }
  let name: string | undefined;
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--name") {
      name = argv[++i];
    } else if (a?.startsWith("--name=")) {
      name = a.slice("--name=".length);
    } else {
      throw new Error(`unknown arg: ${a}\n\n${usage()}`);
    }
  }
  return { sub, name };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const tokensFile = process.env.TOKENS_FILE ?? DEFAULT_TOKENS_FILE;
  const tokens = createTokenStore(tokensFile);

  if (args.sub === "list") {
    const list = await tokens.list();
    if (list.length === 0) {
      process.stdout.write("(no tokens)\n");
      return;
    }
    for (const t of list) {
      process.stdout.write(`${t.name}\t${t.created}\n`);
    }
    return;
  }

  if (!args.name) {
    throw new Error(`--name is required for "${args.sub}"\n\n${usage()}`);
  }

  if (args.sub === "create") {
    const result = await tokens.create(args.name);
    process.stdout.write(
      `Token created. Save this now — it will not be shown again:\n\n  ${result.token}\n\n` +
      `Use as: Authorization: Bearer ${result.token}\n`,
    );
    return;
  }

  if (args.sub === "revoke") {
    const ok = await tokens.revoke(args.name);
    if (!ok) {
      process.stderr.write(`token "${args.name}" not found\n`);
      process.exit(1);
    }
    process.stdout.write(`revoked "${args.name}"\n`);
    return;
  }
}

main().catch((err) => {
  process.stderr.write(`cli: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
