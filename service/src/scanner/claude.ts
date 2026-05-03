// Claude triage caller. Single non-streaming call per project: send all raw
// findings + their source slices in one request, get back a parsed JSON object.
//
// Why streaming: large projects can produce dozens of findings, each with up
// to 600 chars of rationale; a single response can run 20-60k tokens. Streaming
// keeps us under the 10-minute request timeout without us having to manage it.
//
// Why prompt caching: the system prompt is ~4k tokens of frozen rubric. Caching
// it pays back from the second project in a daily multi-project sweep.

import Anthropic from "@anthropic-ai/sdk";
import { betaZodOutputFormat } from "@anthropic-ai/sdk/helpers/beta/zod";
import type { RawFinding } from "./tools/types.js";
import { SourceReader } from "./source.js";
import { SYSTEM_PROMPT, TriageOutputSchema, buildUserMessage, type TriageOutput } from "./prompt.js";

export const TRIAGE_MODEL = "claude-opus-4-7";

export interface TriageUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens: number;
  cache_creation_input_tokens: number;
}

export interface ClaudeTriageResult {
  parsed: TriageOutput;
  usage: TriageUsage;
}

export interface ClaudeTriageOptions {
  client: Anthropic;
  projectKey: string;
  projectPath: string;
  raws: RawFinding[];
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void;
  // Hard ceiling on response length. Findings rarely come close to this; the
  // default sizes for ~150 findings worst-case.
  maxTokens?: number;
}

export async function triageWithClaude(opts: ClaudeTriageOptions): Promise<ClaudeTriageResult> {
  const { client, projectKey, projectPath, raws, log } = opts;
  const reader = new SourceReader(projectPath);
  const userText = buildUserMessage({ projectKey, raws, reader });

  log("debug", `claude: model=${TRIAGE_MODEL}, raws=${raws.length}, prompt_chars=${userText.length}`);

  // betaZodOutputFormat() returns the JSON-schema descriptor + a `.parse()` we
  // call on the response text. The wire location moved from top-level
  // `output_format` (deprecated, returns 400) to `output_config.format`, but
  // the SDK types and auto-parser haven't caught up yet — so we send the
  // schema in the new place and parse the response ourselves.
  const outputFormat = betaZodOutputFormat(TriageOutputSchema);

  const stream = client.beta.messages.stream({
    model: TRIAGE_MODEL,
    max_tokens: opts.maxTokens ?? 64000,
    system: [
      { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } },
    ],
    messages: [{ role: "user", content: userText }],
    // Adaptive thinking is the only on-mode for Opus 4.7; the SDK's published
    // BetaThinkingConfigParam union (enabled | disabled) is one release behind
    // and rejects "adaptive" at type-check time. The wire format is correct.
    thinking: { type: "adaptive" } as unknown as Anthropic.Beta.BetaThinkingConfigParam,
    output_config: {
      effort: "high",
      format: { type: outputFormat.type, schema: outputFormat.schema },
    } as unknown as Anthropic.Beta.BetaOutputConfig,
  });

  const final = await stream.finalMessage();
  const usage: TriageUsage = {
    input_tokens: final.usage.input_tokens,
    output_tokens: final.usage.output_tokens,
    cache_read_input_tokens: final.usage.cache_read_input_tokens ?? 0,
    cache_creation_input_tokens: final.usage.cache_creation_input_tokens ?? 0,
  };
  log("info",
    `claude: in=${usage.input_tokens} (cache_read=${usage.cache_read_input_tokens}, ` +
    `cache_create=${usage.cache_creation_input_tokens}) out=${usage.output_tokens}`,
  );

  const text = final.content
    .filter((b): b is Anthropic.Beta.BetaTextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");
  if (text.length === 0) {
    throw new Error(`claude triage: empty text response. stop_reason=${final.stop_reason}`);
  }
  let parsed: TriageOutput;
  try {
    parsed = outputFormat.parse(text);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`claude triage: failed to parse response (${msg}). stop_reason=${final.stop_reason}, text:\n${text}`);
  }
  return { parsed, usage };
}

export function makeAnthropicClient(): Anthropic {
  // Reads ANTHROPIC_API_KEY from the environment by default.
  return new Anthropic();
}
