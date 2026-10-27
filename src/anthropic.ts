// Anthropic Messages API proxy helpers (the server holds the key; clients
// never do). Generalizes Contrarian contria-engine's postMessages (retries),
// Stokked rapid-processor's env + model allowlist + upstream status mapping,
// and Carpe Vitem analyze-food's direct call.
//
// Env:
//   ANTHROPIC_API_KEY ?? AI_API_KEY   the key (AI_API_KEY = legacy name)
//   ANTHROPIC_BASE_URL                default https://api.anthropic.com/v1
//   ANTHROPIC_VERSION                 default 2023-06-01
//   AI_DEFAULT_MODEL                  default claude-opus-5-5
//   AI_ALLOWED_MODELS ?? ALLOWED_MODELS  comma list; default = just the default model

import { HttpError } from "./http.ts";

export const DEFAULT_MODEL = "claude-opus-5-5";

export interface AnthropicConfig {
  apiKey: string;
  baseUrl: string;
  version: string;
  defaultModel: string;
  allowedModels: string[];
}

/** Parse a comma-separated model allowlist; empty → just the default model. */
export function parseAllowedModels(raw: string | null | undefined, defaultModel: string): string[] {
  const list = (raw ?? "").split(",").map((m) => m.trim()).filter(Boolean);
  return list.length ? list : [defaultModel];
}

/** Read the config from env (call per request or cache — it's cheap). */
export function anthropicConfig(): AnthropicConfig {
  const e = (k: string) => Deno.env.get(k)?.trim() || undefined;
  const defaultModel = e("AI_DEFAULT_MODEL") ?? DEFAULT_MODEL;
  return {
    apiKey: e("ANTHROPIC_API_KEY") ?? e("AI_API_KEY") ?? "",
    baseUrl: (e("ANTHROPIC_BASE_URL") ?? "https://api.anthropic.com/v1").replace(/\/+$/, ""),
    version: e("ANTHROPIC_VERSION") ?? "2023-06-01",
    defaultModel,
    allowedModels: parseAllowedModels(e("AI_ALLOWED_MODELS") ?? e("ALLOWED_MODELS"), defaultModel),
  };
}

/**
 * The client's requested model if allowlisted, else the default. Unlisted
 * models fall back silently: pricier models multiply cost under a flat price.
 */
export function pickModel(
  requested: unknown,
  cfg: Pick<AnthropicConfig, "defaultModel" | "allowedModels"> = anthropicConfig(),
): string {
  return typeof requested === "string" && cfg.allowedModels.includes(requested) ? requested : cfg.defaultModel;
}

/** A system prompt as one cached text block (stable prefix → prompt caching). */
export function cachedSystem(
  text: string,
): Array<{ type: "text"; text: string; cache_control: { type: "ephemeral" } }> {
  return [{ type: "text", text, cache_control: { type: "ephemeral" } }];
}

export class AnthropicError extends Error {
  constructor(public reason: "not_configured" | "unreachable" | "timeout", message?: string) {
    super(message ?? reason);
    this.name = "AnthropicError";
  }
}

export interface PostMessagesOptions {
  /** Total attempts (default 3). */
  retries?: number;
  /** Backoff base: delay = base * 2^(attempt-1), capped, or the server's retry-after (default 500ms). */
  baseDelayMs?: number;
  maxDelayMs?: number;
  /** Per-attempt timeout (default 200s — under typical client timeouts). */
  timeoutMs?: number;
  /** Log label prefix (default "anthropic"). */
  label?: string;
  /** Override config (default: anthropicConfig()). */
  config?: AnthropicConfig;
  /** Extra headers (e.g. anthropic-beta). */
  headers?: Record<string, string>;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function isRetryable(status: number): boolean {
  return status === 429 || status === 529 || status >= 500;
}

/**
 * POST /v1/messages with retries on connection failures, 429, 5xx and 529
 * (overloaded). Nothing should be persisted before the response, so the call
 * is safe to repeat. Returns the final Response — 2xx, a non-retryable 4xx,
 * or the last retryable error once attempts run out (map it with
 * `upstreamError`). Throws AnthropicError when unconfigured or when every
 * attempt failed to connect / timed out.
 */
export async function postMessages(body: unknown, opts: PostMessagesOptions = {}): Promise<Response> {
  const cfg = opts.config ?? anthropicConfig();
  if (!cfg.apiKey) throw new AnthropicError("not_configured", "ANTHROPIC_API_KEY / AI_API_KEY is not set");
  const attempts = Math.max(1, opts.retries ?? 3);
  const base = opts.baseDelayMs ?? 500;
  const maxDelay = opts.maxDelayMs ?? 8_000;
  const label = opts.label ?? "anthropic";
  const doFetch = opts.fetch ?? fetch;
  const payload = JSON.stringify(body);

  let lastErr: unknown = null;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let res: Response | null = null;
    try {
      res = await doFetch(`${cfg.baseUrl}/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": cfg.apiKey,
          "anthropic-version": cfg.version,
          ...(opts.headers ?? {}),
        },
        body: payload,
        signal: AbortSignal.timeout(opts.timeoutMs ?? 200_000),
      });
    } catch (err) {
      lastErr = err;
      console.error(`${label}_unreachable`, attempt, String(err));
    }

    if (res && !isRetryable(res.status)) return res;
    if (res && attempt === attempts) return res;

    let delay = Math.min(maxDelay, base * 2 ** (attempt - 1));
    if (res) {
      const retryAfter = Number(res.headers.get("retry-after"));
      if (Number.isFinite(retryAfter) && retryAfter > 0) delay = Math.min(maxDelay, retryAfter * 1000);
      console.error(`${label}_error`, attempt, res.status, (await res.text().catch(() => "")).slice(0, 500));
    }
    if (attempt < attempts) await sleep(delay);
  }
  const timedOut = lastErr instanceof DOMException && lastErr.name === "TimeoutError";
  throw new AnthropicError(timedOut ? "timeout" : "unreachable", String(lastErr));
}

/**
 * Map a failed upstream response to the HttpError clients already
 * distinguish (Stokked's mapping): 429 → 429 `ai_rate_limited` (with
 * Retry-After), 529 → 503 `ai_overloaded`, everything else → 502 `upstream_error`.
 * The upstream body is never forwarded.
 */
export function upstreamError(res: Response): HttpError {
  const retryAfter = res.headers.get("retry-after") ?? "30";
  if (res.status === 429) return new HttpError(429, "ai_rate_limited", undefined, { "Retry-After": retryAfter });
  if (res.status === 529) return new HttpError(503, "ai_overloaded", undefined, { "Retry-After": retryAfter });
  return new HttpError(502, "upstream_error");
}

/** Map an AnthropicError to an HttpError (500 ai_not_configured / 504 / 502). */
export function anthropicHttpError(err: AnthropicError): HttpError {
  if (err.reason === "not_configured") return new HttpError(500, "ai_not_configured");
  if (err.reason === "timeout") return new HttpError(504, "upstream_timeout");
  return new HttpError(502, "upstream_unreachable");
}

/** Concatenate the text blocks of a Messages response. */
export function responseText(result: { content?: Array<{ type: string; text?: string }> }): string {
  return (result.content ?? []).filter((b) => b.type === "text" && b.text).map((b) => b.text).join("");
}
