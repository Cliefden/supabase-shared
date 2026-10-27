// Two layers of cost guard for paid upstream calls (Anthropic etc.):
//
//  1. rateLimiter — in-memory sliding window per key (user id). Resets on cold
//     start and isn't shared across isolates: a soft guard against runaway
//     client loops, not anti-abuse. (Stokked rapid-processor's 20/min.)
//  2. DailyCap — durable per-user cap the app implements against its own
//     usage table/RPC (Contrarian engine_calls_last_24h, Stokked ai_usage),
//     enforced by enforceDailyCap.

import { HttpError } from "./http.ts";

export interface RateLimitResult {
  allowed: boolean;
  /** Requests left in the current window after this one. */
  remaining: number;
  /** Seconds until the oldest counted request leaves the window (0 when allowed). */
  retryAfterSec: number;
}

export interface RateLimiter {
  /** Record a request for `key` and say whether it is allowed. Denied requests aren't recorded. */
  check(key: string): RateLimitResult;
  /** check() that throws HttpError 429 `rate_limited` with Retry-After. */
  enforce(key: string): void;
  reset(key?: string): void;
  /** Number of tracked keys (for tests/metrics). */
  size(): number;
}

export interface RateLimiterOptions {
  perMinute?: number;
  /** Generic form: `limit` per `windowMs` (overrides perMinute). */
  limit?: number;
  windowMs?: number;
  /** Clock, injectable for tests. */
  now?: () => number;
}

export function rateLimiter(opts: RateLimiterOptions): RateLimiter {
  const limit = opts.limit ?? opts.perMinute ?? 20;
  const windowMs = opts.windowMs ?? 60_000;
  const now = opts.now ?? Date.now;
  const hits = new Map<string, number[]>();
  let lastPrune = now();

  // Drop idle keys once per window so a long-lived isolate doesn't keep an
  // entry for every user it has ever seen.
  function prune(t: number) {
    if (t - lastPrune < windowMs) return;
    lastPrune = t;
    for (const [k, list] of hits) {
      if (!list.length || list[list.length - 1] <= t - windowMs) hits.delete(k);
    }
  }

  function check(key: string): RateLimitResult {
    const t = now();
    prune(t);
    const cutoff = t - windowMs;
    const list = (hits.get(key) ?? []).filter((ts) => ts > cutoff);
    if (list.length >= limit) {
      hits.set(key, list);
      return { allowed: false, remaining: 0, retryAfterSec: Math.max(1, Math.ceil((list[0] + windowMs - t) / 1000)) };
    }
    list.push(t);
    hits.set(key, list);
    return { allowed: true, remaining: limit - list.length, retryAfterSec: 0 };
  }

  return {
    check,
    enforce(key) {
      const r = check(key);
      if (!r.allowed) {
        throw new HttpError(429, "rate_limited", undefined, { "Retry-After": String(r.retryAfterSec) });
      }
    },
    reset(key) {
      if (key === undefined) hits.clear();
      else hits.delete(key);
    },
    size: () => hits.size,
  };
}

/**
 * A durable per-user cap, implemented by the app against its own ledger.
 *
 *   const cap: DailyCap = {
 *     usedToday: async (userId) => {
 *       const { data, error } = await userClient.rpc("engine_calls_last_24h");
 *       return error ? null : data;           // null → unknown (fail open)
 *     },
 *     limitFor: (userId) => (isPlus ? 30 : 3),
 *   };
 *   await enforceDailyCap(cap, user.id);
 */
export interface DailyCap {
  /**
   * Calls used in the current window (rolling 24h or calendar day — the app
   * decides). Negative = unlimited (Contrarian's RPC returns -1 for admins).
   * null = unknown (lookup failed).
   */
  usedToday(userId: string): Promise<number | null>;
  /** The cap for this user. Negative = unlimited. */
  limitFor(userId: string): number | Promise<number>;
}

export interface EnforceDailyCapOptions {
  /** On lookup failure (null or throw): allow (default true — the cap guards cost, it shouldn't take the product down). */
  failOpen?: boolean;
  /** Count includes the current request already (e.g. a reserved usage row). Default false. */
  includesCurrent?: boolean;
  /** Error code for the 429 (default `daily_limit_exceeded`). */
  code?: string;
  retryAfterSec?: number;
}

/** Throws HttpError 429 when the user is over their cap; returns {used, limit} otherwise. */
export async function enforceDailyCap(
  cap: DailyCap,
  userId: string,
  opts: EnforceDailyCapOptions = {},
): Promise<{ used: number | null; limit: number }> {
  const failOpen = opts.failOpen ?? true;
  let used: number | null;
  try {
    used = await cap.usedToday(userId);
  } catch (err) {
    console.error("daily_cap_lookup_failed", userId, err);
    used = null;
  }
  const limit = await cap.limitFor(userId);
  if (used === null) {
    if (failOpen) return { used, limit };
    throw new HttpError(503, "usage_check_failed");
  }
  if (used < 0 || limit < 0) return { used, limit };
  const total = opts.includesCurrent ? used : used + 1;
  if (total > limit) {
    throw new HttpError(429, opts.code ?? "daily_limit_exceeded", undefined, {
      "Retry-After": String(opts.retryAfterSec ?? 3600),
    });
  }
  return { used, limit };
}
