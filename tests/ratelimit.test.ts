import { assertEquals } from "jsr:@std/assert@1";
import { type DailyCap, enforceDailyCap, rateLimiter } from "../src/ratelimit.ts";
import { HttpError } from "../src/http.ts";

Deno.test("rateLimiter: sliding window per key", () => {
  let t = 1_000_000;
  const rl = rateLimiter({ perMinute: 3, now: () => t });
  assertEquals(rl.check("u1").allowed, true);
  t += 10_000;
  assertEquals(rl.check("u1").allowed, true);
  t += 10_000;
  const third = rl.check("u1");
  assertEquals([third.allowed, third.remaining], [true, 0]);
  const denied = rl.check("u1");
  assertEquals(denied.allowed, false);
  // Oldest hit at t0 leaves the window at t0+60s; now is t0+20s → 40s.
  assertEquals(denied.retryAfterSec, 40);
  // Other keys are independent.
  assertEquals(rl.check("u2").allowed, true);
  // Sliding: after the first hit ages out, exactly one slot frees up.
  t = 1_000_000 + 60_001;
  assertEquals(rl.check("u1").allowed, true);
  assertEquals(rl.check("u1").allowed, false);
});

Deno.test("rateLimiter: denied requests don't extend the window", () => {
  let t = 0;
  const rl = rateLimiter({ limit: 1, windowMs: 1000, now: () => t });
  assertEquals(rl.check("k").allowed, true);
  for (let i = 0; i < 5; i++) {
    t += 100;
    assertEquals(rl.check("k").allowed, false);
  }
  t = 1001;
  assertEquals(rl.check("k").allowed, true);
});

Deno.test("rateLimiter: idle keys are pruned", () => {
  let t = 0;
  const rl = rateLimiter({ perMinute: 5, now: () => t });
  rl.check("a");
  rl.check("b");
  assertEquals(rl.size(), 2);
  t = 120_000;
  rl.check("c");
  assertEquals(rl.size(), 1);
});

Deno.test("rateLimiter.enforce throws 429 with Retry-After", () => {
  const rl = rateLimiter({ perMinute: 1, now: () => 0 });
  rl.enforce("k");
  try {
    rl.enforce("k");
    throw new Error("expected 429");
  } catch (err) {
    if (!(err instanceof HttpError)) throw err;
    assertEquals(err.status, 429);
    assertEquals(err.code, "rate_limited");
    assertEquals(err.headers?.["Retry-After"], "60");
  }
});

const cap = (used: number | null | Error, limit: number): DailyCap => ({
  usedToday: () => (used instanceof Error ? Promise.reject(used) : Promise.resolve(used)),
  limitFor: () => limit,
});

async function status(p: Promise<unknown>): Promise<number> {
  const orig = console.error;
  console.error = () => {};
  try {
    await p;
    return 200;
  } catch (err) {
    if (err instanceof HttpError) return err.status;
    throw err;
  } finally {
    console.error = orig;
  }
}

Deno.test("enforceDailyCap", async () => {
  assertEquals(await status(enforceDailyCap(cap(2, 3), "u")), 200); // 3rd call allowed
  assertEquals(await status(enforceDailyCap(cap(3, 3), "u")), 429); // 4th refused
  assertEquals(await status(enforceDailyCap(cap(3, 3), "u", { includesCurrent: true })), 200);
  assertEquals(await status(enforceDailyCap(cap(-1, 3), "u")), 200); // admin sentinel
  assertEquals(await status(enforceDailyCap(cap(999, -1), "u")), 200); // unlimited plan
  assertEquals(await status(enforceDailyCap(cap(null, 3), "u")), 200); // fail open
  assertEquals(await status(enforceDailyCap(cap(new Error("db"), 3), "u")), 200);
  assertEquals(await status(enforceDailyCap(cap(null, 3), "u", { failOpen: false })), 503);
});
