import { assertEquals } from "jsr:@std/assert@1";
import { corsHeaders, errorJson, handle, HttpError, json, parseOrigins, preflight, readJson } from "../src/http.ts";
import { bearer, isUuid, requireUser, timingSafeEqual } from "../src/auth.ts";

const post = (body: string, headers: Record<string, string> = {}) =>
  new Request("http://x/fn", { method: "POST", body, headers });

Deno.test("corsHeaders: wildcard default", () => {
  const h = corsHeaders("https://evil.example");
  assertEquals(h["Access-Control-Allow-Origin"], "*");
  assertEquals(h["Vary"], undefined);
});

Deno.test("corsHeaders: allowlist echoes listed origins, else first entry", () => {
  const allowOrigins = parseOrigins("https://stokked.ai, https://www.stokked.ai,,");
  assertEquals(allowOrigins, ["https://stokked.ai", "https://www.stokked.ai"]);
  assertEquals(
    corsHeaders("https://www.stokked.ai", { allowOrigins })["Access-Control-Allow-Origin"],
    "https://www.stokked.ai",
  );
  assertEquals(
    corsHeaders("https://evil.example", { allowOrigins })["Access-Control-Allow-Origin"],
    "https://stokked.ai",
  );
  assertEquals(corsHeaders(null, { allowOrigins })["Vary"], "Origin");
});

Deno.test("preflight", () => {
  assertEquals(preflight(new Request("http://x", { method: "GET" })), null);
  const res = preflight(new Request("http://x", { method: "OPTIONS" }))!;
  assertEquals(res.status, 200);
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
});

Deno.test("json + errorJson", async () => {
  const r = json({ a: 1 }, 201, { headers: { "X-Test": "1" } });
  assertEquals(r.status, 201);
  assertEquals(r.headers.get("Content-Type"), "application/json");
  assertEquals(r.headers.get("X-Test"), "1");
  assertEquals(await r.json(), { a: 1 });
  const e = errorJson("nope", 418, { detail: "x" });
  assertEquals(e.status, 418);
  assertEquals(await e.json(), { error: "nope", detail: "x" });
});

Deno.test("handle: success gets CORS headers", async () => {
  const h = handle(() => json({ ok: true }));
  const res = await h(post("{}"));
  assertEquals(res.status, 200);
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
});

Deno.test("handle: OPTIONS preflight short-circuits", async () => {
  let called = false;
  const h = handle(() => {
    called = true;
    return json({});
  }, { methods: ["POST"] });
  const res = await h(new Request("http://x", { method: "OPTIONS" }));
  assertEquals(res.status, 200);
  assertEquals(called, false);
});

Deno.test("handle: method not allowed", async () => {
  const res = await handle(() => json({}), { methods: ["POST"] })(new Request("http://x"));
  assertEquals(res.status, 405);
  assertEquals(res.headers.get("Allow"), "POST");
  assertEquals(await res.json(), { error: "method_not_allowed" });
});

Deno.test("handle: HttpError maps to JSON with headers", async () => {
  const res = await handle(() => {
    throw new HttpError(429, "rate_limited", { retry: true }, { "Retry-After": "60" });
  })(post("{}"));
  assertEquals(res.status, 429);
  assertEquals(res.headers.get("Retry-After"), "60");
  assertEquals(await res.json(), { error: "rate_limited", retry: true });
});

Deno.test("handle: unknown error → 500 internal_error, no details", async () => {
  const origError = console.error;
  console.error = () => {};
  try {
    const res = await handle(() => {
      throw new Error("db password is hunter2");
    })(post("{}"));
    assertEquals(res.status, 500);
    assertEquals(await res.json(), { error: "internal_error" });
  } finally {
    console.error = origError;
  }
});

Deno.test("handle: cors:false (webhooks) adds no CORS headers", async () => {
  const res = await handle(() => json({}), { cors: false })(post("{}"));
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), null);
});

Deno.test("handle: immutable upstream Response headers still get CORS", async () => {
  const upstream = Response.json({ x: 1 }); // immutable headers in Deno
  const res = await handle(() => upstream)(post("{}"));
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
  assertEquals(await res.json(), { x: 1 });
});

Deno.test("readJson: parses, rejects bad JSON and oversize (by UTF-8 bytes)", async () => {
  assertEquals(await readJson(post('{"a":1}')), { a: 1 });
  const bad = await handle(async (req) => json(await readJson(req)))(post("{nope"));
  assertEquals(bad.status, 400);
  assertEquals(await bad.json(), { error: "invalid_json" });
  // 10 × "é" = 20 bytes > 15 even though .length is 14 with quotes.
  const big = await handle(async (req) => json(await readJson(req, { maxBytes: 15 })))(post(`"${"é".repeat(10)}"`));
  assertEquals(big.status, 413);
});

Deno.test("bearer", () => {
  const r = (v?: string) => new Request("http://x", { headers: v ? { Authorization: v } : {} });
  assertEquals(bearer(r("Bearer abc.def")), "abc.def");
  assertEquals(bearer(r("bearer   tok ")), "tok");
  assertEquals(bearer(r("Basic xyz")), null);
  assertEquals(bearer(r()), null);
});

Deno.test("requireUser: missing token → 401 before any network/env access", async () => {
  try {
    await requireUser(new Request("http://x"));
    throw new Error("should have thrown");
  } catch (err) {
    assertEquals(err instanceof HttpError && err.status, 401);
    assertEquals((err as HttpError).code, "missing_token");
  }
});

Deno.test("timingSafeEqual + isUuid", () => {
  assertEquals(timingSafeEqual("secret", "secret"), true);
  assertEquals(timingSafeEqual("secret", "secreT"), false);
  assertEquals(timingSafeEqual("secret", "secret2"), false);
  assertEquals(timingSafeEqual("", ""), false);
  assertEquals(timingSafeEqual(undefined, "x"), false);
  assertEquals(isUuid("8a6e0804-2bd0-4672-b79d-d97027f9071a"), true);
  assertEquals(isUuid("not-a-uuid"), false);
});
