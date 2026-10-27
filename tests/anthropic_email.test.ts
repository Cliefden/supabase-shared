import { assertEquals } from "jsr:@std/assert@1";
import {
  type AnthropicConfig,
  AnthropicError,
  parseAllowedModels,
  pickModel,
  postMessages,
  upstreamError,
} from "../src/anthropic.ts";
import { sendEmail } from "../src/email.ts";

const cfg: AnthropicConfig = {
  apiKey: "sk-ant-test",
  baseUrl: "https://api.example/v1",
  version: "2023-06-01",
  defaultModel: "claude-opus-5-5",
  allowedModels: ["claude-opus-5-5", "claude-sonnet-5-5"],
};

const quiet = async <T>(fn: () => Promise<T>): Promise<T> => {
  const orig = console.error;
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.error = orig;
  }
};

function scripted(steps: Array<number | "throw">, seen: Request[] = []): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push(new Request(input, init));
    const s = steps.shift() ?? 200;
    if (s === "throw") throw new TypeError("connection reset");
    return new Response(JSON.stringify({ status: s }), { status: s });
  }) as typeof fetch;
}

Deno.test("parseAllowedModels / pickModel", () => {
  assertEquals(parseAllowedModels(" a, b ,,", "d"), ["a", "b"]);
  assertEquals(parseAllowedModels(undefined, "d"), ["d"]);
  assertEquals(pickModel("claude-sonnet-5-5", cfg), "claude-sonnet-5-5");
  assertEquals(pickModel("claude-fancy-9", cfg), "claude-opus-5-5");
  assertEquals(pickModel(42, cfg), "claude-opus-5-5");
});

Deno.test("postMessages: headers + body, no retry on 200", async () => {
  const seen: Request[] = [];
  const res = await postMessages({ model: "m" }, { config: cfg, fetch: scripted([200], seen), baseDelayMs: 1 });
  assertEquals(res.status, 200);
  assertEquals(seen.length, 1);
  assertEquals(seen[0].url, "https://api.example/v1/messages");
  assertEquals(seen[0].headers.get("x-api-key"), "sk-ant-test");
  assertEquals(seen[0].headers.get("anthropic-version"), "2023-06-01");
  assertEquals(await seen[0].json(), { model: "m" });
});

Deno.test("postMessages: retries 529 / 5xx / 429 / connection errors, then succeeds", async () => {
  const seen: Request[] = [];
  const res = await quiet(() =>
    postMessages({}, { config: cfg, fetch: scripted([529, "throw", 200], seen), retries: 3, baseDelayMs: 1 })
  );
  assertEquals([res.status, seen.length], [200, 3]);
});

Deno.test("postMessages: 4xx is returned immediately", async () => {
  const seen: Request[] = [];
  const res = await postMessages({}, { config: cfg, fetch: scripted([400], seen), baseDelayMs: 1 });
  assertEquals([res.status, seen.length], [400, 1]);
});

Deno.test("postMessages: exhausted retryable status returns the last response", async () => {
  const seen: Request[] = [];
  const res = await quiet(() =>
    postMessages({}, { config: cfg, fetch: scripted([429, 429, 429], seen), baseDelayMs: 1 })
  );
  assertEquals([res.status, seen.length], [429, 3]);
  const e = upstreamError(res);
  assertEquals([e.status, e.code], [429, "ai_rate_limited"]);
  assertEquals(upstreamError(new Response("", { status: 529 })).status, 503);
  assertEquals(upstreamError(new Response("", { status: 401 })).code, "upstream_error");
});

Deno.test("postMessages: all connection failures → AnthropicError unreachable; no key → not_configured", async () => {
  const err = await quiet(() =>
    postMessages({}, { config: cfg, fetch: scripted(["throw", "throw"]), retries: 2, baseDelayMs: 1 }).catch((e) => e)
  );
  assertEquals(err instanceof AnthropicError && err.reason, "unreachable");
  const nk = await postMessages({}, { config: { ...cfg, apiKey: "" } }).catch((e) => e);
  assertEquals(nk instanceof AnthropicError && nk.reason, "not_configured");
});

Deno.test("sendEmail: Resend request shape + idempotency key", async () => {
  Deno.env.set("RESEND_API_KEY", "re_test");
  Deno.env.set("EMAIL_FROM", "Vivum <noreply@example.com>");
  const seen: Request[] = [];
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push(new Request(input, init));
    return new Response('{"id":"msg_1"}', { status: 200 });
  }) as typeof fetch;
  const r = await sendEmail({
    to: "a@example.com",
    subject: "S",
    text: "T",
    html: "<p>T</p>",
    idempotencyKey: "k1",
    fetch: fakeFetch,
  });
  assertEquals(r, { ok: true, id: "msg_1" });
  assertEquals(seen[0].url, "https://api.resend.com/emails");
  assertEquals(seen[0].headers.get("authorization"), "Bearer re_test");
  assertEquals(seen[0].headers.get("idempotency-key"), "k1");
  assertEquals(await seen[0].json(), {
    from: "Vivum <noreply@example.com>",
    to: ["a@example.com"],
    subject: "S",
    text: "T",
    html: "<p>T</p>",
  });

  const fail = await quiet(() =>
    sendEmail({
      to: "a@example.com",
      subject: "S",
      text: "T",
      fetch: (() => Promise.resolve(new Response("bad", { status: 422 }))) as typeof fetch,
    })
  );
  assertEquals(fail, { ok: false, status: 422, error: "bad" });

  Deno.env.delete("RESEND_API_KEY");
  assertEquals(await sendEmail({ to: "a@example.com", subject: "S", text: "T" }), {
    ok: false,
    status: 0,
    error: "not_configured",
  });
});
