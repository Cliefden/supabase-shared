import { assertEquals, assertMatch } from "jsr:@std/assert@1";
import { createApnsClient, hostFor, isDeadToken, isValidDeviceToken, JWT_TTL_MS, pkcs8FromPem } from "../src/apns.ts";

const fromB64url = (s: string) =>
  Uint8Array.from(
    atob(s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - s.length % 4) % 4)),
    (c) => c.charCodeAt(0),
  );

async function generatedP8(): Promise<{ pem: string; publicKey: CryptoKey }> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const b64 = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, "$1\n");
  return { pem: `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`, publicKey: kp.publicKey };
}

const TOKEN = "a".repeat(64);

Deno.test("provider JWT: ES256 header/claims, raw 64-byte signature verifies", async () => {
  const { pem, publicKey } = await generatedP8();
  const now = Date.parse("2026-10-27T10:00:00Z");
  const client = createApnsClient({
    keyId: "KEY1234567",
    teamId: "TEAM123456",
    key: pem,
    topic: "com.example.app",
    now: () => now,
  });
  const jwt = await client.providerToken();
  const [h, p, s] = jwt.split(".");
  assertEquals(JSON.parse(new TextDecoder().decode(fromB64url(h))), { alg: "ES256", kid: "KEY1234567" });
  assertEquals(JSON.parse(new TextDecoder().decode(fromB64url(p))), { iss: "TEAM123456", iat: now / 1000 });
  const sig = fromB64url(s);
  assertEquals(sig.length, 64); // IEEE P1363 r||s, not DER
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    sig,
    new TextEncoder().encode(`${h}.${p}`),
  );
  assertEquals(ok, true);
});

Deno.test("provider JWT: cached for 50 min, then re-minted", async () => {
  const { pem } = await generatedP8();
  let t = Date.parse("2026-10-27T10:00:00Z");
  const client = createApnsClient({ keyId: "K", teamId: "T", key: pem, topic: "x", now: () => t });
  const first = await client.providerToken();
  t += JWT_TTL_MS - 1000;
  assertEquals(await client.providerToken(), first);
  t += 2000;
  const second = await client.providerToken();
  assertEquals(second === first, false);
});

Deno.test("pkcs8FromPem accepts escaped newlines and bare base64", async () => {
  const { pem } = await generatedP8();
  const escaped = pem.replace(/\n/g, "\\n");
  const bare = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  assertEquals(pkcs8FromPem(escaped), pkcs8FromPem(pem));
  assertEquals(pkcs8FromPem(bare), pkcs8FromPem(pem));
});

type Captured = { url: string; headers: Headers; body: Record<string, unknown> };

function stubFetch(responses: Array<{ status: number; body?: string }>, captured: Captured[]): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    captured.push({
      url: String(input),
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body)),
    });
    const r = responses.shift() ?? { status: 200 };
    return new Response(r.body ?? "", { status: r.status, headers: { "apns-id": "id-1" } });
  }) as typeof fetch;
}

Deno.test("sendAlert: host per env, headers, payload", async () => {
  const { pem } = await generatedP8();
  const captured: Captured[] = [];
  const client = createApnsClient({
    keyId: "K",
    teamId: "T",
    key: pem,
    topic: "com.example.app",
    fetch: stubFetch([], captured),
  });

  const r = await client.sendAlert({ token: TOKEN, env: "production" }, {
    title: "Hi",
    body: "There",
    data: { event_id: "e1" },
    threadId: "t",
    collapseId: "c".repeat(80),
  });
  assertEquals(r, { status: 200, reason: undefined, apnsId: "id-1" });
  const c = captured[0];
  assertEquals(c.url, `https://api.push.apple.com/3/device/${TOKEN}`);
  assertEquals(c.headers.get("apns-push-type"), "alert");
  assertEquals(c.headers.get("apns-topic"), "com.example.app");
  assertEquals(c.headers.get("apns-collapse-id")?.length, 64);
  assertMatch(c.headers.get("authorization")!, /^bearer [\w-]+\.[\w-]+\.[\w-]+$/);
  assertEquals(c.body, {
    event_id: "e1",
    aps: { alert: { title: "Hi", body: "There" }, sound: "default", "thread-id": "t" },
  });

  await client.sendAlert({ token: TOKEN, env: "development" }, { title: "a", body: "b" });
  assertEquals(captured[1].url.startsWith("https://api.sandbox.push.apple.com/"), true);
});

Deno.test("sendLiveActivity: topic suffix + content-state", async () => {
  const { pem } = await generatedP8();
  const captured: Captured[] = [];
  const now = Date.parse("2026-10-27T10:00:00Z");
  const client = createApnsClient({
    keyId: "K",
    teamId: "T",
    key: pem,
    topic: "ai.celiador.companion",
    fetch: stubFetch([], captured),
    now: () => now,
  });
  await client.sendLiveActivity({ token: TOKEN, env: "sandbox" }, {
    event: "end",
    contentState: { step: 3 },
    dismissImmediately: true,
  });
  const c = captured[0];
  assertEquals(c.headers.get("apns-push-type"), "liveactivity");
  assertEquals(c.headers.get("apns-topic"), "ai.celiador.companion.push-type.liveactivity");
  assertEquals(c.body, {
    aps: { timestamp: now / 1000, event: "end", "content-state": { step: 3 }, "dismissal-date": now / 1000 },
  });
});

Deno.test("ExpiredProviderToken: one retry with a fresh JWT", async () => {
  const { pem } = await generatedP8();
  const captured: Captured[] = [];
  let t = 0;
  const client = createApnsClient({
    keyId: "K",
    teamId: "T",
    key: pem,
    topic: "x",
    now: () => (t += 1000),
    fetch: stubFetch([{ status: 403, body: '{"reason":"ExpiredProviderToken"}' }, { status: 200 }], captured),
  });
  const r = await client.sendAlert({ token: TOKEN, env: "production" }, { title: "a", body: "b" });
  assertEquals(r.status, 200);
  assertEquals(captured.length, 2);
  assertEquals(captured[0].headers.get("authorization") === captured[1].headers.get("authorization"), false);
});

Deno.test("dead tokens and invalid tokens", async () => {
  assertEquals(isDeadToken({ status: 410 }), true);
  assertEquals(isDeadToken({ status: 400, reason: "BadDeviceToken" }), true);
  assertEquals(isDeadToken({ status: 400, reason: "Unregistered" }), true);
  assertEquals(isDeadToken({ status: 400, reason: "DeviceTokenNotForTopic" }), false);
  assertEquals(isDeadToken({ status: 500 }), false);
  assertEquals(isValidDeviceToken(TOKEN), true);
  assertEquals(isValidDeviceToken("../../evil"), false);
  assertEquals(hostFor("production"), "api.push.apple.com");
  assertEquals(hostFor(undefined), "api.sandbox.push.apple.com");

  const { pem } = await generatedP8();
  const captured: Captured[] = [];
  const client = createApnsClient({ keyId: "K", teamId: "T", key: pem, topic: "x", fetch: stubFetch([], captured) });
  const r = await client.sendAlert({ token: "../../3/device/x", env: "production" }, { title: "a", body: "b" });
  assertEquals(r, { status: 0, reason: "BadDeviceToken" });
  assertEquals(captured.length, 0); // never reached the network
});

Deno.test("malformed key → InvalidProviderKey, no throw", async () => {
  const orig = console.error;
  console.error = () => {};
  try {
    const client = createApnsClient({
      keyId: "K",
      teamId: "T",
      key: "not a key",
      topic: "x",
      fetch: stubFetch([], []),
    });
    const r = await client.sendAlert({ token: TOKEN, env: "production" }, { title: "a", body: "b" });
    assertEquals(r, { status: 0, reason: "InvalidProviderKey" });
  } finally {
    console.error = orig;
  }
});
