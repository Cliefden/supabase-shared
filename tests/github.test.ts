import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { HttpError } from "../src/http.ts";
import { rateLimiter } from "../src/ratelimit.ts";
import {
  createIssue,
  formatIssueBody,
  formatIssueTitle,
  githubAppAuth,
  GitHubError,
  githubHttpError,
  issueLabels,
  type IssueReport,
  maxRequestBytes,
  parseIssueApps,
  pkcs8FromPkcs1,
  reportIssue,
  resolveIssueApp,
  rsaPkcs8FromPem,
  staticToken,
  validateIssueReport,
} from "../src/github.ts";

const quiet = async <T>(fn: () => Promise<T> | T): Promise<T> => {
  const origErr = console.error;
  const origLog = console.log;
  console.error = () => {};
  console.log = () => {};
  try {
    return await fn();
  } finally {
    console.error = origErr;
    console.log = origLog;
  }
};

const apps = parseIssueApps(JSON.stringify({
  otta: { repo: "Cliefden/Otta", bundleIds: ["com.crawik.otta"] },
  vivum: { repo: "Cliefden/Vivum", labels: ["tester-report", "needs-triage"], assignees: ["scw"] },
}));

function sampleReport(overrides: Partial<IssueReport> = {}): IssueReport {
  return {
    schema: 1,
    kind: "bug",
    title: "Map crashes | sometimes",
    body: "Tapped the coverage layer.\n\nIt went black.",
    reporter: "erik@example.com",
    reporterId: "11111111-2222-3333-4444-555555555555",
    createdAt: "2026-10-27T00:00:00Z",
    context: {
      bundleIdentifier: "com.crawik.otta",
      appVersion: "2.2.1",
      build: "57",
      channel: "testFlight",
      systemName: "iOS",
      systemVersion: "27.1.0",
      deviceModel: "iPhone17,1",
      locale: "sv_SE",
      timeZone: "Europe/Stockholm",
      isLowPowerModeEnabled: false,
    },
    extra: { plan: "pro" },
    log: "12:00:00.000 E [sync] failed\n```\nnot a fence",
    attachments: [],
    ...overrides,
  };
}

const sampleJson = (overrides: Record<string, unknown> = {}) => ({ ...sampleReport(), ...overrides });

// ---------------------------------------------------------------- app map

Deno.test("parseIssueApps: validates shape", () => {
  assertEquals(parseIssueApps(undefined), {});
  assertEquals(apps.otta.repo, "Cliefden/Otta");
  assertEquals(apps.vivum.labels, ["tester-report", "needs-triage"]);
  assertThrows(() => parseIssueApps("nope"), Error, "valid JSON");
  assertThrows(() => parseIssueApps('{"x":{"repo":"no-slash"}}'), Error, "owner/name");
  assertThrows(() => parseIssueApps('{"bad key!":{"repo":"a/b"}}'), Error, "invalid");
  assertThrows(() => parseIssueApps('{"x":{"repo":"a/b","labels":"from-app"}}'), Error, "string array");
});

Deno.test("resolveIssueApp: unknown_app / bundle_mismatch", () => {
  assertEquals(resolveIssueApp(apps, "otta", "com.crawik.otta").repo, "Cliefden/Otta");
  assertEquals(resolveIssueApp(apps, "vivum", "anything").repo, "Cliefden/Vivum");
  const unknown = assertThrows(() => resolveIssueApp(apps, "nope", "x"), HttpError);
  assertEquals([unknown.status, unknown.code], [401, "unknown_app"]);
  const missing = assertThrows(() => resolveIssueApp(apps, null, "x"), HttpError);
  assertEquals(missing.status, 401);
  const mismatch = assertThrows(() => resolveIssueApp(apps, "otta", "com.other"), HttpError);
  assertEquals([mismatch.status, mismatch.code], [403, "bundle_mismatch"]);
});

// ---------------------------------------------------------------- validation

Deno.test("validateIssueReport: accepts a valid report and trims", () => {
  const r = validateIssueReport(
    sampleJson({ title: "  Hi  ", reporter: " ", extra: undefined, attachments: undefined }),
  );
  assertEquals(r.title, "Hi");
  assertEquals(r.reporter, "");
  assertEquals(r.extra, {});
  assertEquals(r.attachments, []);
  assertEquals(r.context.channel, "testFlight");
});

Deno.test("validateIssueReport: rejects bad fields with the field name", () => {
  const bad = (overrides: Record<string, unknown>, field: string) => {
    const err = assertThrows(() => validateIssueReport(sampleJson(overrides)), HttpError);
    assertEquals([err.status, err.code, err.extra?.field], [400, "invalid_report", field]);
  };
  bad({ schema: 2 }, "schema");
  bad({ kind: "crash" }, "kind");
  bad({ title: "" }, "title");
  bad({ title: "x".repeat(201) }, "title");
  bad({ body: 42 }, "body");
  bad({ reporterId: "has space" }, "reporterId");
  bad({ createdAt: "yesterday" }, "createdAt");
  bad({ context: { ...sampleReport().context, channel: "beta" } }, "context.channel");
  bad({ context: { ...sampleReport().context, isLowPowerModeEnabled: "no" } }, "context.isLowPowerModeEnabled");
  bad({ context: { ...sampleReport().context, build: "" } }, "context.build");
  bad({ extra: { k: 1 } }, "extra");
  bad({ extra: Object.fromEntries(Array.from({ length: 41 }, (_, i) => [`k${i}`, "v"])) }, "extra");
  bad({ log: "x".repeat(64_001) }, "log");
  bad({ attachments: [{ name: "a.png", contentType: "image/png", data: "not base64!" }] }, "attachments[0].data");
  bad(
    { attachments: [{ name: "a.exe", contentType: "application/x-msdownload", data: "AA==" }] },
    "attachments[0].contentType",
  );
  bad({ attachments: [1, 2, 3, 4] }, "attachments");
  const err = assertThrows(() => validateIssueReport([]), HttpError);
  assertEquals(err.extra?.field, "body");
});

Deno.test("validateIssueReport: attachment size cap", () => {
  const limits = {
    ...{
      title: 200,
      body: 20_000,
      reporter: 200,
      log: 64_000,
      extraEntries: 40,
      extraValue: 500,
      attachments: 3,
      attachmentBytes: 3,
    },
  };
  const ok = validateIssueReport(
    sampleJson({ attachments: [{ name: "a.png", contentType: "image/png", data: "AAAA" }] }),
    limits,
  );
  assertEquals(ok.attachments.length, 1);
  const err = assertThrows(
    () =>
      validateIssueReport(
        sampleJson({ attachments: [{ name: "a.png", contentType: "image/png", data: "AAAAAAAA" }] }),
        limits,
      ),
    HttpError,
  );
  assertEquals(err.extra?.field, "attachments[0].data");
  assert(maxRequestBytes() > 3 * 2 * 1024 * 1024);
});

// ---------------------------------------------------------------- formatting

Deno.test("formatIssueTitle: kind prefix, single line, capped", () => {
  assertEquals(formatIssueTitle(sampleReport()), "[Bug] Map crashes | sometimes");
  assertEquals(formatIssueTitle(sampleReport({ kind: "idea", title: "a\n\nb   c" })), "[Idea] a b c");
  assertEquals(formatIssueTitle(sampleReport({ title: "x".repeat(300) })).length, 256);
});

Deno.test("formatIssueBody: description, context table, fenced log, attachments", () => {
  const body = formatIssueBody(
    sampleReport({
      attachments: [
        { name: "shot.png", contentType: "image/png", data: "AA==" },
        { name: "state.json", contentType: "application/json", data: "AA==" },
        { name: "lost.png", contentType: "image/png", data: "AA==" },
      ],
    }),
    { attachmentUrls: ["https://s/shot.png", "https://s/state.json", null] },
  );
  assertStringIncludes(body, "Tapped the coverage layer.");
  assertStringIncludes(body, "![shot.png](https://s/shot.png)");
  assertStringIncludes(body, "- [state.json](https://s/state.json)");
  assertStringIncludes(body, "- lost.png (image/png) — not stored");
  assertStringIncludes(body, "| App | com.crawik.otta 2.2.1 (57) |");
  assertStringIncludes(body, "| Channel | TestFlight |");
  assertStringIncludes(body, "| OS | iOS 27.1.0 |");
  assertStringIncludes(body, "| Reporter | erik@example.com |");
  assertStringIncludes(body, "| plan | pro |");
  // The log contains ``` so the fence must be longer than three backticks.
  assertStringIncludes(
    body,
    "<summary>Recent log</summary>\n\n````\n12:00:00.000 E [sync] failed\n```\nnot a fence\n````",
  );
  assertStringIncludes(body, "_Filed from the app by PortfolioFeedback._");

  const minimal = formatIssueBody(sampleReport({ body: "", reporter: undefined, log: undefined, extra: {} }));
  assertStringIncludes(minimal, "_No description._");
  assertStringIncludes(minimal, "| Reporter | — |");
  assert(!minimal.includes("Recent log"));
  assert(!minimal.includes("### Attachments"));
});

Deno.test("issueLabels: base + kind + channel, deduped", () => {
  assertEquals(issueLabels(apps.otta, sampleReport()), ["from-app", "kind:bug", "channel:testFlight"]);
  assertEquals(issueLabels(apps.vivum, sampleReport({ kind: "idea" })), [
    "tester-report",
    "needs-triage",
    "kind:idea",
    "channel:testFlight",
  ]);
  assertEquals(issueLabels({ repo: "a/b", labels: ["kind:bug"] }, sampleReport()), ["kind:bug", "channel:testFlight"]);
});

// ---------------------------------------------------------------- GitHub auth

async function testRsaKey() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return { pair, pkcs8 };
}

/** Pull the RSAPrivateKey OCTET STRING out of a PKCS#8 PrivateKeyInfo (test helper). */
function pkcs1FromPkcs8(pkcs8: Uint8Array): Uint8Array {
  // SEQUENCE { INTEGER 0, SEQUENCE algId, OCTET STRING key } — find the last OCTET STRING with a long-form length.
  for (let i = 0; i < pkcs8.length - 4; i++) {
    if (pkcs8[i] === 0x04 && pkcs8[i + 1] === 0x82) {
      const len = (pkcs8[i + 2] << 8) | pkcs8[i + 3];
      if (i + 4 + len === pkcs8.length) return pkcs8.slice(i + 4);
    }
  }
  throw new Error("octet string not found");
}

const pem = (label: string, der: Uint8Array) => {
  const b64 = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
};

Deno.test("rsaPkcs8FromPem: PKCS#1 is wrapped into PKCS#8 byte-for-byte; PKCS#8 and escaped PEM pass through", async () => {
  const { pkcs8 } = await testRsaKey();
  const pkcs1 = pkcs1FromPkcs8(pkcs8);
  assertEquals(pkcs8FromPkcs1(pkcs1), pkcs8);
  assertEquals(rsaPkcs8FromPem(pem("RSA PRIVATE KEY", pkcs1)), pkcs8);
  assertEquals(rsaPkcs8FromPem(pem("PRIVATE KEY", pkcs8)), pkcs8);
  assertEquals(rsaPkcs8FromPem(pem("RSA PRIVATE KEY", pkcs1).replace(/\n/g, "\\n")), pkcs8);
  // Importable.
  await crypto.subtle.importKey(
    "pkcs8",
    rsaPkcs8FromPem(pem("RSA PRIVATE KEY", pkcs1)),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );
});

Deno.test("githubAppAuth: signed app JWT → installation token, cached, refreshed near expiry", async () => {
  const { pair, pkcs8 } = await testRsaKey();
  const privateKey = pem("RSA PRIVATE KEY", pkcs1FromPkcs8(pkcs8));
  let t = Date.parse("2026-10-27T12:00:00Z");
  const seen: Request[] = [];
  let mints = 0;
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const req = new Request(input, init);
    seen.push(req);
    mints++;
    const expires = new Date(t + 60 * 60 * 1000).toISOString();
    return new Response(JSON.stringify({ token: `ghs_${mints}`, expires_at: expires }), { status: 201 });
  }) as typeof fetch;

  const auth = githubAppAuth({ appId: "12345", privateKey, installationId: "987", fetch: fakeFetch, now: () => t });
  assertEquals(await auth.token(), "ghs_1");
  assertEquals(seen[0].url, "https://api.github.com/app/installations/987/access_tokens");
  assertEquals(seen[0].method, "POST");

  // Verify the JWT with the public key.
  const jwt = seen[0].headers.get("authorization")!.replace("Bearer ", "");
  const [h, p, s] = jwt.split(".");
  const fromB64url = (v: string) =>
    Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  assertEquals(JSON.parse(new TextDecoder().decode(fromB64url(h))), { alg: "RS256", typ: "JWT" });
  const payload = JSON.parse(new TextDecoder().decode(fromB64url(p)));
  assertEquals(payload.iss, "12345");
  assertEquals(payload.iat, Math.floor(t / 1000) - 60);
  assertEquals(payload.exp - payload.iat, 600);
  assert(
    await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      pair.publicKey,
      fromB64url(s),
      new TextEncoder().encode(`${h}.${p}`),
    ),
  );

  // Cached while fresh; concurrent callers share one mint.
  t += 10 * 60 * 1000;
  const [a, b] = await Promise.all([auth.token(), auth.token()]);
  assertEquals([a, b, mints], ["ghs_1", "ghs_1", 1]);
  // Within 5 min of expiry → refresh.
  t += 46 * 60 * 1000;
  assertEquals(await auth.token(), "ghs_2");
  assertEquals(mints, 2);
});

Deno.test("githubAppAuth: non-2xx from GitHub throws GitHubError", async () => {
  const { pkcs8 } = await testRsaKey();
  const auth = githubAppAuth({
    appId: "1",
    privateKey: pem("PRIVATE KEY", pkcs8),
    installationId: "2",
    fetch: (() => Promise.resolve(new Response('{"message":"Bad credentials"}', { status: 401 }))) as typeof fetch,
  });
  const err = await assertRejects(() => auth.token(), GitHubError);
  assertEquals(err.status, 401);
  assertStringIncludes(err.message, "Bad credentials");
});

// ---------------------------------------------------------------- createIssue

Deno.test("createIssue: request shape and response mapping", async () => {
  const seen: Request[] = [];
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push(new Request(input, init));
    return new Response(JSON.stringify({ number: 42, html_url: "https://github.com/Cliefden/Otta/issues/42" }), {
      status: 201,
    });
  }) as typeof fetch;
  const created = await createIssue(
    { repo: "Cliefden/Otta", title: "[Bug] x", body: "b", labels: ["from-app"], assignees: [] },
    { auth: staticToken("ghp_x"), fetch: fakeFetch },
  );
  assertEquals(created, { number: 42, url: "https://github.com/Cliefden/Otta/issues/42" });
  assertEquals(seen[0].url, "https://api.github.com/repos/Cliefden/Otta/issues");
  assertEquals(seen[0].headers.get("authorization"), "Bearer ghp_x");
  assertEquals(seen[0].headers.get("accept"), "application/vnd.github+json");
  assertEquals(seen[0].headers.get("x-github-api-version"), "2022-11-28");
  assertEquals(await seen[0].json(), { title: "[Bug] x", body: "b", labels: ["from-app"] }); // empty assignees omitted
});

Deno.test("createIssue: errors → GitHubError; githubHttpError maps to client codes", async () => {
  const status = (code: number, body = "{}") =>
    createIssue({ repo: "a/b", title: "t", body: "b" }, {
      auth: staticToken("x"),
      fetch: (() => Promise.resolve(new Response(body, { status: code }))) as typeof fetch,
    });
  const notFound = await assertRejects(() => status(404), GitHubError);
  assertEquals(notFound.status, 404);
  const unreachable = await assertRejects(
    () =>
      createIssue({ repo: "a/b", title: "t", body: "b" }, {
        auth: staticToken("x"),
        fetch: (() => Promise.reject(new TypeError("dns"))) as typeof fetch,
      }),
    GitHubError,
  );
  assertEquals(unreachable.status, 0);
  const weird = await assertRejects(() => status(201, '{"id":1}'), GitHubError);
  assertStringIncludes(weird.message, "unexpected response shape");

  await quiet(() => {
    assertEquals(githubHttpError(notFound).status, 502);
    assertEquals(githubHttpError(notFound).code, "github_error");
    assertEquals(githubHttpError(notFound).extra, { status: 404 });
    assertEquals(githubHttpError(unreachable).code, "github_unreachable");
    assertEquals(githubHttpError(new GitHubError(403, "API rate limit exceeded")).code, "github_rate_limited");
  });
});

// ---------------------------------------------------------------- reportIssue pipeline

function post(body: unknown, headers: Record<string, string> = {}) {
  return new Request("https://x/functions/v1/report-issue", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-App-Key": "otta", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function githubStub(seen: Request[] = []) {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const req = new Request(input, init);
    seen.push(req);
    return new Response(JSON.stringify({ number: 7, html_url: "https://github.com/Cliefden/Otta/issues/7" }), {
      status: 201,
    });
  }) as typeof fetch;
}

Deno.test("reportIssue: happy path files the issue and answers 201", async () => {
  const seen: Request[] = [];
  const stored: string[] = [];
  const res = await quiet(() =>
    reportIssue(
      post(sampleJson({ attachments: [{ name: "shot.png", contentType: "image/png", data: "iVBORw0KGgo=" }] })),
      {
        apps,
        auth: staticToken("tok"),
        fetch: githubStub(seen),
        perInstall: rateLimiter({ perMinute: 5 }),
        perApp: rateLimiter({ perMinute: 30 }),
        storeAttachment: ({ name, bytes, appKey }) => {
          stored.push(`${appKey}/${name}:${bytes.length}`);
          return Promise.resolve("https://s/shot.png");
        },
      },
    )
  );
  assertEquals(res.status, 201);
  assertEquals(await res.json(), { number: 7, url: "https://github.com/Cliefden/Otta/issues/7" });
  assertEquals(stored, ["otta/shot.png:8"]);
  const gh = await seen[0].json();
  assertEquals(gh.title, "[Bug] Map crashes | sometimes");
  assertEquals(gh.labels, ["from-app", "kind:bug", "channel:testFlight"]);
  assertStringIncludes(gh.body, "![shot.png](https://s/shot.png)");
  assertStringIncludes(gh.body, "| Channel | TestFlight |");
});

Deno.test("reportIssue: no store → attachments noted as not stored; store failure is swallowed", async () => {
  const seen: Request[] = [];
  const res = await quiet(() =>
    reportIssue(post(sampleJson({ attachments: [{ name: "a.png", contentType: "image/png", data: "AA==" }] })), {
      apps,
      auth: staticToken("tok"),
      fetch: githubStub(seen),
      perInstall: rateLimiter({ perMinute: 5 }),
      perApp: rateLimiter({ perMinute: 30 }),
      storeAttachment: null,
    })
  );
  assertEquals(res.status, 201);
  assertStringIncludes((await seen[0].json()).body, "- a.png (image/png) — not stored");

  const seen2: Request[] = [];
  const res2 = await quiet(() =>
    reportIssue(post(sampleJson({ attachments: [{ name: "a.png", contentType: "image/png", data: "AA==" }] })), {
      apps,
      auth: staticToken("tok"),
      fetch: githubStub(seen2),
      perInstall: rateLimiter({ perMinute: 5 }),
      perApp: rateLimiter({ perMinute: 30 }),
      storeAttachment: () => Promise.reject(new Error("bucket missing")),
    })
  );
  assertEquals(res2.status, 201);
  assertStringIncludes((await seen2[0].json()).body, "not stored");
});

Deno.test("reportIssue: rejections", async () => {
  const base = {
    apps,
    auth: staticToken("tok"),
    fetch: githubStub(),
    perInstall: rateLimiter({ perMinute: 5 }),
    perApp: rateLimiter({ perMinute: 30 }),
    storeAttachment: null,
  };
  const expect = async (p: Promise<Response>, status: number, code: string) => {
    const err = await assertRejects(() => p, HttpError);
    assertEquals([err.status, err.code], [status, code]);
    return err;
  };
  await expect(reportIssue(post(sampleJson(), { "X-App-Key": "nope" }), base), 401, "unknown_app");
  await expect(reportIssue(post(sampleJson(), { "X-App-Key": "" }), base), 401, "unknown_app");
  await expect(reportIssue(post("{not json"), base), 400, "invalid_json");
  await expect(reportIssue(post(sampleJson({ kind: "x" })), base), 400, "invalid_report");
  await expect(
    reportIssue(post(sampleJson({ context: { ...sampleReport().context, bundleIdentifier: "com.other" } })), base),
    403,
    "bundle_mismatch",
  );
  await expect(reportIssue(post(sampleJson()), { ...base, auth: null }), 503, "not_configured");

  // GitHub failure → 502 github_error, details not forwarded.
  const err = await quiet(() =>
    expect(
      reportIssue(post(sampleJson()), {
        ...base,
        fetch: (() => Promise.resolve(new Response('{"message":"Not Found"}', { status: 404 }))) as typeof fetch,
      }),
      502,
      "github_error",
    )
  );
  assertEquals(err.extra, { status: 404 });
});

Deno.test("reportIssue: per-install and per-app rate limits", async () => {
  let t = 0;
  const perInstall = rateLimiter({ perMinute: 2, now: () => t });
  const perApp = rateLimiter({ perMinute: 3, now: () => t });
  const opts = { apps, auth: staticToken("tok"), fetch: githubStub(), perInstall, perApp, storeAttachment: null };
  await quiet(async () => {
    assertEquals((await reportIssue(post(sampleJson()), opts)).status, 201);
    assertEquals((await reportIssue(post(sampleJson()), opts)).status, 201);
    const third = await assertRejects(() => reportIssue(post(sampleJson()), opts), HttpError);
    assertEquals([third.status, third.code], [429, "rate_limited"]);
    assertMatch(third.headers?.["Retry-After"] ?? "", /^\d+$/);
    // A different install on the same app hits the per-app cap (3rd app request counted above was the per-app check).
    const other = await assertRejects(() => reportIssue(post(sampleJson({ reporterId: "other" })), opts), HttpError);
    assertEquals(other.code, "rate_limited");
    t += 61_000;
    assertEquals((await reportIssue(post(sampleJson({ reporterId: "other" })), opts)).status, 201);
  });
});
