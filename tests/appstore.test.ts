// Port of Contrarian/supabase/tests/appstore-edge (which runs inside the
// edge-runtime container) to `deno test`. Fixtures are real Apple-signed App
// Store Server Notification TEST payloads for com.crawik.contria (one
// Sandbox, one Production). Note: Deno CLI is not the edge runtime — before
// trusting a runtime upgrade, also run Contrarian's in-container harness.

import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import * as x509 from "npm:@peculiar/x509@1";
import { CompactSign } from "npm:jose@5";
import {
  AppleJWSError,
  createAppStoreVerifier,
  statusFromTransaction,
  verificationReason,
} from "../src/appstore/mod.ts";

const CONTRIA = { bundleIds: ["com.crawik.contria"], appAppleId: 6785219877 };
const verifier = createAppStoreVerifier(CONTRIA);

const fixture = async (name: string) =>
  (await Deno.readTextFile(new URL(`./fixtures/appstore/${name}`, import.meta.url))).trim();
const sandbox = await fixture("sandbox.jws");
const production = await fixture("production.jws");

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const enc = (obj: unknown) => b64url(new TextEncoder().encode(JSON.stringify(obj)));
const dec = (part: string) =>
  JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - part.length % 4) % 4)));
const der = (c: x509.X509Certificate) => btoa(String.fromCharCode(...new Uint8Array(c.rawData)));

const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
const genKeys = () => crypto.subtle.generateKey(alg, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

/** An attacker-built chain that mimics Apple's (same subjects + OIDs), signed by its own root. */
async function forgedChain() {
  const rootKeys = await genKeys();
  const interKeys = await genKeys();
  const leafKeys = await genKeys();
  const notBefore = new Date(Date.now() - 86_400_000);
  const notAfter = new Date(Date.now() + 86_400_000 * 365);
  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Apple Root CA - G3, OU=Apple Certification Authority, O=Apple Inc., C=US",
    notBefore,
    notAfter,
    keys: rootKeys,
    signingAlgorithm: alg,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
  });
  const inter = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    issuer: root.subject,
    subject: "CN=Apple Worldwide Developer Relations Certification Authority, OU=G6, O=Apple Inc., C=US",
    notBefore,
    notAfter,
    publicKey: interKeys.publicKey,
    signingKey: rootKeys.privateKey,
    signingAlgorithm: alg,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.Extension("1.2.840.113635.100.6.2.1", false, new Uint8Array([5, 0])),
    ],
  });
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: "03",
    issuer: inter.subject,
    subject:
      "CN=Prod ECC Mac App Store and iTunes Store Receipt Signing, OU=Apple Worldwide Developer Relations, O=Apple Inc., C=US",
    notBefore,
    notAfter,
    publicKey: leafKeys.publicKey,
    signingKey: interKeys.privateKey,
    signingAlgorithm: alg,
    extensions: [new x509.Extension("1.2.840.113635.100.6.11.1", false, new Uint8Array([5, 0]))],
  });
  return { x5c: [der(leaf), der(inter), der(root)], leafKey: leafKeys.privateKey };
}

async function sign(header: Record<string, unknown>, payload: unknown, key: CryptoKey) {
  return await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ ...header, alg: "ES256" })
    .sign(key);
}

async function outcome(jws: string, v = verifier) {
  try {
    const { payload, environment } = await v.verifyNotification(jws);
    return `ok:${environment}:${payload.notificationType}`;
  } catch (err) {
    return `reject:${verificationReason(err)}`;
  }
}

const [sh, sp, ss] = sandbox.split(".");
const realHeader = dec(sh);
const realPayload = dec(sp);
const evilPayload = { ...realPayload, notificationType: "SUBSCRIBED" };

// ── the original Contrarian cases ───────────────────────────────────────────

Deno.test("real sandbox TEST verifies", async () => {
  assertEquals(await outcome(sandbox), "ok:Sandbox:TEST");
});

Deno.test("real production TEST verifies", async () => {
  assertEquals(await outcome(production), "ok:Production:TEST");
});

Deno.test("tampered payload, original signature", async () => {
  assertEquals(await outcome(`${sh}.${enc(evilPayload)}.${ss}`), "reject:signature_invalid");
});

Deno.test("Apple's x5c header, attacker's signature", async () => {
  assertEquals(
    await outcome(await sign(realHeader, evilPayload, (await genKeys()).privateKey)),
    "reject:signature_invalid",
  );
});

Deno.test("attacker-built chain mimicking Apple", async () => {
  const { x5c, leafKey } = await forgedChain();
  assertEquals(await outcome(await sign({ x5c }, evilPayload, leafKey)), "reject:untrusted_root");
});

Deno.test("alg confusion (HS256 header)", async () => {
  assertEquals(await outcome(`${enc({ ...realHeader, alg: "HS256" })}.${sp}.${ss}`), "reject:unexpected_alg");
});

Deno.test("alg none", async () => {
  assertEquals(await outcome(`${enc({ alg: "none" })}.${sp}.`), "reject:unexpected_alg");
});

Deno.test("missing x5c", async () => {
  assertEquals(await outcome(`${enc({ alg: "ES256" })}.${sp}.${ss}`), "reject:bad_x5c");
});

Deno.test("garbage", async () => {
  assertEquals(await outcome("a.b.c"), "reject:malformed_jws");
});

// ── parameterization (new) ──────────────────────────────────────────────────

Deno.test("bundle id not in the allowlist is rejected", async () => {
  const other = createAppStoreVerifier({ bundleIds: ["com.example.other"], appAppleId: 6785219877 });
  assertEquals(await outcome(sandbox, other), "reject:invalid_bundle_id");
  assertEquals(await outcome(production, other), "reject:invalid_bundle_id");
});

Deno.test("multiple bundle ids: any listed id passes", async () => {
  const multi = createAppStoreVerifier({
    bundleIds: ["com.example.mac", "com.crawik.contria"],
    appAppleId: 6785219877,
  });
  assertEquals(await outcome(sandbox, multi), "ok:Sandbox:TEST");
});

Deno.test("allowSandbox: false rejects Sandbox, still accepts Production", async () => {
  const prodOnly = createAppStoreVerifier({ ...CONTRIA, allowSandbox: false });
  assertEquals(await outcome(sandbox, prodOnly), "reject:sandbox_not_allowed");
  assertEquals(await outcome(production, prodOnly), "ok:Production:TEST");
});

Deno.test("Production needs the matching appAppleId", async () => {
  const wrong = createAppStoreVerifier({ bundleIds: CONTRIA.bundleIds, appAppleId: 1 });
  assertEquals(await outcome(production, wrong), "reject:invalid_app_apple_id");
  const missing = createAppStoreVerifier({ bundleIds: CONTRIA.bundleIds });
  assertEquals(await outcome(production, missing), "reject:app_apple_id_required");
  // Sandbox may omit it.
  assertEquals(await outcome(sandbox, missing), "ok:Sandbox:TEST");
});

Deno.test("verifyTransaction rejects a notification-shaped payload (no bundleId at top level)", async () => {
  await assertRejects(() => verifier.verifyTransaction(sandbox), AppleJWSError, "invalid_bundle_id");
});

Deno.test("empty bundleIds throws at construction", () => {
  let threw = false;
  try {
    createAppStoreVerifier({ bundleIds: [" "] });
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

// ── statusFromTransaction ───────────────────────────────────────────────────

Deno.test("statusFromTransaction", () => {
  const now = Date.parse("2026-10-27T12:00:00Z");
  const day = 86_400_000;
  assertEquals(statusFromTransaction({ expiresDate: now + day }, undefined, now).status, "active");
  assertEquals(statusFromTransaction({ expiresDate: now - day }, undefined, now).status, "expired");
  assertEquals(
    statusFromTransaction({ expiresDate: now - day }, { gracePeriodExpiresDate: now + day }, now),
    { status: "grace", periodEnd: new Date(now + day).toISOString() },
  );
  assertEquals(
    statusFromTransaction({ expiresDate: now + day, revocationDate: now - 1000 }, undefined, now),
    { status: "expired", periodEnd: new Date(now - 1000).toISOString() },
  );
  // Non-expiring (lifetime unlock): active until revoked.
  assertEquals(statusFromTransaction({}, undefined, now), { status: "active", periodEnd: null });
});
