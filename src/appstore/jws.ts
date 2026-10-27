// Apple JWS verification on WebCrypto only (ported from Contrarian's
// _shared/apple-jws.ts, where it is live and verified against real Apple
// sandbox + production notifications).
//
// Why not @apple/app-store-server-library: the Supabase edge runtime (Deno
// 2.1, edge-runtime v1.71–v1.77) does not implement node:crypto's
// X509Certificate.verify/toString, and jsonwebtoken rejects the P-256 key
// there. The library therefore throws on EVERY genuine Apple JWS — Contrarian
// shipped broken that way, and Stokked forwards to Next.js because of it.
//
// This performs the same checks the library does with online checks off:
//   1. Header: alg ES256, x5c = [leaf, intermediate, root].
//   2. The intermediate is signed by one of the vendored Apple roots (the x5c
//      root is ignored — trust comes only from roots.ts), is a CA, and
//      carries Apple's intermediate OID; the leaf is signed by the
//      intermediate and carries Apple's leaf OID.
//   3. Every certificate in the chain is valid at the payload's signedDate.
//   4. The JWS signature verifies against the leaf's P-256 key.
// Bundle / environment / app id checks live in verifier.ts.

import * as x509 from "npm:@peculiar/x509@1";
import { compactVerify, decodeProtectedHeader } from "npm:jose@5";
import { appleRootCertificates } from "./roots.ts";

const LEAF_OID = "1.2.840.113635.100.6.11.1";
const INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";

export class AppleJWSError extends Error {
  constructor(public reason: string) {
    super(reason);
    this.name = "AppleJWSError";
  }
}

// A signature check that throws (e.g. a forged cert whose algorithm doesn't
// match the claimed issuer's key) counts as "not signed by this issuer".
async function signedBy(c: x509.X509Certificate, issuer: x509.X509Certificate): Promise<boolean> {
  try {
    return await c.verify({ publicKey: issuer.publicKey, signatureOnly: true });
  } catch {
    return false;
  }
}

let _roots: x509.X509Certificate[] | null = null;
function roots(): x509.X509Certificate[] {
  _roots ??= appleRootCertificates().map((b) => new x509.X509Certificate(b));
  return _roots;
}

function cert(b64: unknown): x509.X509Certificate {
  if (typeof b64 !== "string") throw new AppleJWSError("x5c_entry_not_string");
  try {
    return new x509.X509Certificate(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  } catch {
    throw new AppleJWSError("x5c_unparseable");
  }
}

/** Verify an Apple-signed JWS and return its decoded payload. Throws AppleJWSError. */
export async function verifyAppleJWS<T = Record<string, unknown>>(jws: string): Promise<T> {
  let header;
  try {
    header = decodeProtectedHeader(jws);
  } catch {
    throw new AppleJWSError("malformed_jws");
  }
  if (header.alg !== "ES256") throw new AppleJWSError("unexpected_alg");
  if (!Array.isArray(header.x5c) || header.x5c.length !== 3) throw new AppleJWSError("bad_x5c");

  const leaf = cert(header.x5c[0]);
  const intermediate = cert(header.x5c[1]);

  let root: x509.X509Certificate | undefined;
  for (const r of roots()) {
    if (r.subject !== intermediate.issuer) continue;
    if (await signedBy(intermediate, r)) {
      root = r;
      break;
    }
  }
  if (!root) throw new AppleJWSError("untrusted_root");

  if (leaf.issuer !== intermediate.subject) throw new AppleJWSError("leaf_issuer_mismatch");
  if (!(await signedBy(leaf, intermediate))) {
    throw new AppleJWSError("leaf_signature_invalid");
  }
  if (!intermediate.getExtension(x509.BasicConstraintsExtension)?.ca) {
    throw new AppleJWSError("intermediate_not_ca");
  }
  if (!leaf.getExtension(LEAF_OID)) throw new AppleJWSError("leaf_oid_missing");
  if (!intermediate.getExtension(INTERMEDIATE_OID)) throw new AppleJWSError("intermediate_oid_missing");

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "spki",
      leaf.publicKey.rawData,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new AppleJWSError("leaf_key_not_p256");
  }

  let payloadBytes: Uint8Array;
  try {
    ({ payload: payloadBytes } = await compactVerify(jws, key, { algorithms: ["ES256"] }));
  } catch {
    throw new AppleJWSError("signature_invalid");
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    throw new AppleJWSError("payload_not_json");
  }

  // Validity at signing time (what the library does without online checks), so
  // a redelivered notification still verifies after a leaf rotation.
  const signedDate = typeof payload.signedDate === "number" ? new Date(payload.signedDate) : new Date();
  for (const c of [leaf, intermediate, root]) {
    if (c.notBefore > signedDate || c.notAfter < signedDate) {
      throw new AppleJWSError("cert_not_valid_at_signed_date");
    }
  }

  return payload as T;
}

/** Log-friendly reason for a verification failure (never the JWS itself). */
export function verificationReason(err: unknown): string {
  if (err instanceof AppleJWSError) return err.reason;
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}
