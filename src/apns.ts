// APNs sender for Deno: provider JWT (ES256) signed with WebCrypto, delivered
// with fetch (Deno's fetch negotiates HTTP/2 via ALPN, which APNs requires).
// Port of Celiador daemon/src/push/apns.ts (Node http2 + node:crypto) with
// Ariman's ExpiredProviderToken retry and alert options.
//
// Env:
//   APNS_KEY_ID   the .p8 key's Key ID
//   APNS_TEAM_ID  Apple Developer team id
//   APNS_KEY      the .p8 contents (PKCS#8 PEM; literal "\n" escapes and a bare
//                 base64 body are accepted). APNS_PRIVATE_KEY is read as a fallback.
//   APNS_TOPIC    the app's bundle id
// Push is a no-op ({status: 0, reason: "not_configured"}) when unset.

export type ApnsEnvironment = "production" | "sandbox" | string;

export interface ApnsConfig {
  keyId: string;
  teamId: string;
  /** PKCS#8 PEM (or base64 body) of the .p8 key. */
  key: string;
  topic: string;
  /** Injectable for tests. */
  fetch?: typeof fetch;
  /** Injectable for tests. */
  now?: () => number;
}

export interface SendResult {
  status: number;
  reason?: string;
  apnsId?: string;
}

export interface ApnsClient {
  providerToken(force?: boolean): Promise<string>;
  sendAlert(device: ApnsDevice, alert: ApnsAlert): Promise<SendResult>;
  sendLiveActivity(activity: ApnsDevice, opts: LiveActivityOptions): Promise<SendResult>;
  /** Low-level: POST an arbitrary payload with arbitrary apns-* headers. */
  send(device: ApnsDevice, headers: Record<string, string>, payload: unknown): Promise<SendResult>;
}

export interface ApnsDevice {
  token: string;
  /** "production" → api.push.apple.com; anything else → sandbox (debug builds register sandbox tokens). */
  env: ApnsEnvironment;
}

export interface ApnsAlert {
  title: string;
  body: string;
  subtitle?: string;
  /** Extra top-level payload keys for the app (ids, never PII). */
  data?: Record<string, unknown>;
  threadId?: string;
  /** Collapses repeated notices on the device (≤ 64 bytes). */
  collapseId?: string;
  sound?: string | null;
  badge?: number;
  /** Seconds from now after which APNs stops trying (default: APNs' own). */
  expiresInSec?: number;
  priority?: 5 | 10;
}

export interface LiveActivityOptions {
  event: "update" | "end";
  contentState: Record<string, unknown>;
  dismissImmediately?: boolean;
  /** Unix seconds. */
  staleDate?: number;
  alert?: { title: string; body: string };
  priority?: 5 | 10;
}

export const REQUEST_TIMEOUT_MS = 10_000;
// Apple rejects tokens older than 60 min (ExpiredProviderToken) and throttles
// refreshes more often than every 20 min (TooManyProviderTokenUpdates).
export const JWT_TTL_MS = 50 * 60 * 1000;

export function hostFor(env: ApnsEnvironment | undefined): string {
  return env === "production" ? "api.push.apple.com" : "api.sandbox.push.apple.com";
}

/** APNs device / Live Activity push tokens are hex (32 bytes today). */
export function isValidDeviceToken(token: unknown): token is string {
  return typeof token === "string" && /^[0-9a-fA-F]{64,200}$/.test(token);
}

/**
 * APNs says this token will never work again — prune it. (DeviceTokenNotForTopic
 * is deliberately excluded: it usually means a misconfigured APNS_TOPIC, and
 * pruning on it would wipe every token.)
 */
export function isDeadToken(result: SendResult): boolean {
  return result.status === 410 || result.reason === "BadDeviceToken" || result.reason === "Unregistered";
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const b64urlJson = (v: unknown) => b64url(new TextEncoder().encode(JSON.stringify(v)));

/** PKCS#8 DER bytes from a PEM / escaped PEM / bare base64 body. */
export function pkcs8FromPem(raw: string) {
  const body = raw
    .replace(/\\n/g, "\n")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "")
    .replace(/-----END [A-Z ]*PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

/** An APNs client bound to one key/topic. Most callers use the env-based sendAlert/sendLiveActivity. */
export function createApnsClient(cfg: ApnsConfig): ApnsClient {
  const now = cfg.now ?? Date.now;
  const doFetch = cfg.fetch ?? fetch;
  let keyPromise: Promise<CryptoKey> | null = null;
  let cached: { jwt: string; at: number } | null = null;

  function signingKey(): Promise<CryptoKey> {
    if (!keyPromise) {
      const p = (async () =>
        await crypto.subtle.importKey(
          "pkcs8",
          pkcs8FromPem(cfg.key),
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["sign"],
        ))();
      // A bad key shouldn't be cached forever (env could be fixed + isolate reused).
      p.catch(() => {
        if (keyPromise === p) keyPromise = null;
      });
      keyPromise = p;
    }
    return keyPromise;
  }

  async function providerToken(force = false): Promise<string> {
    const t = now();
    if (!force && cached && t - cached.at < JWT_TTL_MS) return cached.jwt;
    const input = `${b64urlJson({ alg: "ES256", kid: cfg.keyId })}.${
      b64urlJson({ iss: cfg.teamId, iat: Math.floor(t / 1000) })
    }`;
    // WebCrypto ECDSA emits raw r||s (IEEE P1363), which JWS ES256 expects — not DER.
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      await signingKey(),
      new TextEncoder().encode(input),
    );
    const jwt = `${input}.${b64url(new Uint8Array(sig))}`;
    cached = { jwt, at: t };
    return jwt;
  }

  async function postOnce(
    device: ApnsDevice,
    headers: Record<string, string>,
    body: string,
    jwt: string,
  ): Promise<SendResult> {
    try {
      const res = await doFetch(`https://${hostFor(device.env)}/3/device/${device.token}`, {
        method: "POST",
        headers: { authorization: `bearer ${jwt}`, "content-type": "application/json", ...headers },
        body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const text = await res.text().catch(() => "");
      let reason: string | undefined;
      try {
        reason = text ? JSON.parse(text).reason : undefined;
      } catch {
        reason = text.slice(0, 100) || undefined;
      }
      return { status: res.status, reason, apnsId: res.headers.get("apns-id") ?? undefined };
    } catch (err) {
      const timeout = err instanceof DOMException && err.name === "TimeoutError";
      return { status: 0, reason: timeout ? "Timeout" : String(err) };
    }
  }

  async function send(device: ApnsDevice, headers: Record<string, string>, payload: unknown): Promise<SendResult> {
    // Defense in depth: never let a token rewrite the request path.
    if (!isValidDeviceToken(device.token)) return { status: 0, reason: "BadDeviceToken" };
    let jwt: string;
    try {
      jwt = await providerToken();
    } catch (err) {
      console.error("[apns] provider token signing failed:", err instanceof Error ? err.message : err);
      return { status: 0, reason: "InvalidProviderKey" };
    }
    const body = JSON.stringify(payload);
    let r = await postOnce(device, headers, body, jwt);
    if (r.status === 403 && r.reason === "ExpiredProviderToken") {
      r = await postOnce(device, headers, body, await providerToken(true));
    }
    if (r.status !== 200 && !isDeadToken(r)) console.error("[apns] send failed", r.status, r.reason ?? "");
    return r;
  }

  return {
    providerToken,
    send,
    sendAlert(device, alert) {
      const headers: Record<string, string> = {
        "apns-push-type": "alert",
        "apns-topic": cfg.topic,
        "apns-priority": String(alert.priority ?? 10),
      };
      if (alert.collapseId) headers["apns-collapse-id"] = alert.collapseId.slice(0, 64);
      if (alert.expiresInSec) {
        headers["apns-expiration"] = String(Math.floor(now() / 1000) + alert.expiresInSec);
      }
      const aps: Record<string, unknown> = {
        alert: { title: alert.title, body: alert.body, ...(alert.subtitle ? { subtitle: alert.subtitle } : {}) },
      };
      if (alert.sound !== null) aps.sound = alert.sound ?? "default";
      if (alert.badge !== undefined) aps.badge = alert.badge;
      if (alert.threadId) aps["thread-id"] = alert.threadId;
      return send(device, headers, { ...(alert.data ?? {}), aps });
    },
    sendLiveActivity(activity, opts) {
      const ts = Math.floor(now() / 1000);
      const aps: Record<string, unknown> = { timestamp: ts, event: opts.event, "content-state": opts.contentState };
      if (opts.event === "end" && opts.dismissImmediately) aps["dismissal-date"] = ts;
      if (opts.staleDate) aps["stale-date"] = opts.staleDate;
      if (opts.alert) aps.alert = opts.alert;
      return send(activity, {
        "apns-push-type": "liveactivity",
        "apns-topic": `${cfg.topic}.push-type.liveactivity`,
        "apns-priority": String(opts.priority ?? 10),
      }, { aps });
    },
  };
}

// ── env-based default client ────────────────────────────────────────────────

let _client: ApnsClient | null | undefined;

function envClient(): ApnsClient | null {
  if (_client !== undefined) return _client;
  const keyId = Deno.env.get("APNS_KEY_ID")?.trim();
  const teamId = Deno.env.get("APNS_TEAM_ID")?.trim();
  const key = (Deno.env.get("APNS_KEY") ?? Deno.env.get("APNS_PRIVATE_KEY"))?.trim();
  const topic = Deno.env.get("APNS_TOPIC")?.trim();
  _client = keyId && teamId && key && topic ? createApnsClient({ keyId, teamId, key, topic }) : null;
  return _client;
}

/** True when APNS_KEY_ID / APNS_TEAM_ID / APNS_KEY / APNS_TOPIC are all set. */
export function apnsConfigured(): boolean {
  return envClient() !== null;
}

const NOT_CONFIGURED: SendResult = { status: 0, reason: "not_configured" };

/** Alert push via the env-configured client. Never throws. */
export function sendAlert(device: ApnsDevice, alert: ApnsAlert): Promise<SendResult> {
  const c = envClient();
  return c ? c.sendAlert(device, alert) : Promise.resolve(NOT_CONFIGURED);
}

/** Live Activity update/end via the env-configured client. Never throws. */
export function sendLiveActivity(activity: ApnsDevice, opts: LiveActivityOptions): Promise<SendResult> {
  const c = envClient();
  return c ? c.sendLiveActivity(activity, opts) : Promise.resolve(NOT_CONFIGURED);
}
