// GitHub issue filing for the in-app reporter (PortfolioFeedback Swift package).
//
// One `report-issue` edge function serves every app: it holds the GitHub
// credential, maps the caller's app key to a repo, validates and size-caps the
// report, formats the issue, optionally stores attachments, and rate limits per
// install. The app binary never carries a GitHub token — an extracted app key
// can at most file labelled issues in that app's own repo, rate limited.
//
// Env:
//   ISSUE_APPS                   JSON: { "<appKey>": { "repo": "Cliefden/Otta",
//                                "bundleIds": ["com.crawik.otta"], "labels": ["from-app"] } }
//   GITHUB_TOKEN                 a fine-grained PAT with Issues: read/write on those repos — OR —
//   GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY + GITHUB_APP_INSTALLATION_ID
//                                a GitHub App installed on the org (preferred: not tied to a
//                                person, tokens rotate). The key may be PKCS#1 ("BEGIN RSA
//                                PRIVATE KEY", as GitHub downloads it) or PKCS#8.
//   GITHUB_API_URL               default https://api.github.com
//   ISSUE_ATTACHMENTS_BUCKET     optional storage bucket for screenshots (signed URLs, 1 year)
//   ISSUE_RATE_PER_MINUTE        per install (default 5); ISSUE_APP_RATE_PER_MINUTE per app (default 30)

import { HttpError, json, readJson } from "./http.ts";
import { type RateLimiter, rateLimiter } from "./ratelimit.ts";

// ---------------------------------------------------------------- app map

export interface IssueAppConfig {
  /** `owner/name`. */
  repo: string;
  /** When set, the report's bundle identifier must be one of these. */
  bundleIds?: string[];
  /** Base labels (default `["from-app"]`). `kind:` and `channel:` labels are added. */
  labels?: string[];
  assignees?: string[];
}

export type IssueApps = Record<string, IssueAppConfig>;

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/** Parse and validate the ISSUE_APPS JSON. Throws on a malformed map (a config error, not a request error). */
export function parseIssueApps(raw: string | undefined | null): IssueApps {
  if (!raw || !raw.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("ISSUE_APPS is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("ISSUE_APPS must be an object");
  const apps: IssueApps = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(key)) throw new Error(`ISSUE_APPS key "${key}" is invalid`);
    const cfg = value as Partial<IssueAppConfig> | null;
    if (!cfg || typeof cfg.repo !== "string" || !REPO_RE.test(cfg.repo)) {
      throw new Error(`ISSUE_APPS["${key}"].repo must be "owner/name"`);
    }
    const strings = (v: unknown, field: string): string[] | undefined => {
      if (v === undefined) return undefined;
      if (!Array.isArray(v) || !v.every((s) => typeof s === "string" && s.trim())) {
        throw new Error(`ISSUE_APPS["${key}"].${field} must be a string array`);
      }
      return v.map((s: string) => s.trim());
    };
    apps[key] = {
      repo: cfg.repo,
      bundleIds: strings(cfg.bundleIds, "bundleIds"),
      labels: strings(cfg.labels, "labels"),
      assignees: strings(cfg.assignees, "assignees"),
    };
  }
  return apps;
}

let _apps: IssueApps | null = null;

/** ISSUE_APPS from the environment, parsed once per isolate. */
export function issueAppsFromEnv(): IssueApps {
  _apps ??= parseIssueApps(Deno.env.get("ISSUE_APPS"));
  return _apps;
}

/** The app for `X-App-Key`, or 401 `unknown_app`; 403 `bundle_mismatch` when the report's bundle isn't allowed. */
export function resolveIssueApp(apps: IssueApps, appKey: string | null | undefined, bundleId: string): IssueAppConfig {
  const key = (appKey ?? "").trim();
  const app = key ? apps[key] : undefined;
  if (!app) throw new HttpError(401, "unknown_app");
  if (app.bundleIds?.length && !app.bundleIds.includes(bundleId)) throw new HttpError(403, "bundle_mismatch");
  return app;
}

// ---------------------------------------------------------------- report

export type IssueKind = "bug" | "idea" | "question";
export const ISSUE_KINDS: IssueKind[] = ["bug", "idea", "question"];
export type BuildChannel = "xcode" | "adHoc" | "testFlight" | "appStore" | "unknown";
const CHANNELS: BuildChannel[] = ["xcode", "adHoc", "testFlight", "appStore", "unknown"];

export interface IssueAttachment {
  name: string;
  contentType: string;
  /** Base64 (standard alphabet). */
  data: string;
}

export interface DeviceContext {
  bundleIdentifier: string;
  appVersion: string;
  build: string;
  channel: BuildChannel;
  systemName: string;
  systemVersion: string;
  deviceModel: string;
  locale: string;
  timeZone: string;
  isLowPowerModeEnabled: boolean;
}

/** Mirrors `IssueReport` in the Swift package (schema 1). */
export interface IssueReport {
  schema: number;
  kind: IssueKind;
  title: string;
  body: string;
  reporter?: string;
  reporterId: string;
  createdAt: string;
  context: DeviceContext;
  extra: Record<string, string>;
  log?: string;
  attachments: IssueAttachment[];
}

export interface ReportLimits {
  title: number;
  body: number;
  reporter: number;
  log: number;
  extraEntries: number;
  extraValue: number;
  attachments: number;
  /** Decoded bytes per attachment. */
  attachmentBytes: number;
}

export const DEFAULT_LIMITS: ReportLimits = {
  title: 200,
  body: 20_000,
  reporter: 200,
  log: 64_000,
  extraEntries: 40,
  extraValue: 500,
  attachments: 3,
  attachmentBytes: 2 * 1024 * 1024,
};

/** Request body cap for `readJson` given the limits (attachments as base64 + slack). */
export function maxRequestBytes(limits: ReportLimits = DEFAULT_LIMITS): number {
  return Math.ceil(limits.attachments * limits.attachmentBytes * 1.37) + limits.log + limits.body + 64 * 1024;
}

const invalid = (field: string) => new HttpError(400, "invalid_report", { field });

function str(v: unknown, field: string, max: number, opts: { required?: boolean } = {}): string | undefined {
  if (v === undefined || v === null) {
    if (opts.required) throw invalid(field);
    return undefined;
  }
  if (typeof v !== "string") throw invalid(field);
  const trimmed = v.trim();
  if (opts.required && !trimmed) throw invalid(field);
  if (trimmed.length > max) throw invalid(field);
  return trimmed;
}

/** Type-check and size-cap a parsed body. Throws 400 `invalid_report` with the offending `field`. */
export function validateIssueReport(body: unknown, limits: ReportLimits = DEFAULT_LIMITS): IssueReport {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw invalid("body");
  const b = body as Record<string, unknown>;
  if (b.schema !== 1) throw invalid("schema");
  if (!ISSUE_KINDS.includes(b.kind as IssueKind)) throw invalid("kind");

  const title = str(b.title, "title", limits.title, { required: true })!;
  const text = str(b.body, "body", limits.body) ?? "";
  const reporter = str(b.reporter, "reporter", limits.reporter);
  const reporterId = str(b.reporterId, "reporterId", 64, { required: true })!;
  if (!/^[A-Za-z0-9_-]+$/.test(reporterId)) throw invalid("reporterId");
  const createdAt = str(b.createdAt, "createdAt", 40, { required: true })!;
  if (Number.isNaN(Date.parse(createdAt))) throw invalid("createdAt");

  const c = b.context;
  if (!c || typeof c !== "object" || Array.isArray(c)) throw invalid("context");
  const ctx = c as Record<string, unknown>;
  const ctxStr = (k: string, max = 120) => str(ctx[k], `context.${k}`, max, { required: true })!;
  if (!CHANNELS.includes(ctx.channel as BuildChannel)) throw invalid("context.channel");
  if (typeof ctx.isLowPowerModeEnabled !== "boolean") throw invalid("context.isLowPowerModeEnabled");
  const context: DeviceContext = {
    bundleIdentifier: ctxStr("bundleIdentifier", 200),
    appVersion: ctxStr("appVersion", 40),
    build: ctxStr("build", 40),
    channel: ctx.channel as BuildChannel,
    systemName: ctxStr("systemName", 40),
    systemVersion: ctxStr("systemVersion", 40),
    deviceModel: ctxStr("deviceModel", 80),
    locale: ctxStr("locale", 40),
    timeZone: ctxStr("timeZone", 80),
    isLowPowerModeEnabled: ctx.isLowPowerModeEnabled,
  };

  const extra: Record<string, string> = {};
  if (b.extra !== undefined) {
    if (!b.extra || typeof b.extra !== "object" || Array.isArray(b.extra)) throw invalid("extra");
    const entries = Object.entries(b.extra as Record<string, unknown>);
    if (entries.length > limits.extraEntries) throw invalid("extra");
    for (const [k, v] of entries) {
      if (!k.trim() || k.length > 80 || typeof v !== "string" || v.length > limits.extraValue) throw invalid("extra");
      extra[k] = v;
    }
  }

  const log = str(b.log, "log", limits.log);

  const attachments: IssueAttachment[] = [];
  if (b.attachments !== undefined) {
    if (!Array.isArray(b.attachments)) throw invalid("attachments");
    if (b.attachments.length > limits.attachments) throw invalid("attachments");
    b.attachments.forEach((a, i) => {
      if (!a || typeof a !== "object") throw invalid(`attachments[${i}]`);
      const att = a as Record<string, unknown>;
      const name = str(att.name, `attachments[${i}].name`, 120, { required: true })!;
      const contentType = str(att.contentType, `attachments[${i}].contentType`, 80, { required: true })!;
      if (!/^(image\/(png|jpeg|heic|webp)|text\/plain|application\/(json|zip|octet-stream))$/.test(contentType)) {
        throw invalid(`attachments[${i}].contentType`);
      }
      if (typeof att.data !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(att.data)) {
        throw invalid(`attachments[${i}].data`);
      }
      // Decoded size ≈ 3/4 of the base64 length.
      if ((att.data.length * 3) / 4 > limits.attachmentBytes) throw invalid(`attachments[${i}].data`);
      attachments.push({ name, contentType, data: att.data });
    });
  }

  return {
    schema: 1,
    kind: b.kind as IssueKind,
    title,
    body: text,
    reporter,
    reporterId,
    createdAt,
    context,
    extra,
    log,
    attachments,
  };
}

// ---------------------------------------------------------------- formatting

const KIND_PREFIX: Record<IssueKind, string> = { bug: "Bug", idea: "Idea", question: "Question" };
const CHANNEL_LABEL: Record<BuildChannel, string> = {
  xcode: "Xcode",
  adHoc: "Ad hoc",
  testFlight: "TestFlight",
  appStore: "App Store",
  unknown: "Unknown",
};

/** `[Bug] <title>`, single line, ≤ 256 chars (GitHub's cap). */
export function formatIssueTitle(report: IssueReport): string {
  const title = report.title.replace(/\s+/g, " ").trim();
  return `[${KIND_PREFIX[report.kind]}] ${title}`.slice(0, 256);
}

/** Markdown-table cell: no pipes or newlines. */
const cell = (v: string) => v.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

/** Keep user text from closing our fenced blocks. */
function fence(text: string): string {
  let marks = "```";
  while (text.includes(marks)) marks += "`";
  return `${marks}\n${text}\n${marks}`;
}

export interface FormatBodyOptions {
  /** Public/signed URLs for attachments that were stored, by index. */
  attachmentUrls?: Array<string | null>;
}

export function formatIssueBody(report: IssueReport, opts: FormatBodyOptions = {}): string {
  const c = report.context;
  const parts: string[] = [];

  parts.push(report.body ? report.body : "_No description._");

  const urls = opts.attachmentUrls ?? [];
  if (report.attachments.length) {
    const lines = report.attachments.map((a, i) => {
      const url = urls[i];
      if (!url) return `- ${a.name} (${a.contentType}) — not stored`;
      return a.contentType.startsWith("image/") ? `![${a.name}](${url})` : `- [${a.name}](${url})`;
    });
    parts.push(`### Attachments\n\n${lines.join("\n")}`);
  }

  const rows: Array<[string, string]> = [
    ["App", `${c.bundleIdentifier} ${c.appVersion} (${c.build})`],
    ["Channel", CHANNEL_LABEL[c.channel]],
    ["OS", `${c.systemName} ${c.systemVersion}`],
    ["Device", c.deviceModel],
    ["Locale / time zone", `${c.locale} / ${c.timeZone}`],
    ["Low Power Mode", c.isLowPowerModeEnabled ? "on" : "off"],
    ["Reported", report.createdAt],
    ["Reporter", report.reporter ?? "—"],
    ["Install id", report.reporterId],
  ];
  for (const [k, v] of Object.entries(report.extra)) rows.push([k, v]);
  parts.push(
    `### Context\n\n| | |\n|---|---|\n${rows.map(([k, v]) => `| ${cell(k)} | ${cell(v)} |`).join("\n")}`,
  );

  if (report.log) {
    parts.push(`<details>\n<summary>Recent log</summary>\n\n${fence(report.log)}\n\n</details>`);
  }

  parts.push("_Filed from the app by PortfolioFeedback._");
  return parts.join("\n\n");
}

/** Base labels + `kind:` + `channel:`, deduplicated. */
export function issueLabels(app: IssueAppConfig, report: IssueReport): string[] {
  const base = app.labels ?? ["from-app"];
  return [...new Set([...base, `kind:${report.kind}`, `channel:${report.context.channel}`])];
}

// ---------------------------------------------------------------- GitHub auth

export interface GitHubAuth {
  /** A token valid for the next request. */
  token(): Promise<string>;
}

export function staticToken(token: string): GitHubAuth {
  return { token: () => Promise.resolve(token) };
}

export interface GitHubAppAuthOptions {
  appId: string;
  /** PEM: PKCS#1 ("BEGIN RSA PRIVATE KEY") or PKCS#8 ("BEGIN PRIVATE KEY"); `\n` escapes OK. */
  privateKey: string;
  installationId: string;
  apiUrl?: string;
  fetch?: typeof fetch;
  now?: () => number;
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const b64urlJson = (v: unknown) => b64url(new TextEncoder().encode(JSON.stringify(v)));

/** DER length prefix. */
function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

const RSA_ALG_ID = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];

/** Wrap a PKCS#1 RSAPrivateKey DER in a PKCS#8 PrivateKeyInfo (WebCrypto imports only PKCS#8). */
export function pkcs8FromPkcs1(pkcs1: Uint8Array): Uint8Array<ArrayBuffer> {
  const octet = [0x04, ...derLength(pkcs1.length)];
  const inner = [0x02, 0x01, 0x00, ...RSA_ALG_ID, ...octet];
  const total = inner.length + pkcs1.length;
  const out = new Uint8Array(new ArrayBuffer(1 + derLength(total).length + total));
  out.set([0x30, ...derLength(total), ...inner], 0);
  out.set(pkcs1, 1 + derLength(total).length + inner.length);
  return out;
}

/** PKCS#8 DER from a GitHub App key PEM (PKCS#1 or PKCS#8), escaped PEM, or a bare base64 body (assumed PKCS#8). */
export function rsaPkcs8FromPem(raw: string): Uint8Array<ArrayBuffer> {
  const text = raw.replace(/\\n/g, "\n");
  const isPkcs1 = /-----BEGIN RSA PRIVATE KEY-----/.test(text);
  const body = text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "")
    .replace(/-----END [A-Z ]*PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const der = decodeBase64(body);
  return isPkcs1 ? pkcs8FromPkcs1(der) : der;
}

export const GITHUB_API = "https://api.github.com";
const GITHUB_HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
/** App JWTs may live 10 min; GitHub also rejects an `iat` ahead of its clock, hence the 60 s backdate. */
const APP_JWT_TTL_SEC = 9 * 60;
/** Refresh installation tokens this long before `expires_at`. */
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

/** GitHub App auth: RS256 app JWT → installation access token, cached until shortly before expiry. */
export function githubAppAuth(opts: GitHubAppAuthOptions): GitHubAuth {
  const now = opts.now ?? Date.now;
  const doFetch = opts.fetch ?? fetch;
  const api = (opts.apiUrl ?? GITHUB_API).replace(/\/$/, "");
  let keyPromise: Promise<CryptoKey> | null = null;
  let cached: { token: string; expiresAt: number } | null = null;
  let inFlight: Promise<string> | null = null;

  function signingKey(): Promise<CryptoKey> {
    if (!keyPromise) {
      const p = crypto.subtle.importKey(
        "pkcs8",
        rsaPkcs8FromPem(opts.privateKey),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"],
      );
      p.catch(() => {
        if (keyPromise === p) keyPromise = null;
      });
      keyPromise = p;
    }
    return keyPromise;
  }

  async function appJwt(): Promise<string> {
    const iat = Math.floor(now() / 1000) - 60;
    const unsigned = `${b64urlJson({ alg: "RS256", typ: "JWT" })}.${
      b64urlJson({ iat, exp: iat + 60 + APP_JWT_TTL_SEC, iss: opts.appId })
    }`;
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", await signingKey(), new TextEncoder().encode(unsigned));
    return `${unsigned}.${b64url(new Uint8Array(sig))}`;
  }

  async function mint(): Promise<string> {
    const res = await doFetch(`${api}/app/installations/${opts.installationId}/access_tokens`, {
      method: "POST",
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${await appJwt()}` },
      signal: AbortSignal.timeout(10_000),
    });
    const text = await res.text().catch(() => "");
    if (!res.ok) throw new GitHubError(res.status, `installation token: ${text.slice(0, 300)}`);
    const data = JSON.parse(text) as { token?: string; expires_at?: string };
    if (!data.token) throw new GitHubError(res.status, "installation token: no token in response");
    const expiresAt = data.expires_at ? Date.parse(data.expires_at) : now() + 55 * 60 * 1000;
    cached = { token: data.token, expiresAt };
    return data.token;
  }

  return {
    async token() {
      if (cached && cached.expiresAt - now() > TOKEN_REFRESH_MARGIN_MS) return cached.token;
      if (!inFlight) {
        inFlight = mint().finally(() => {
          inFlight = null;
        });
      }
      return await inFlight;
    },
  };
}

/** The configured auth, or null when neither a token nor an App is set. */
export function githubAuthFromEnv(): GitHubAuth | null {
  const env = (k: string) => Deno.env.get(k)?.trim() || "";
  const appId = env("GITHUB_APP_ID");
  const key = env("GITHUB_APP_PRIVATE_KEY");
  const installation = env("GITHUB_APP_INSTALLATION_ID");
  if (appId && key && installation) {
    return githubAppAuth({
      appId,
      privateKey: key,
      installationId: installation,
      apiUrl: env("GITHUB_API_URL") || undefined,
    });
  }
  const token = env("GITHUB_TOKEN");
  return token ? staticToken(token) : null;
}

// ---------------------------------------------------------------- GitHub API

export class GitHubError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "GitHubError";
  }
}

export interface CreateIssueInput {
  repo: string;
  title: string;
  body: string;
  labels?: string[];
  assignees?: string[];
}

export interface CreateIssueOptions {
  auth: GitHubAuth;
  apiUrl?: string;
  fetch?: typeof fetch;
}

export interface CreatedIssue {
  number: number;
  url: string;
}

/** POST /repos/{repo}/issues. Throws GitHubError on a non-2xx or a connection failure (status 0). */
export async function createIssue(input: CreateIssueInput, opts: CreateIssueOptions): Promise<CreatedIssue> {
  const api = (opts.apiUrl ?? GITHUB_API).replace(/\/$/, "");
  const token = await opts.auth.token();
  const payload: Record<string, unknown> = { title: input.title, body: input.body };
  if (input.labels?.length) payload.labels = input.labels;
  if (input.assignees?.length) payload.assignees = input.assignees;
  let res: Response;
  try {
    res = await (opts.fetch ?? fetch)(`${api}/repos/${input.repo}/issues`, {
      method: "POST",
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000),
    });
  } catch (err) {
    throw new GitHubError(0, String(err));
  }
  const text = await res.text().catch(() => "");
  if (!res.ok) throw new GitHubError(res.status, text.slice(0, 500));
  let data: { number?: number; html_url?: string };
  try {
    data = JSON.parse(text);
  } catch {
    throw new GitHubError(res.status, "unparseable response");
  }
  if (typeof data.number !== "number" || typeof data.html_url !== "string") {
    throw new GitHubError(res.status, "unexpected response shape");
  }
  return { number: data.number, url: data.html_url };
}

/** Map a GitHubError to the client-facing HttpError (details are logged, never returned). */
export function githubHttpError(err: GitHubError): HttpError {
  console.error("github_issue_failed", err.status, err.message);
  if (err.status === 0) return new HttpError(503, "github_unreachable");
  if (err.status === 403 && /rate limit/i.test(err.message)) return new HttpError(503, "github_rate_limited");
  return new HttpError(502, "github_error", { status: err.status });
}

// ---------------------------------------------------------------- attachments

export interface StoredAttachmentInput {
  appKey: string;
  report: IssueReport;
  index: number;
  name: string;
  contentType: string;
  bytes: Uint8Array;
}

/** Store one attachment and return a URL for the issue body, or null to omit it. */
export type AttachmentStore = (input: StoredAttachmentInput) => Promise<string | null>;

const SIGNED_URL_TTL_SEC = 365 * 24 * 60 * 60;

/** Supabase Storage store: `<bucket>/<appKey>/<yyyy-mm>/<uuid>-<name>`, signed for a year. */
export function supabaseAttachmentStore(bucket: string): AttachmentStore {
  return async ({ appKey, name, contentType, bytes }) => {
    // Lazy import keeps github.ts free of supabase-js for functions that don't store files.
    const { serviceClient } = await import("./auth.ts");
    const month = new Date().toISOString().slice(0, 7);
    const safeName = name.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80);
    const path = `${appKey}/${month}/${crypto.randomUUID()}-${safeName}`;
    const storage = serviceClient().storage.from(bucket);
    const up = await storage.upload(path, bytes, { contentType, upsert: false });
    if (up.error) {
      console.error("issue_attachment_upload_failed", up.error.message);
      return null;
    }
    const signed = await storage.createSignedUrl(path, SIGNED_URL_TTL_SEC);
    if (signed.error || !signed.data?.signedUrl) {
      console.error("issue_attachment_sign_failed", signed.error?.message);
      return null;
    }
    return signed.data.signedUrl;
  };
}

export function decodeBase64(data: string): Uint8Array<ArrayBuffer> {
  const binary = atob(data);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------- handler

export interface ReportIssueOptions {
  apps?: IssueApps;
  auth?: GitHubAuth | null;
  limits?: ReportLimits;
  /** Per-install limiter (key `appKey:reporterId`). Default 5/min from ISSUE_RATE_PER_MINUTE. */
  perInstall?: RateLimiter;
  /** Per-app limiter (key `appKey`). Default 30/min from ISSUE_APP_RATE_PER_MINUTE. */
  perApp?: RateLimiter;
  /** Attachment storage. Default: Supabase Storage when ISSUE_ATTACHMENTS_BUCKET is set, else attachments are dropped. */
  storeAttachment?: AttachmentStore | null;
  apiUrl?: string;
  fetch?: typeof fetch;
}

const envInt = (k: string, fallback: number) => {
  const n = Number(Deno.env.get(k));
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

let _perInstall: RateLimiter | null = null;
let _perApp: RateLimiter | null = null;

/**
 * The whole `report-issue` pipeline: resolve the app from `X-App-Key`, rate limit,
 * validate, store attachments, file the issue. Answers 201 `{number, url}`.
 *
 *   Deno.serve(handle((req) => reportIssue(req), { methods: ["POST"] }));
 */
export async function reportIssue(req: Request, opts: ReportIssueOptions = {}): Promise<Response> {
  const apps = opts.apps ?? issueAppsFromEnv();
  const auth = opts.auth === undefined ? githubAuthFromEnv() : opts.auth;
  if (!auth) throw new HttpError(503, "not_configured");
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const perInstall = opts.perInstall ??
    (_perInstall ??= rateLimiter({ perMinute: envInt("ISSUE_RATE_PER_MINUTE", 5) }));
  const perApp = opts.perApp ?? (_perApp ??= rateLimiter({ perMinute: envInt("ISSUE_APP_RATE_PER_MINUTE", 30) }));

  const appKey = (req.headers.get("X-App-Key") ?? "").trim();
  if (!appKey || !apps[appKey]) throw new HttpError(401, "unknown_app");
  perApp.enforce(appKey);

  const body = await readJson(req, { maxBytes: maxRequestBytes(limits) });
  const report = validateIssueReport(body, limits);
  const app = resolveIssueApp(apps, appKey, report.context.bundleIdentifier);
  perInstall.enforce(`${appKey}:${report.reporterId}`);

  let store = opts.storeAttachment;
  if (store === undefined) {
    const bucket = Deno.env.get("ISSUE_ATTACHMENTS_BUCKET")?.trim();
    store = bucket ? supabaseAttachmentStore(bucket) : null;
  }
  const attachmentUrls: Array<string | null> = [];
  for (const [index, att] of report.attachments.entries()) {
    if (!store) {
      attachmentUrls.push(null);
      continue;
    }
    try {
      attachmentUrls.push(
        await store({
          appKey,
          report,
          index,
          name: att.name,
          contentType: att.contentType,
          bytes: decodeBase64(att.data),
        }),
      );
    } catch (err) {
      console.error("issue_attachment_failed", String(err));
      attachmentUrls.push(null);
    }
  }

  let created: CreatedIssue;
  try {
    created = await createIssue(
      {
        repo: app.repo,
        title: formatIssueTitle(report),
        body: formatIssueBody(report, { attachmentUrls }),
        labels: issueLabels(app, report),
        assignees: app.assignees,
      },
      { auth, apiUrl: opts.apiUrl, fetch: opts.fetch },
    );
  } catch (err) {
    if (err instanceof GitHubError) throw githubHttpError(err);
    throw err;
  }
  console.log("issue_filed", appKey, app.repo, created.number, report.kind, report.context.channel);
  return json({ number: created.number, url: created.url }, 201);
}
