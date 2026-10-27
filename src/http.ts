// HTTP plumbing shared by every edge function: CORS, JSON responses, a typed
// error, and a `handle()` wrapper that turns thrown HttpErrors into JSON and
// never lets an unknown exception escape as a bare 500 with a stack trace.
//
// Replaces the per-function `CORS_HEADERS` + `json(body, status)` copies in
// Contrarian, Carpe Vitem, ThenCam and Stokked.

export const DEFAULT_ALLOW_HEADERS = "authorization, x-client-info, apikey, content-type";
export const DEFAULT_ALLOW_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS";

export interface CorsOptions {
  /**
   * Browser origins allowed to call the function. Omitted/empty → `*` (fine
   * for bearer-token APIs: no cookies are involved). When set, a listed
   * request Origin is echoed back and anything else gets the first entry
   * (so the browser blocks it) — the Stokked `AI_ALLOWED_ORIGINS` behaviour.
   */
  allowOrigins?: string[];
  allowHeaders?: string;
  allowMethods?: string;
}

/** Parse a comma-separated origin list (e.g. from an env var). */
export function parseOrigins(raw: string | undefined | null): string[] {
  return (raw ?? "").split(",").map((o) => o.trim()).filter(Boolean);
}

/** CORS response headers for a request `origin` (the request's Origin header). */
export function corsHeaders(
  origin?: string | null,
  opts: CorsOptions = {},
): Record<string, string> {
  const headers: Record<string, string> = {
    "Access-Control-Allow-Headers": opts.allowHeaders ?? DEFAULT_ALLOW_HEADERS,
    "Access-Control-Allow-Methods": opts.allowMethods ?? DEFAULT_ALLOW_METHODS,
  };
  const list = opts.allowOrigins?.filter(Boolean) ?? [];
  if (list.length === 0) {
    headers["Access-Control-Allow-Origin"] = "*";
  } else {
    headers["Access-Control-Allow-Origin"] = origin && list.includes(origin) ? origin : list[0];
    headers["Vary"] = "Origin";
  }
  return headers;
}

/** The CORS preflight response for an OPTIONS request, or null for any other method. */
export function preflight(req: Request, opts: CorsOptions = {}): Response | null {
  if (req.method !== "OPTIONS") return null;
  return new Response("ok", { headers: corsHeaders(req.headers.get("Origin"), opts) });
}

/** A JSON response. `init.headers` are merged over the content type. */
export function json(body: unknown, status = 200, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { ...init, status, headers });
}

/** `{ error: code, ...extra }` with the given status — the portfolio's error shape. */
export function errorJson(
  code: string,
  status: number,
  extra?: Record<string, unknown>,
  init: ResponseInit = {},
): Response {
  return json({ error: code, ...(extra ?? {}) }, status, init);
}

/**
 * Throw from anywhere inside a `handle()`d function to answer with
 * `{ error: code, ...extra }`. `headers` ride along (e.g. Retry-After).
 */
export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    public extra?: Record<string, unknown>,
    public headers?: Record<string, string>,
  ) {
    super(code);
    this.name = "HttpError";
  }

  toResponse(): Response {
    return errorJson(this.code, this.status, this.extra, { headers: this.headers });
  }
}

export interface HandleOptions {
  /** CORS for every response (and automatic OPTIONS preflight). `false` = no CORS headers (webhooks). */
  cors?: CorsOptions | false;
  /** Allowed methods (OPTIONS is implicit when CORS is on). Others → 405 method_not_allowed. */
  methods?: string[];
  /** Log label for unexpected errors (defaults to "handler"). */
  label?: string;
}

/** Copy `extra` headers onto a response, rebuilding it if its headers are immutable. */
function withHeaders(res: Response, extra: Record<string, string>): Response {
  try {
    for (const [k, v] of Object.entries(extra)) {
      if (!res.headers.has(k)) res.headers.set(k, v);
    }
    return res;
  } catch {
    // e.g. a proxied fetch() Response: immutable headers.
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(extra)) if (!headers.has(k)) headers.set(k, v);
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  }
}

/**
 * Wrap a handler for `Deno.serve`:
 *  - answers CORS preflight and adds CORS headers to every response (unless `cors: false`),
 *  - enforces `methods` (405),
 *  - maps a thrown HttpError to its JSON response,
 *  - logs anything else and answers 500 `internal_error` (no details leak).
 *
 *   Deno.serve(handle(async (req) => json({ ok: true }), { methods: ["POST"] }));
 */
export function handle(
  fn: (req: Request) => Response | Promise<Response>,
  opts: HandleOptions = {},
): (req: Request) => Promise<Response> {
  const label = opts.label ?? "handler";
  const methods = opts.methods?.map((m) => m.toUpperCase());
  return async (req: Request) => {
    const cors = opts.cors === false ? null : corsHeaders(req.headers.get("Origin"), opts.cors ?? {});
    if (cors && req.method === "OPTIONS") return new Response("ok", { headers: cors });
    let res: Response;
    try {
      if (methods && !methods.includes(req.method.toUpperCase())) {
        throw new HttpError(405, "method_not_allowed", undefined, { Allow: methods.join(", ") });
      }
      res = await fn(req);
    } catch (err) {
      if (err instanceof HttpError) {
        res = err.toResponse();
      } else {
        console.error(`${label}_failed`, err);
        res = errorJson("internal_error", 500);
      }
    }
    return cors ? withHeaders(res, cors) : res;
  };
}

/**
 * Read and parse a JSON request body with a byte cap. Throws HttpError
 * 413 `request_too_large` or 400 `invalid_json`. Compares UTF-8 bytes, not
 * UTF-16 code units (multi-byte text would otherwise pass at ~3x the cap).
 */
export async function readJson<T = Record<string, unknown>>(
  req: Request,
  opts: { maxBytes?: number } = {},
): Promise<T> {
  const max = opts.maxBytes ?? 1024 * 1024;
  const declared = Number(req.headers.get("Content-Length") ?? "0");
  if (declared > max) throw new HttpError(413, "request_too_large");
  const raw = await req.text();
  if (new TextEncoder().encode(raw).byteLength > max) throw new HttpError(413, "request_too_large");
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}
