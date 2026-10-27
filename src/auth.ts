// Supabase auth preamble: the anon client with the caller's forwarded
// Authorization → getUser() → service-role client dance that every
// user-facing function repeats.
//
// Env (stock on every Supabase stack): SUPABASE_URL, SUPABASE_ANON_KEY,
// SUPABASE_SERVICE_ROLE_KEY. Read lazily so a module import never throws.

import { createClient, type SupabaseClient, type User } from "jsr:@supabase/supabase-js@2";
import { HttpError } from "./http.ts";

// deno-lint-ignore no-explicit-any
export type AnyClient = SupabaseClient<any, any, any>;

function env(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`${name} is not set`);
  return v;
}

const NO_SESSION = { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false };

let _service: AnyClient | null = null;

/** Service-role client (bypasses RLS). Cached per isolate. */
export function serviceClient(): AnyClient {
  _service ??= createClient(env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY"), {
    auth: NO_SESSION,
  });
  return _service;
}

/** The bearer token from `Authorization: Bearer <token>`, or null. */
export function bearer(req: Request): string | null {
  const header = req.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return m ? m[1].trim() || null : null;
}

/**
 * Anon-key client that forwards the caller's Authorization header, so
 * PostgREST/RPC calls run as the user under RLS.
 */
export function userClient(req: Request): AnyClient {
  const token = bearer(req);
  return createClient(env("SUPABASE_URL"), env("SUPABASE_ANON_KEY"), {
    auth: NO_SESSION,
    global: { headers: token ? { Authorization: `Bearer ${token}` } : {} },
  });
}

export interface RequireUserOptions {
  /**
   * Accept GoTrue anonymous users (`is_anonymous`). Default true; false →
   * 403 `signup_required` (Contrarian's purchase/checkout guard).
   */
  allowAnonymous?: boolean;
}

export interface AuthedRequest {
  user: User;
  userId: string;
  token: string;
  userClient: AnyClient;
  serviceClient: AnyClient;
}

/**
 * Verify the caller's Supabase JWT with GoTrue. Throws HttpError
 * 401 `missing_token` / 401 `invalid_token` / 403 `signup_required`.
 */
export async function requireUser(
  req: Request,
  opts: RequireUserOptions = {},
): Promise<AuthedRequest> {
  const token = bearer(req);
  if (!token) throw new HttpError(401, "missing_token");
  const uc = userClient(req);
  const { data, error } = await uc.auth.getUser(token);
  if (error || !data?.user) throw new HttpError(401, "invalid_token");
  if (opts.allowAnonymous === false && data.user.is_anonymous) {
    throw new HttpError(403, "signup_required");
  }
  return { user: data.user, userId: data.user.id, token, userClient: uc, serviceClient: serviceClient() };
}

/**
 * Constant-time string compare for shared secrets. Runs over the longer of
 * the two inputs so the timing doesn't reveal a prefix match; unequal lengths
 * (and empty strings) are never equal.
 */
export function timingSafeEqual(a: string | null | undefined, b: string | null | undefined): boolean {
  if (typeof a !== "string" || typeof b !== "string" || !a || !b) return false;
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  const n = Math.max(ea.length, eb.length);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < n; i++) diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
  return diff === 0;
}

/** True when `token` is this stack's service-role key (cron / ops callers). */
export function isServiceRoleToken(token: string | null | undefined): boolean {
  return timingSafeEqual(token, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** RFC 4122-shaped UUID (Supabase user ids, StoreKit appAccountToken). */
export function isUuid(v: unknown): v is string {
  return typeof v === "string" && UUID_RE.test(v);
}
