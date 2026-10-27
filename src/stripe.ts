// Stripe helpers. The Stripe SDK is passed in rather than imported, so this
// module doesn't pin a version for the app — but every portfolio function
// should construct it the same way:
//
//   import Stripe from "npm:stripe@17";
//   const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!, {
//     httpClient: Stripe.createFetchHttpClient(), // no Node sockets on the edge runtime
//     apiVersion: "2025-03-31.basil",            // GA; Managed Payments needs ≥ basil
//   });
//
// ─── Canonical status mapping ─────────────────────────────────────────────────
//
//   Stripe status        → portfolio status   entitled?
//   active               → active             yes
//   trialing             → trialing           yes
//   past_due             → grace              yes
//   unpaid               → expired            no
//   canceled             → expired            no
//   incomplete_expired   → expired            no
//   paused               → expired            no
//   incomplete           → inactive           no
//   (anything else)      → inactive           no
//
// The vocabulary is the same one appstore/statusFromTransaction emits
// (active | grace | expired), plus `trialing` and `inactive`, so one
// `subscriptions.status` column serves both stores.
//
// Why past_due → grace: Stripe's past_due means the renewal invoice failed and
// Smart Retries are running; the subscription stays live and the customer
// keeps access unless the account is configured otherwise. That is exactly
// Apple's Billing Grace Period (renewal failed, retrying, user still entitled)
// — not Apple's post-grace "billing retry", where access is gone. Calling it
// `grace` makes `isEntitled` treat both stores identically.
//
// Why trialing stays trialing: clients want to render "Free trial"; entitlement
// checks must use isEntitled() (or `status in ('active','trialing','grace')`).
//
// DRIFT this replaces (2026-10):
//   Stokked web/src/lib/stripe.ts  : trialing→trialing, past_due→in_billing_retry,
//                                    default (incomplete, paused)→expired
//   Contrarian stripe-webhook      : trialing→active,   past_due→grace,
//                                    default (incomplete, paused)→inactive
// Adopting this in Stokked means its SQL (has_active_subscription & co.) must
// accept `grace` where it accepted `in_billing_retry`; in Contrarian, the
// SQL must accept `trialing` where it accepted `active`. Migrate the SQL first.

import type { AnyClient } from "./auth.ts";
import { HttpError } from "./http.ts";

export type PortfolioSubscriptionStatus = "active" | "trialing" | "grace" | "expired" | "inactive";

export const ENTITLED_STATUSES: readonly PortfolioSubscriptionStatus[] = ["active", "trialing", "grace"];

/** Stripe subscription status → portfolio vocabulary (see the table above). */
export function mapStripeStatus(status: string | null | undefined): PortfolioSubscriptionStatus {
  switch (status) {
    case "active":
      return "active";
    case "trialing":
      return "trialing";
    case "past_due":
      return "grace";
    case "unpaid":
    case "canceled":
    case "incomplete_expired":
    case "paused":
      return "expired";
    case "incomplete":
    default:
      return "inactive";
  }
}

/** Does this status grant entitlement (subject to the period end)? */
export function isEntitled(status: string | null | undefined, periodEnd?: string | null, now = Date.now()): boolean {
  if (!ENTITLED_STATUSES.includes(status as PortfolioSubscriptionStatus)) return false;
  return !periodEnd || Date.parse(periodEnd) > now;
}

/** Minimal structural shape of a Stripe.Subscription used here. */
export interface SubscriptionLike {
  id?: string;
  status?: string;
  customer?: string | { id: string } | null;
  metadata?: Record<string, string> | null;
  current_period_end?: number | null;
  items?: { data?: Array<{ current_period_end?: number | null; price?: { id?: string } | null }> } | null;
}

/**
 * Period end as ISO, or null. It moved from the top-level `current_period_end`
 * to the subscription item in API 2025-03-31.basil — read whichever is present
 * (the latest item end, for multi-item subscriptions).
 */
export function subscriptionPeriodEnd(sub: SubscriptionLike): string | null {
  let epoch = sub.current_period_end ?? null;
  if (!epoch) {
    for (const item of sub.items?.data ?? []) {
      const e = item.current_period_end;
      if (e && (!epoch || e > epoch)) epoch = e;
    }
  }
  return epoch ? new Date(epoch * 1000).toISOString() : null;
}

/** The customer id from a string or expanded object. */
export function customerId(customer: string | { id: string } | null | undefined): string | null {
  if (!customer) return null;
  return typeof customer === "string" ? customer : customer.id ?? null;
}

/** Minimal structural shape of the Stripe client used here. */
export interface StripeLike {
  webhooks: {
    constructEventAsync(
      payload: string,
      header: string,
      secret: string,
      tolerance?: number,
      cryptoProvider?: unknown,
    ): Promise<StripeEventLike>;
  };
  customers: {
    // Loosely typed so a real Stripe instance (Customer | DeletedCustomer) fits.
    retrieve(id: string): Promise<unknown>;
    del(id: string): Promise<unknown>;
  };
}

export interface StripeEventLike {
  id: string;
  type: string;
  livemode: boolean;
  data: { object: unknown };
}

export interface ResolveUserIdOptions {
  /** Trusted user id already on the event (checkout `client_reference_id`). */
  hint?: string | null;
  /** The subscription, whose metadata is the last fallback. */
  subscription?: SubscriptionLike | null;
  /** When given, the Stripe customer's metadata is consulted. */
  stripe?: StripeLike;
  /** Table/column mapping customer → user (default subscriptions.stripe_customer_id → user_id). */
  table?: string;
  customerColumn?: string;
  userColumn?: string;
  /** Metadata keys holding the Supabase user id, in priority order. */
  metadataKeys?: string[];
}

/**
 * Resolve the Supabase user for a Stripe customer: hint → own table row
 * (written by checkout before the session) → customer metadata → subscription
 * metadata. Returns null when unresolvable (log and ack — retries won't help).
 */
export async function resolveUserId(
  service: AnyClient,
  customer: string | { id: string } | null | undefined,
  opts: ResolveUserIdOptions = {},
): Promise<string | null> {
  if (opts.hint) return opts.hint;
  const keys = opts.metadataKeys ?? ["supabase_user_id", "user_id"];
  const fromMeta = (m: Record<string, string> | null | undefined) => {
    for (const k of keys) if (m?.[k]) return m[k];
    return null;
  };

  const id = customerId(customer);
  if (id) {
    const userColumn = opts.userColumn ?? "user_id";
    const { data, error } = await service
      .from(opts.table ?? "subscriptions")
      .select(userColumn)
      .eq(opts.customerColumn ?? "stripe_customer_id", id)
      .limit(1)
      .maybeSingle();
    if (error) throw error;
    const row = data as Record<string, unknown> | null;
    if (row?.[userColumn]) return String(row[userColumn]);

    if (opts.stripe) {
      const c = (await opts.stripe.customers.retrieve(id)) as {
        deleted?: unknown;
        metadata?: Record<string, string> | null;
      };
      if (!c.deleted) {
        const u = fromMeta(c.metadata);
        if (u) return u;
      }
    }
  }
  return fromMeta(opts.subscription?.metadata);
}

/** True for live-mode secret/restricted keys. */
export function isLiveKey(secretKey: string | null | undefined): boolean {
  return !!secretKey && (secretKey.startsWith("sk_live_") || secretKey.startsWith("rk_live_"));
}

/**
 * Does the event's mode match the key's? Never let a test-mode event write
 * live entitlement or vice versa (a sandbox checkout once left a Contrarian
 * live row pointing at a test customer). Answer 200 + ignore on mismatch.
 */
export function eventModeMatches(event: StripeEventLike, secretKey: string | null | undefined): boolean {
  return event.livemode === isLiveKey(secretKey);
}

/**
 * Verify a webhook request's signature over the raw body and return the
 * event. Uses the SubtleCrypto provider (the sync constructEvent needs Node
 * crypto, which the edge runtime lacks). Throws HttpError 400
 * `missing_signature` / `invalid_signature`, 500 `stripe_not_configured`.
 */
export async function verifyWebhook(
  stripe: StripeLike,
  req: Request,
  secret: string | null | undefined,
  opts: { cryptoProvider?: unknown; tolerance?: number } = {},
): Promise<StripeEventLike> {
  if (!secret) throw new HttpError(500, "stripe_not_configured");
  const signature = req.headers.get("stripe-signature");
  if (!signature) throw new HttpError(400, "missing_signature");
  const body = await req.text();
  // The Stripe class exposes createSubtleCryptoProvider statically.
  const provider = opts.cryptoProvider ??
    (stripe.constructor as { createSubtleCryptoProvider?: () => unknown }).createSubtleCryptoProvider?.();
  try {
    return await stripe.webhooks.constructEventAsync(body, signature, secret, opts.tolerance, provider);
  } catch (err) {
    console.error("stripe_signature_invalid", err instanceof Error ? err.message : err);
    throw new HttpError(400, "invalid_signature");
  }
}

/**
 * Delete a Stripe customer (cancels its subscriptions immediately, no refund,
 * scrubs the billing profile) — the delete-account `beforeDelete` step.
 * Already-deleted is fine; anything else throws HttpError 502 `stripe_error`.
 */
export async function deleteStripeCustomer(stripe: StripeLike, id: string): Promise<void> {
  try {
    await stripe.customers.del(id);
  } catch (err) {
    if ((err as { code?: string })?.code === "resource_missing") return;
    console.error("stripe_customer_delete_failed", id, err);
    throw new HttpError(502, "stripe_error");
  }
}
