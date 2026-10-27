import { assertEquals } from "jsr:@std/assert@1";
import Stripe from "npm:stripe@17";
import {
  eventModeMatches,
  isEntitled,
  isLiveKey,
  mapStripeStatus,
  subscriptionPeriodEnd,
  verifyWebhook,
} from "../src/stripe.ts";
import { HttpError } from "../src/http.ts";

Deno.test("mapStripeStatus: the canonical table", () => {
  const table: Record<string, string> = {
    active: "active",
    trialing: "trialing",
    past_due: "grace",
    unpaid: "expired",
    canceled: "expired",
    incomplete_expired: "expired",
    paused: "expired",
    incomplete: "inactive",
    something_new: "inactive",
  };
  for (const [stripe, ours] of Object.entries(table)) assertEquals(mapStripeStatus(stripe), ours, stripe);
  assertEquals(mapStripeStatus(undefined), "inactive");
});

Deno.test("isEntitled: active/trialing/grace within period", () => {
  const now = Date.parse("2026-10-27T00:00:00Z");
  const future = "2026-11-27T00:00:00Z";
  const past = "2026-09-27T00:00:00Z";
  for (const s of ["active", "trialing", "grace"]) {
    assertEquals(isEntitled(s, future, now), true, s);
    assertEquals(isEntitled(s, null, now), true, s);
    assertEquals(isEntitled(s, past, now), false, s);
  }
  for (const s of ["expired", "inactive", "in_billing_retry"]) assertEquals(isEntitled(s, future, now), false, s);
});

Deno.test("subscriptionPeriodEnd: top-level (pre-basil) and item-level (basil)", () => {
  const t = 1_800_000_000;
  const iso = new Date(t * 1000).toISOString();
  assertEquals(subscriptionPeriodEnd({ current_period_end: t }), iso);
  assertEquals(subscriptionPeriodEnd({ items: { data: [{ current_period_end: t }] } }), iso);
  assertEquals(
    subscriptionPeriodEnd({ items: { data: [{ current_period_end: t - 100 }, { current_period_end: t }] } }),
    iso,
  );
  assertEquals(subscriptionPeriodEnd({}), null);
});

Deno.test("isLiveKey / eventModeMatches", () => {
  assertEquals(isLiveKey("sk_live_x"), true);
  assertEquals(isLiveKey("rk_live_x"), true);
  assertEquals(isLiveKey("sk_test_x"), false);
  const ev = { id: "evt", type: "x", livemode: false, data: { object: {} } };
  assertEquals(eventModeMatches(ev, "sk_test_x"), true);
  assertEquals(eventModeMatches(ev, "sk_live_x"), false);
});

// Real stripe@17 SDK: a signed test payload round-trips through verifyWebhook
// with the SubtleCrypto provider (picked up from the instance's class).
const stripe = new Stripe("sk_test_dummy", { httpClient: Stripe.createFetchHttpClient() });
const secret = "whsec_test_secret";
const payload = JSON.stringify({
  id: "evt_1",
  object: "event",
  type: "customer.subscription.updated",
  livemode: false,
  data: { object: { id: "sub_1" } },
});
const webhookReq = (sig: string | null, body = payload) =>
  new Request("http://x/stripe-webhook", { method: "POST", body, headers: sig ? { "stripe-signature": sig } : {} });

Deno.test("verifyWebhook: valid signature", async () => {
  const sig = await stripe.webhooks.generateTestHeaderStringAsync({ payload, secret });
  const event = await verifyWebhook(stripe, webhookReq(sig), secret);
  assertEquals(event.id, "evt_1");
  assertEquals(event.type, "customer.subscription.updated");
});

async function expectHttpError(p: Promise<unknown>, status: number, code: string) {
  const origError = console.error;
  console.error = () => {};
  try {
    await p;
    throw new Error("expected HttpError");
  } catch (err) {
    if (!(err instanceof HttpError)) throw err;
    assertEquals([err.status, err.code], [status, code]);
  } finally {
    console.error = origError;
  }
}

Deno.test("verifyWebhook: tampered body / missing signature / unconfigured", async () => {
  const sig = await stripe.webhooks.generateTestHeaderStringAsync({ payload, secret });
  await expectHttpError(
    verifyWebhook(stripe, webhookReq(sig, payload.replace("sub_1", "sub_2")), secret),
    400,
    "invalid_signature",
  );
  await expectHttpError(verifyWebhook(stripe, webhookReq(sig), "whsec_other"), 400, "invalid_signature");
  await expectHttpError(verifyWebhook(stripe, webhookReq(null), secret), 400, "missing_signature");
  await expectHttpError(verifyWebhook(stripe, webhookReq(sig), ""), 500, "stripe_not_configured");
});
