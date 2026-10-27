# supabase-shared

Shared Deno module for the portfolio's Supabase edge functions. It replaces the
helpers that were copy-pasted into almost every function (and had already
drifted): CORS + JSON responses, the auth preamble, App Store JWS / Server
Notifications v2 verification, account deletion, Stripe helpers, the Anthropic
proxy, rate limiting, APNs push and Resend email.

Seeded from Contrarian's `_shared/` (the only App Store verifier that works on
the edge runtime, and tested) and Celiador's APNs sender. See
`Celiador/_standard/SHARED_PACKAGES_SURVEY.md` §1.1 for the survey behind it.

- **Runtime:** `Deno.serve` era. Imports are `jsr:@supabase/supabase-js@2` and
  `npm:` specifiers written inline (no import map, so a vendored copy works as
  is). No `deno.land/std@0.168`, no esm.sh.
- **Distribution:** vendored. Each app copies a pinned tag into
  `supabase/functions/_shared/portfolio/` with `scripts/sync-shared.sh` and
  commits it. The self-hosted edge runtime would otherwise need a token for a
  private remote import at boot.

## Modules

| File | What it does |
|---|---|
| `src/http.ts` | `corsHeaders(origin?, {allowOrigins?})`, `preflight(req)`, `json(body, status, init?)`, `errorJson(code, status, extra?)`, `HttpError`, `handle(fn, {cors, methods})`, `readJson(req, {maxBytes})`, `parseOrigins` |
| `src/auth.ts` | `serviceClient()`, `userClient(req)`, `requireUser(req, {allowAnonymous?})` → `{user, userId, token, userClient, serviceClient}`, `bearer(req)`, `timingSafeEqual`, `isServiceRoleToken`, `isUuid` |
| `src/appstore/` | `createAppStoreVerifier({bundleIds, appAppleId?, allowSandbox?})` → `verifyTransaction`, `verifyNotification`, `verifyRenewalInfo`; `statusFromTransaction`; `verifyAppleJWS`, `AppleJWSError`, `verificationReason`; vendored Apple roots |
| `src/account.ts` | `purgeUserStorage(service, bucket, userId)`, `listAllPaths`, `deleteAuthUser(service, userId)` (404 = success), `deleteAccount({req, buckets, beforeDelete?})` |
| `src/stripe.ts` | canonical `mapStripeStatus`, `isEntitled`, `subscriptionPeriodEnd`, `resolveUserId`, `verifyWebhook`, `eventModeMatches`/`isLiveKey`, `deleteStripeCustomer`. The Stripe SDK is passed in. |
| `src/anthropic.ts` | `anthropicConfig()` (env), `parseAllowedModels`, `pickModel`, `cachedSystem`, `postMessages(body, {retries: 3})`, `upstreamError`, `anthropicHttpError`, `responseText` |
| `src/ratelimit.ts` | `rateLimiter({perMinute})` (in-memory sliding window), the `DailyCap` interface, `enforceDailyCap(cap, userId)` |
| `src/apns.ts` | `sendAlert`, `sendLiveActivity` (env-configured), `createApnsClient(cfg)`, `isDeadToken`, `isValidDeviceToken`, `hostFor` |
| `src/email.ts` | `sendEmail({to, subject, text, html?, idempotencyKey?})` via Resend, `emailConfigured`, `canEmailPublic` |
| `src/mod.ts` | re-exports everything |

Import a submodule (`./_shared/portfolio/http.ts`) instead of `mod.ts` to keep a
function's dependency graph small: `appstore/` pulls `@peculiar/x509` and `jose`,
and `auth`/`account` pull supabase-js.

### Examples

**A user-facing JSON function**

```ts
import { handle, HttpError, json, readJson } from "../_shared/portfolio/http.ts";
import { requireUser } from "../_shared/portfolio/auth.ts";

Deno.serve(handle(async (req) => {
  const { userId, userClient } = await requireUser(req); // 401 missing_token / invalid_token
  const body = await readJson<{ text?: string }>(req, { maxBytes: 64 * 1024 });
  if (!body.text) throw new HttpError(400, "missing_text");
  const { error } = await userClient.from("notes").insert({ user_id: userId, text: body.text });
  if (error) throw new HttpError(500, "db_error");
  return json({ ok: true });
}, { methods: ["POST"], cors: { allowOrigins: ["https://stokked.ai", "https://www.stokked.ai"] } }));
```

`handle()` answers the CORS preflight, adds CORS headers to every response,
returns 405 for other methods, turns an `HttpError` into `{error: code}`, and
answers an unknown exception with 500 `internal_error` (the error is logged,
never returned). Use `cors: false` for webhooks.

**App Store: verify a client purchase**

```ts
import { createAppStoreVerifier, statusFromTransaction, verificationReason } from "../_shared/portfolio/appstore/mod.ts";

const appstore = createAppStoreVerifier({
  bundleIds: ["com.crawik.contria"],
  appAppleId: 6785219877,           // required for Production notifications
  allowSandbox: true,               // TestFlight runs in sandbox
});

try {
  const { txn, environment } = await appstore.verifyTransaction(jws);
  const { status, periodEnd } = statusFromTransaction(txn);
} catch (err) {
  console.error("invalid_jws", verificationReason(err)); // answer 400, not 401
}
```

**App Store Server Notifications v2**

```ts
const { payload, environment, transaction, renewalInfo } = await appstore.verifyNotification(signedPayload);
// inner signedTransactionInfo / signedRenewalInfo are already verified, in the same environment
if (transaction) {
  const { status, periodEnd } = statusFromTransaction(transaction, renewalInfo);
}
```

Failure reasons include `untrusted_root`, `signature_invalid`, `invalid_bundle_id`,
`invalid_app_apple_id`, `app_apple_id_required`, `sandbox_not_allowed`,
`environment_mismatch`, `cert_not_valid_at_signed_date`.

**Delete account (Stripe first, then storage, then the auth user)**

```ts
import Stripe from "npm:stripe@17";
import { handle, json } from "../_shared/portfolio/http.ts";
import { deleteAccount } from "../_shared/portfolio/account.ts";
import { deleteStripeCustomer } from "../_shared/portfolio/stripe.ts";

Deno.serve(handle(async (req) => {
  const result = await deleteAccount({
    req,
    buckets: ["food_photos"],
    beforeDelete: async ({ userId, serviceClient }) => {
      const { data } = await serviceClient.from("subscriptions").select("stripe_customer_id").eq("user_id", userId).maybeSingle();
      if (data?.stripe_customer_id) await deleteStripeCustomer(stripe(), data.stripe_customer_id); // 502 aborts
    },
  });
  return json({ deleted: true, ...result });
}, { methods: ["POST"] }));
```

**Stripe webhook**

```ts
import Stripe from "npm:stripe@17";
import { handle, json } from "../_shared/portfolio/http.ts";
import { serviceClient } from "../_shared/portfolio/auth.ts";
import { eventModeMatches, mapStripeStatus, resolveUserId, subscriptionPeriodEnd, verifyWebhook } from "../_shared/portfolio/stripe.ts";

const key = Deno.env.get("STRIPE_SECRET_KEY") ?? "";
const stripe = new Stripe(key, { httpClient: Stripe.createFetchHttpClient(), apiVersion: "2025-03-31.basil" });

Deno.serve(handle(async (req) => {
  const event = await verifyWebhook(stripe, req, Deno.env.get("STRIPE_WEBHOOK_SECRET")); // 400 invalid_signature
  if (!eventModeMatches(event, key)) return json({ received: true, ignored: "mode_mismatch" });
  // ...re-retrieve the subscription, then:
  // const userId = await resolveUserId(serviceClient(), sub.customer, { stripe, subscription: sub });
  // upsert { status: mapStripeStatus(sub.status), current_period_end: subscriptionPeriodEnd(sub) }
  return json({ received: true });
}, { cors: false, methods: ["POST"] }));
```

**Anthropic proxy with rate limit + daily cap**

```ts
import { handle, json, readJson } from "../_shared/portfolio/http.ts";
import { requireUser } from "../_shared/portfolio/auth.ts";
import { AnthropicError, anthropicHttpError, cachedSystem, pickModel, postMessages, upstreamError } from "../_shared/portfolio/anthropic.ts";
import { type DailyCap, enforceDailyCap, rateLimiter } from "../_shared/portfolio/ratelimit.ts";

const perMinute = rateLimiter({ perMinute: 20 });

Deno.serve(handle(async (req) => {
  const { userId, userClient } = await requireUser(req);
  perMinute.enforce(userId);                                   // 429 rate_limited
  const cap: DailyCap = {
    usedToday: async () => { const { data, error } = await userClient.rpc("engine_calls_last_24h"); return error ? null : data; },
    limitFor: () => 30,
  };
  await enforceDailyCap(cap, userId);                         // 429 daily_limit_exceeded (fails open)
  const body = await readJson<{ model?: string; messages: unknown[] }>(req, { maxBytes: 128 * 1024 });
  let res: Response;
  try {
    res = await postMessages({ model: pickModel(body.model), max_tokens: 4096, system: cachedSystem(PROMPT), messages: body.messages });
  } catch (err) {
    if (err instanceof AnthropicError) throw anthropicHttpError(err);
    throw err;
  }
  if (!res.ok) throw upstreamError(res);                       // 429 / 503 / 502, upstream body never forwarded
  return json(await res.json());
}, { methods: ["POST"] }));
```

Env: `ANTHROPIC_API_KEY ?? AI_API_KEY`, `ANTHROPIC_BASE_URL` (default
`https://api.anthropic.com/v1`), `ANTHROPIC_VERSION`, `AI_DEFAULT_MODEL` (default
`claude-opus-5-5`), `AI_ALLOWED_MODELS` (or `ALLOWED_MODELS`; default = only the
default model). `postMessages` retries connection errors, 429, 5xx and 529 with
exponential backoff (honouring `retry-after`).

**APNs**

```ts
import { isDeadToken, sendAlert, sendLiveActivity } from "../_shared/portfolio/apns.ts";

const r = await sendAlert({ token, env: "production" }, { title: "Check-in", body: "How was today?", data: { day: "2026-10-27" } });
if (isDeadToken(r)) await service.from("device_tokens").delete().eq("token", token);
await sendLiveActivity({ token: laToken, env: "sandbox" }, { event: "update", contentState: { step: 3 } });
```

Env: `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_KEY` (the .p8 PEM; `\n` escapes and a
bare base64 body work; `APNS_PRIVATE_KEY` is accepted too), `APNS_TOPIC`. The
JWT is signed with `crypto.subtle` (ES256, raw r‖s signature) and cached for 50
minutes; `ExpiredProviderToken` gets one retry with a fresh token. Delivery uses
`fetch` (Deno negotiates HTTP/2 with api.push.apple.com over ALPN) with a 10 s
`AbortSignal.timeout`. A `production` token goes to `api.push.apple.com`;
anything else goes to the sandbox host. Push is a no-op
(`{status: 0, reason: "not_configured"}`) when the env isn't set.

**Email**

```ts
import { sendEmail } from "../_shared/portfolio/email.ts";
const r = await sendEmail({ to: "user@example.com", subject: "Welcome", text: "Hi!", idempotencyKey: `welcome-${userId}` });
```

Env: `RESEND_API_KEY`, `EMAIL_FROM`. Never throws; returns `{ok, id}` or `{ok: false, status, error}`.

## Canonical Stripe status mapping

| Stripe | portfolio | entitled |
|---|---|---|
| `active` | `active` | yes |
| `trialing` | `trialing` | yes |
| `past_due` | `grace` | yes |
| `unpaid` | `expired` | no |
| `canceled` | `expired` | no |
| `incomplete_expired` | `expired` | no |
| `paused` | `expired` | no |
| `incomplete` | `inactive` | no |
| anything else | `inactive` | no |

Apple's `statusFromTransaction` returns the same words (`active | grace | expired`),
so one `subscriptions.status` column works for both stores. Check entitlement
with `isEntitled(status, periodEnd)`, or in SQL with
`status in ('active','trialing','grace') and (current_period_end is null or current_period_end > now())`.

- **`past_due` → `grace`:** in Stripe, `past_due` means the renewal payment
  failed, Smart Retries are running, and the customer keeps access. Apple's
  Billing Grace Period works the same way (renewal failed, Apple is retrying,
  the user stays entitled). It is not Apple's later billing-retry state, where
  access is gone.
- **`trialing` stays `trialing`:** clients show "Free trial". It still counts
  as entitled.
- **`incomplete` → `inactive`:** the first invoice was never paid, so the user
  was never entitled. `paused` → `expired`: the user had access and lost it.

**Drift this replaces.** The apps had two different mappings:

| Stripe | Stokked `web/src/lib/stripe.ts` | Contrarian `stripe-webhook` | canonical |
|---|---|---|---|
| `trialing` | `trialing` | `active` | `trialing` |
| `past_due` | `in_billing_retry` | `grace` | `grace` |
| `incomplete` | `expired` | `inactive` | `inactive` |
| `paused` | `expired` | `inactive` | `expired` |

Migrate the SQL before you switch an app over:
- **Stokked:** `has_active_subscription` and similar functions must accept
  `grace` wherever they accept `in_billing_retry`. The delete-account
  "still billable" check must treat `inactive` the way it treats `expired`.
- **Contrarian:** `has_active_subscription()` and the checkout `already_subscribed`
  guard must accept `trialing` wherever they accept `active`. Contrarian has no
  trials today, so this is a no-op until one is added.

## Sync into an app

```sh
# from the app repo root
../supabase-shared/scripts/sync-shared.sh 0.1.0 supabase/functions/_shared/portfolio
git add supabase/functions/_shared/portfolio && git commit -m "Vendor supabase-shared 0.1.0"
```

- The script shallow-clones the tag from
  `https://github.com/Cliefden/supabase-shared.git`. Set `SUPABASE_SHARED_REPO`
  to use another URL or a local path (for example, to test a tag you haven't
  pushed yet).
- It replaces `<dest>` with `src/` and writes `<dest>/VERSION` (tag, commit,
  repo, date).
- It refuses to overwrite a non-empty directory that has no `VERSION` file.
- Never edit the vendored copy. Change this repo, tag a release, and re-sync.
- ThenCam keeps its functions in `backend/functions/`, so its destination is
  `backend/functions/_shared/portfolio`. Contrarian's
  `tools/deploy-function.sh` must also ship `_shared/portfolio/**` (all files
  are `.ts`; `VERSION` is optional at runtime).

## Development

```sh
deno task check   # deno check src/mod.ts
deno task test    # deno test (57 tests)
deno task lint
```

The tests run on the Deno CLI, not inside the edge runtime. Before you trust an
edge-runtime upgrade, also run Contrarian's in-container harness
(`Contrarian/supabase/tests/appstore-edge`). The App Store fixtures are real
Apple-signed TEST notifications for `com.crawik.contria`.

Releases use semver tags (`git tag 0.2.0`). Apps pin a tag through `sync-shared.sh`.

## Per-app adoption

What each module replaces. Paths are relative to the app's folder in `Apps-AppStore/`.

| App | Existing code | Superseded by |
|---|---|---|
| **Contrarian** | `supabase/functions/_shared/apple-jws.ts`, `apple-roots.ts`, and the verify half of `_shared/appstore.ts` (`verifyTransactionJWS`, `verifyNotification`, `verifyInner*`, `statusFromTransaction`, `verificationReason`) | `appstore/` (`BUNDLE_ID`/`APP_APPLE_ID` become options). `convergeAppleSubscription` and `userIdForOriginalTxn` depend on Contria's schema and stay in the app. |
| | `CORS_HEADERS` + `json()` + the anon-client `getUser()` preamble in `appstore-verify`, `delete-account`, `stripe-checkout`, `stripe-portal`, `contria-engine` | `http.ts` (`handle`, `json`) + `auth.ts` (`requireUser({allowAnonymous: false})` covers the `signup_required` guard) |
| | `appstore-webhook/index.ts` verify + inner verify | `appstore.verifyNotification` (inner JWS included) |
| | `delete-account/index.ts` | `account.deleteAccount({beforeDelete: deleteStripeCustomer})` |
| | `stripe-webhook/index.ts`: `mapStripeStatus`, `subscriptionPeriodEnd`, `resolveUserId`, `constructEventAsync` + crypto provider, livemode check | `stripe.ts` (switch to canonical `trialing` first; see the drift section above) |
| | `contria-engine/index.ts`: env block (`ANTHROPIC_API_KEY ?? AI_API_KEY`, base URL, `AI_DEFAULT_MODEL`, `AI_ALLOWED_MODELS`), `postMessages` with retries, the `engine_calls_last_24h` cap check | `anthropic.ts` + `ratelimit.enforceDailyCap` (Contria's RPC is the `DailyCap`; -1 = admin is supported) |
| **Carpe Vitem** | `supabase/functions/delete-account/index.ts` (`listAllPaths`, batched remove, `deleteUser`) | `account.deleteAccount({buckets: ["food_photos"]})` |
| | `supabase/functions/verify-purchase/index.ts`: `@apple/app-store-server-library@3.1.0` `SignedDataVerifier` loop, `APPLE_ROOT_CA_G3_BASE64` env | `createAppStoreVerifier({bundleIds: APPLE_BUNDLE_IDS, appAppleId: APPLE_APP_ID, allowSandbox: APPLE_ALLOW_SANDBOX !== "false"})`. The roots are vendored, so `APPLE_ROOT_CA_G3_BASE64` is no longer needed. Note: the library breaks on the edge runtime. |
| | `analyze-food/index.ts`: `callAnthropic` (hard-coded `claude-sonnet-4-20250514`, no retry), auth preamble, CORS/JSON | `anthropic.postMessages` + `pickModel`, `auth.requireUser`, `http.handle`. The OpenAI branch stays in the app. |
| | esm.sh `supabase-js` imports in all 3 functions | `jsr:@supabase/supabase-js@2` (through `auth.ts`) |
| **ThenCam** | `backend/functions/verify-apple-purchase/index.ts` + `apple-notifications/index.ts`: `@apple/app-store-server-library@1`, root CA inlined twice, `makeVerifiers()` | `createAppStoreVerifier({bundleIds: [APPLE_BUNDLE_ID], appAppleId: APPLE_APP_APPLE_ID})`. The per-account sandbox gate (`app_metadata.allow_sandbox_purchases`) stays in the app: check `environment === "Sandbox"`. Non-expiring transactions (the Pro unlock) map to `active` until revoked. |
| | `create-checkout-session/index.ts`: auth preamble, CORS pinned to `SITE_URL` | `auth.requireUser` + `handle(fn, {cors: {allowOrigins: [SITE_URL]}})` |
| | `stripe-webhook/index.ts`: `constructEventAsync` + crypto provider | `stripe.verifyWebhook`. The one-time-payment grant/revoke and `stripe_events` idempotency logic stay in the app (not subscriptions, so `mapStripeStatus` doesn't apply). |
| **Stokked** | `supabase/functions/apple-subscription-webhook/index.ts`: a forwarder to Next.js that exists only because the Apple library fails on Deno | `appstore.verifyNotification` can now verify in the edge function itself. This lets you retire the Next.js receiver `web/src/app/api/apple/webhook/route.ts`, after you port its out-of-order guard and status logic. |
| | `rapid-processor/index.ts`: `corsHeaders(origin)` allowlist (`AI_ALLOWED_ORIGINS`), `isRateLimited` (20/min map), env block, Anthropic fetch + 429/529 mapping, `json()` | `http.corsHeaders`/`handle({cors: {allowOrigins: parseOrigins(env)}})`, `ratelimit.rateLimiter({perMinute: 20})`, `anthropic.postMessages` + `upstreamError`. The `ai_usage` reservation becomes a `DailyCap` with `includesCurrent: true`. |
| | `apple-auth/index.ts`: `timingSafeEqual`, the service-role bearer check, `json()`, `std@0.168` `serve` | `auth.timingSafeEqual` / `isServiceRoleToken`, `http.handle`, `Deno.serve`. The SIWA client-secret minting stays in the app. |
| | `web/src/lib/stripe.ts`: `mapStripeStatus`, `subscriptionPeriodEnd` (Node/Next, not Deno) | The canonical mapping documented here. Port the table into the web lib, or move the Stripe webhook to an edge function on `stripe.ts`. Migrate `in_billing_retry` → `grace` in SQL first. |
| **Celiador** (daemon, Node) | `daemon/src/push/apns.ts` (http2 + node:crypto) | `apns.ts` is its Deno port. The daemon stays on Node, so this is the reference implementation for Deno apps, not a drop-in replacement. |
| | `daemon/src/auth.ts` `safeEqual`, `account/routes.ts` `deleteViaGoTrue` (404 = success) | `auth.timingSafeEqual` and `account.deleteAuthUser` (same 404 rule) for edge-function apps |
| **Ariman** (Next.js) | `ariman-web/lib/apns.ts` (http2, ExpiredProviderToken retry), `lib/email.ts` (Resend) | `apns.ts` / `email.ts` are their Deno ports. Adopt them when Ariman moves this work to edge functions. |
| **Nassau** | no App Store verification at all | `appstore/` (new) |
| **Vivum** (new) | needs APNs + Resend (cliefden:8500) | `apns.ts`, `email.ts`, `http.ts`, `auth.ts` from day one |

## Deviations from the source code

- `statusFromTransaction`: a transaction without `expiresDate` (a non-consumable
  or lifetime unlock) is `active` until revoked. Contrarian only had
  subscriptions and returned `expired` here.
- `verifyNotification` also verifies the inner `signedTransactionInfo` and
  `signedRenewalInfo` and returns them as `transaction` and `renewalInfo`.
  Contrarian made separate `verifyInner*` calls.
- A Production notification with no configured `appAppleId` is refused with
  `app_apple_id_required`, as Apple's library does. Contrarian had the id
  hard-coded.
- `apns.isDeadToken` does not treat `DeviceTokenNotForTopic` as dead (Ariman
  did). That error usually means `APNS_TOPIC` is misconfigured, and pruning on
  it would delete every token.
- The default model is `claude-opus-5-5`. Stokked defaulted to Haiku 4.5 and
  Carpe Vitem to Sonnet 4; each app sets `AI_DEFAULT_MODEL` for its own cost
  profile.
