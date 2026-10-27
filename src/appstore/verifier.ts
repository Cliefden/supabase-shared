// App Store claims checks on top of the WebCrypto JWS verifier, generalized
// from Contrarian's _shared/appstore.ts (where BUNDLE_ID / APP_APPLE_ID were
// hard-coded). Never regress to decoding a JWS without verifying it: an old
// Contrarian function did, and any signed-in user could self-grant Plus.
//
//   const appstore = createAppStoreVerifier({
//     bundleIds: ["com.crawik.contria"],
//     appAppleId: 6785219877,
//   });
//   const { txn, environment } = await appstore.verifyTransaction(jws);

import { AppleJWSError, verifyAppleJWS } from "./jws.ts";

export type AppleEnvironment = "Production" | "Sandbox";

/** The decoded transaction fields backends read (Apple's full shape is larger). */
export interface JWSTransactionDecodedPayload {
  transactionId?: string;
  originalTransactionId?: string;
  bundleId?: string;
  productId?: string;
  purchaseDate?: number;
  originalPurchaseDate?: number;
  expiresDate?: number;
  revocationDate?: number;
  revocationReason?: number;
  appAccountToken?: string;
  environment?: string;
  type?: string;
  quantity?: number;
  signedDate?: number;
  [key: string]: unknown;
}

export interface JWSRenewalInfoDecodedPayload {
  originalTransactionId?: string;
  autoRenewProductId?: string;
  autoRenewStatus?: number;
  gracePeriodExpiresDate?: number;
  isInBillingRetryPeriod?: boolean;
  expirationIntent?: number;
  environment?: string;
  signedDate?: number;
  [key: string]: unknown;
}

export interface NotificationData {
  appAppleId?: number;
  bundleId?: string;
  environment?: string;
  signedTransactionInfo?: string;
  signedRenewalInfo?: string;
  status?: number;
}

export interface ResponseBodyV2DecodedPayload {
  notificationType?: string;
  subtype?: string;
  notificationUUID?: string;
  data?: NotificationData;
  summary?: { appAppleId?: number; bundleId?: string; environment?: string };
  signedDate?: number;
  [key: string]: unknown;
}

export interface AppStoreVerifierOptions {
  /** Accepted bundle ids (e.g. the iOS + macOS variants). At least one. */
  bundleIds: string[];
  /**
   * Numeric App Apple ID. Production notifications must carry it; without it
   * configured, Production notifications are refused (`app_apple_id_required`)
   * — the same rule Apple's library enforces. Sandbox may omit it.
   */
  appAppleId?: number;
  /**
   * Accept Sandbox (TestFlight / App Review / sandbox testers). Default true:
   * TestFlight purchases run in sandbox. Record the environment in your audit
   * trail; gate it per account if sandbox must not grant real entitlement.
   */
  allowSandbox?: boolean;
}

export interface VerifiedNotification {
  payload: ResponseBodyV2DecodedPayload;
  environment: AppleEnvironment;
  /** The verified inner signedTransactionInfo, when the notification has one. */
  transaction?: JWSTransactionDecodedPayload;
  /** The verified inner signedRenewalInfo, when the notification has one. */
  renewalInfo?: JWSRenewalInfoDecodedPayload;
}

export interface AppStoreVerifier {
  readonly bundleIds: readonly string[];
  /** Verify a StoreKit 2 transaction JWS (client-submitted, or a notification's inner one). */
  verifyTransaction(
    jws: string,
    expected?: AppleEnvironment,
  ): Promise<{ txn: JWSTransactionDecodedPayload; environment: AppleEnvironment }>;
  /**
   * Verify an App Store Server Notification V2 `signedPayload`, plus its inner
   * transaction / renewal info (same environment as the outer payload).
   */
  verifyNotification(signedPayload: string): Promise<VerifiedNotification>;
  /** Verify a signed renewal info JWS (must match `expected` when given). */
  verifyRenewalInfo(jws: string, expected?: AppleEnvironment): Promise<JWSRenewalInfoDecodedPayload>;
}

function asEnvironment(value: unknown): AppleEnvironment {
  if (value === "Production" || value === "Sandbox") return value;
  // "Xcode" (local StoreKit config) and "LocalTesting" land here too: those
  // are locally signed and would fail the chain anyway.
  throw new AppleJWSError("invalid_environment");
}

export function createAppStoreVerifier(opts: AppStoreVerifierOptions): AppStoreVerifier {
  const bundleIds = [...new Set(opts.bundleIds.map((b) => b.trim()).filter(Boolean))];
  if (bundleIds.length === 0) throw new Error("createAppStoreVerifier: bundleIds is empty");
  const allowSandbox = opts.allowSandbox ?? true;
  const appAppleId = opts.appAppleId;

  function checkEnvironment(value: unknown, expected?: AppleEnvironment): AppleEnvironment {
    const environment = asEnvironment(value);
    if (expected && environment !== expected) throw new AppleJWSError("environment_mismatch");
    if (environment === "Sandbox" && !allowSandbox) throw new AppleJWSError("sandbox_not_allowed");
    return environment;
  }

  async function verifyTransaction(jws: string, expected?: AppleEnvironment) {
    const txn = await verifyAppleJWS<JWSTransactionDecodedPayload>(jws);
    if (!txn.bundleId || !bundleIds.includes(txn.bundleId)) throw new AppleJWSError("invalid_bundle_id");
    return { txn, environment: checkEnvironment(txn.environment, expected) };
  }

  async function verifyRenewalInfo(jws: string, expected?: AppleEnvironment) {
    const info = await verifyAppleJWS<JWSRenewalInfoDecodedPayload>(jws);
    checkEnvironment(info.environment, expected);
    return info;
  }

  async function verifyNotification(signedPayload: string): Promise<VerifiedNotification> {
    const payload = await verifyAppleJWS<ResponseBodyV2DecodedPayload>(signedPayload);
    // External-purchase-token notifications carry neither; refuse them.
    const scope = payload.data ?? payload.summary;
    if (!scope) throw new AppleJWSError("unsupported_notification_shape");
    if (!scope.bundleId || !bundleIds.includes(scope.bundleId)) {
      throw new AppleJWSError("invalid_bundle_id");
    }
    const environment = checkEnvironment(scope.environment);
    // Sandbox notifications may omit the App Apple ID; production ones must match.
    if (environment === "Production") {
      if (appAppleId === undefined) throw new AppleJWSError("app_apple_id_required");
      if (scope.appAppleId !== appAppleId) throw new AppleJWSError("invalid_app_apple_id");
    }
    const result: VerifiedNotification = { payload, environment };
    const data = payload.data;
    if (data?.signedTransactionInfo) {
      result.transaction = (await verifyTransaction(data.signedTransactionInfo, environment)).txn;
    }
    if (data?.signedRenewalInfo) {
      result.renewalInfo = await verifyRenewalInfo(data.signedRenewalInfo, environment);
    }
    return result;
  }

  return { bundleIds, verifyTransaction, verifyNotification, verifyRenewalInfo };
}

/** Entitlement status vocabulary shared with stripe.ts (`mapStripeStatus`). */
export type AppleSubscriptionStatus = "active" | "grace" | "expired";

/**
 * Derive status from the verified transaction itself (not the notification
 * type), so duplicate deliveries converge to the same row. Out-of-order
 * deliveries need a staleness guard in the app's upsert (compare period ends
 * for the same originalTransactionId — see Contrarian's convergeAppleSubscription).
 *
 * The verify path has no renewal info, so a purchase restored mid-grace maps
 * to expired instead of grace; the next server notification corrects it.
 * Non-expiring products (lifetime unlocks) are `active` until revoked.
 */
export function statusFromTransaction(
  txn: JWSTransactionDecodedPayload,
  renewalInfo?: JWSRenewalInfoDecodedPayload,
  now: number = Date.now(),
): { status: AppleSubscriptionStatus; periodEnd: string | null } {
  if (txn.revocationDate) {
    // REFUND / REVOKE: entitlement ends at revocation.
    return { status: "expired", periodEnd: new Date(txn.revocationDate).toISOString() };
  }
  if (!txn.expiresDate) return { status: "active", periodEnd: null };
  if (txn.expiresDate > now) {
    return { status: "active", periodEnd: new Date(txn.expiresDate).toISOString() };
  }
  const grace = renewalInfo?.gracePeriodExpiresDate;
  if (grace && grace > now) {
    return { status: "grace", periodEnd: new Date(grace).toISOString() };
  }
  return { status: "expired", periodEnd: new Date(txn.expiresDate).toISOString() };
}
