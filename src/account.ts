// Self-serve account deletion (App Store guideline 5.1.1(v); GoTrue has no
// user-facing delete endpoint). Generalizes Carpe Vitem's delete-account
// (recursive storage purge) and Contrarian's (Stripe first, then the auth
// user), with Celiador's "404 = already gone" rule.
//
// Order matters: the hook runs first (e.g. cancel Stripe — a still-working
// account beats orphaned billing), then storage, then the auth.users row
// (every user-owned table should cascade from it).

import type { User } from "jsr:@supabase/supabase-js@2";
import { type AnyClient, requireUser, type RequireUserOptions } from "./auth.ts";
import { HttpError } from "./http.ts";

const LIST_PAGE = 1000;
const REMOVE_BATCH = 100;

/** Recursively collect every object path under `prefix` in `bucket`. */
export async function listAllPaths(
  service: AnyClient,
  bucket: string,
  prefix: string,
): Promise<string[]> {
  const paths: string[] = [];
  let offset = 0;
  while (true) {
    const { data, error } = await service.storage.from(bucket).list(prefix, {
      limit: LIST_PAGE,
      offset,
    });
    if (error) throw error;
    if (!data || data.length === 0) break;
    for (const item of data) {
      const fullPath = prefix ? `${prefix}/${item.name}` : item.name;
      // Folders have no id in the storage list API.
      if (item.id === null || item.id === undefined) {
        paths.push(...(await listAllPaths(service, bucket, fullPath)));
      } else {
        paths.push(fullPath);
      }
    }
    if (data.length < LIST_PAGE) break;
    offset += LIST_PAGE;
  }
  return paths;
}

/**
 * Delete every object under `<userId>/` in `bucket` (the portfolio's storage
 * layout convention). Returns the number of objects removed; throws on error.
 */
export async function purgeUserStorage(
  service: AnyClient,
  bucket: string,
  userId: string,
): Promise<number> {
  if (!userId || userId.includes("/") || userId.includes("..")) {
    throw new Error("purgeUserStorage: refusing an unsafe user id prefix");
  }
  const paths = await listAllPaths(service, bucket, userId);
  for (let i = 0; i < paths.length; i += REMOVE_BATCH) {
    const { error } = await service.storage.from(bucket).remove(paths.slice(i, i + REMOVE_BATCH));
    if (error) throw error;
  }
  return paths.length;
}

/** Delete the auth.users row via the admin API. A 404 (already gone) counts as success. */
export async function deleteAuthUser(service: AnyClient, userId: string): Promise<void> {
  const { error } = await service.auth.admin.deleteUser(userId);
  if (!error) return;
  const status = (error as { status?: number }).status;
  if (status === 404 || /not.?found/i.test(error.message ?? "")) return;
  throw error;
}

export interface DeleteAccountContext {
  user: User;
  userId: string;
  userClient: AnyClient;
  serviceClient: AnyClient;
}

export interface DeleteAccountOptions extends RequireUserOptions {
  req: Request;
  /** Storage buckets whose `<userId>/` prefix is purged. */
  buckets?: string[];
  /**
   * Runs before anything is deleted (cancel Stripe, revoke Sign in with Apple,
   * delete rows that don't cascade…). Throw — ideally an HttpError — to abort.
   */
  beforeDelete?: (ctx: DeleteAccountContext) => Promise<void> | void;
}

export interface DeleteAccountResult {
  userId: string;
  /** Objects removed per bucket. */
  removed: Record<string, number>;
}

/**
 * Require the caller, run the hook, purge storage, delete the auth user.
 * Throws HttpError (401 from requireUser, 500 `storage_delete_failed` /
 * `delete_failed`); wrap in `handle()`.
 */
export async function deleteAccount(opts: DeleteAccountOptions): Promise<DeleteAccountResult> {
  const { user, userId, userClient, serviceClient } = await requireUser(opts.req, opts);
  const ctx: DeleteAccountContext = { user, userId, userClient, serviceClient };

  if (opts.beforeDelete) await opts.beforeDelete(ctx);

  const removed: Record<string, number> = {};
  for (const bucket of opts.buckets ?? []) {
    try {
      removed[bucket] = await purgeUserStorage(serviceClient, bucket, userId);
    } catch (err) {
      console.error("delete_account_storage_failed", bucket, userId, err);
      throw new HttpError(500, "storage_delete_failed");
    }
  }

  try {
    await deleteAuthUser(serviceClient, userId);
  } catch (err) {
    console.error("delete_account_failed", userId, err);
    throw new HttpError(500, "delete_failed");
  }
  return { userId, removed };
}
