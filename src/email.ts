// Outbound email via the Resend REST API (port of Ariman lib/email.ts).
//
// Env:
//   RESEND_API_KEY  the API key
//   EMAIL_FROM      sender, e.g. "Vivum <noreply@example.com>". Until a domain
//                   is verified in Resend, onboarding@resend.dev only delivers
//                   to the account owner — canEmailPublic() gates user-facing sends.

export interface SendEmailOptions {
  to: string | string[];
  subject: string;
  text: string;
  html?: string;
  /** Resend dedupes sends with the same key for 24h — use for retried jobs. */
  idempotencyKey?: string;
  /** Override EMAIL_FROM. */
  from?: string;
  replyTo?: string | string[];
  tags?: Array<{ name: string; value: string }>;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

export type SendEmailResult =
  | { ok: true; id?: string }
  | { ok: false; status: number; error: string };

const env = (k: string) => Deno.env.get(k)?.trim() || "";

export function emailConfigured(): boolean {
  return Boolean(env("RESEND_API_KEY") && env("EMAIL_FROM"));
}

/** Configured with a real (non resend.dev) sender. */
export function canEmailPublic(): boolean {
  return emailConfigured() && !env("EMAIL_FROM").includes("resend.dev");
}

/** Send one email. Never throws; failures are logged and returned. */
export async function sendEmail(opts: SendEmailOptions): Promise<SendEmailResult> {
  const apiKey = env("RESEND_API_KEY");
  const from = opts.from ?? env("EMAIL_FROM");
  if (!apiKey || !from) return { ok: false, status: 0, error: "not_configured" };

  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  };
  if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;

  const body: Record<string, unknown> = {
    from,
    to: Array.isArray(opts.to) ? opts.to : [opts.to],
    subject: opts.subject,
    text: opts.text,
  };
  if (opts.html) body.html = opts.html;
  if (opts.replyTo) body.reply_to = opts.replyTo;
  if (opts.tags) body.tags = opts.tags;

  try {
    const res = await (opts.fetch ?? fetch)("https://api.resend.com/emails", {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    const textBody = await res.text().catch(() => "");
    if (!res.ok) {
      console.error("send_email_failed", res.status, textBody.slice(0, 300));
      return { ok: false, status: res.status, error: textBody.slice(0, 300) || `HTTP ${res.status}` };
    }
    let id: string | undefined;
    try {
      id = JSON.parse(textBody).id;
    } catch { /* no body */ }
    return { ok: true, id };
  } catch (err) {
    console.error("send_email_failed", String(err));
    return { ok: false, status: 0, error: String(err) };
  }
}
