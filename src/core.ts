import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export type HeaderBag = Headers | Record<string, string | string[] | undefined> | Map<string, string>;

export interface VerifyOptions {
  /** The raw request body, exactly as received (never re-serialized JSON). */
  payload: string | Uint8Array;
  headers: HeaderBag;
  /** Signing secret. Pass several to support key rotation. */
  secret: string | string[];
  /** Maximum age of the signed timestamp, in seconds (default 300). */
  tolerance?: number;
  /** Current time in Unix seconds (for tests). */
  now?: number;
  /** Full request URL — required by Twilio. */
  url?: string;
}

export interface VerifyResult {
  valid: boolean;
  provider: string;
  reason?: string;
  /** Signed timestamp (Unix seconds), when the provider sends one. */
  timestamp?: number;
  /** Delivery / message id, when the provider sends one — use it for replay protection. */
  id?: string;
}

export interface SignOptions {
  payload: string | Uint8Array;
  secret: string;
  timestamp?: number;
  id?: string;
  url?: string;
}

export interface Context {
  body: Buffer;
  header(name: string): string | undefined;
  secrets: string[];
  tolerance: number;
  now: number;
  url?: string;
}

export interface Provider {
  name: string;
  verify(ctx: Context): VerifyResult;
  sign(opts: SignOptions & { body: Buffer; timestamp: number }): Record<string, string>;
}

export class WebhookVerificationError extends Error {
  constructor(public readonly result: VerifyResult) {
    super(`${result.provider} webhook rejected: ${result.reason}`);
    this.name = "WebhookVerificationError";
  }
}

export const toBuffer = (p: string | Uint8Array): Buffer => (typeof p === "string" ? Buffer.from(p, "utf8") : Buffer.from(p));

export function headerGetter(bag: HeaderBag): (name: string) => string | undefined {
  if (typeof (bag as Headers).get === "function") {
    const h = bag as Headers | Map<string, string>;
    return (name) => {
      if (h instanceof Map) {
        for (const [k, v] of h) if (k.toLowerCase() === name.toLowerCase()) return v;
        return undefined;
      }
      return h.get(name) ?? undefined;
    };
  }
  const lower = new Map<string, string>();
  for (const [k, v] of Object.entries(bag as Record<string, string | string[] | undefined>)) {
    if (v !== undefined) lower.set(k.toLowerCase(), Array.isArray(v) ? v.join(",") : v);
  }
  return (name) => lower.get(name.toLowerCase());
}

export const hmac = (algorithm: string, key: string | Buffer, data: string | Buffer): Buffer =>
  createHmac(algorithm, key).update(data).digest();

export const sha256Hex = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");

/** Constant-time comparison of two signatures. */
export function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

export function decode(value: string, encoding: "hex" | "base64"): Buffer | null {
  const v = value.trim();
  if (encoding === "hex") return /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0 ? Buffer.from(v, "hex") : null;
  return /^[A-Za-z0-9+/_-]+={0,2}$/.test(v) ? Buffer.from(v, "base64") : null;
}

export function checkTimestamp(ts: number, ctx: Context): string | undefined {
  if (!Number.isFinite(ts)) return "invalid timestamp";
  const age = ctx.now - ts;
  if (Math.abs(age) > ctx.tolerance) {
    return age > 0 ? `timestamp is too old (${Math.round(age)}s > ${ctx.tolerance}s)` : `timestamp is in the future (${Math.round(-age)}s)`;
  }
  return undefined;
}

export const ok = (provider: string, extra: Partial<VerifyResult> = {}): VerifyResult => ({ valid: true, provider, ...extra });
export const fail = (provider: string, reason: string, extra: Partial<VerifyResult> = {}): VerifyResult => ({
  valid: false,
  provider,
  reason,
  ...extra,
});
