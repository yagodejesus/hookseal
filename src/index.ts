import {
  headerGetter,
  toBuffer,
  WebhookVerificationError,
  type HeaderBag,
  type Provider,
  type SignOptions,
  type VerifyOptions,
  type VerifyResult,
} from "./core.js";
import { PROVIDERS, type ProviderName } from "./providers.js";

export { hmacProvider, PROVIDERS } from "./providers.js";
export type { HmacConfig, ProviderName } from "./providers.js";
export { ReplayGuard } from "./replay.js";
export { WebhookVerificationError } from "./core.js";
export type { HeaderBag, Provider, SignOptions, VerifyOptions, VerifyResult } from "./core.js";
export const VERSION = "0.1.0";

function provider(p: ProviderName | Provider | string): Provider {
  if (typeof p !== "string") return p;
  const found = PROVIDERS[p.toLowerCase()];
  if (!found) throw new Error(`unknown provider "${p}". Known: ${Object.keys(PROVIDERS).join(", ")} — or use hmacProvider()`);
  return found;
}

/** Verifies a webhook signature. Never throws for bad input — check `result.valid` and `result.reason`. */
export function verify(p: ProviderName | Provider | string, opts: VerifyOptions): VerifyResult {
  const prov = provider(p);
  const secrets = (Array.isArray(opts.secret) ? opts.secret : [opts.secret]).filter(Boolean);
  if (!secrets.length) return { valid: false, provider: prov.name, reason: "no secret configured" };
  return prov.verify({
    body: toBuffer(opts.payload),
    header: headerGetter(opts.headers),
    secrets,
    tolerance: opts.tolerance ?? 300,
    now: opts.now ?? Date.now() / 1000,
    url: opts.url,
  });
}

/** Like `verify`, but throws `WebhookVerificationError` when the signature is not valid. */
export function verifyOrThrow(p: ProviderName | Provider | string, opts: VerifyOptions): VerifyResult {
  const r = verify(p, opts);
  if (!r.valid) throw new WebhookVerificationError(r);
  return r;
}

/**
 * Verifies a Fetch API `Request` (Next.js route handlers, Hono, Remix, Bun, Deno…).
 * Reads the body as text and returns it with the result, so you can parse it after verifying.
 */
export async function verifyRequest(
  p: ProviderName | Provider | string,
  request: Request,
  opts: Omit<VerifyOptions, "payload" | "headers" | "url"> & { url?: string },
): Promise<VerifyResult & { body: string }> {
  const body = await request.text();
  const result = verify(p, { ...opts, payload: body, headers: request.headers, url: opts.url ?? request.url });
  return { ...result, body };
}

/** Produces the headers a provider would send — for tests and local development. */
export function sign(p: ProviderName | Provider | string, opts: SignOptions): Record<string, string> {
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  return provider(p).sign({ ...opts, body: toBuffer(opts.payload), timestamp });
}

type Next = (err?: unknown) => void;
interface MinimalReq {
  body?: unknown;
  headers: HeaderBag;
  protocol?: string;
  originalUrl?: string;
  get?: (name: string) => string | undefined;
}

/**
 * Express/Connect middleware. Mount it after `express.raw({ type: "*\/*" })` so `req.body` is the raw Buffer.
 * Rejects with 401 when the signature is invalid; stores the result in `req.webhook`.
 */
export function middleware(p: ProviderName | Provider | string, opts: Omit<VerifyOptions, "payload" | "headers">) {
  return (req: MinimalReq & { webhook?: VerifyResult }, res: { status(code: number): { json(b: unknown): void } }, next: Next) => {
    if (!(req.body instanceof Uint8Array) && typeof req.body !== "string") {
      next(new Error("hookseal: req.body must be the raw body — use express.raw({ type: '*/*' }) before this middleware"));
      return;
    }
    const url = opts.url ?? (req.get && req.originalUrl ? `${req.protocol}://${req.get("host")}${req.originalUrl}` : undefined);
    const result = verify(p, { ...opts, url, payload: req.body as Uint8Array | string, headers: req.headers });
    if (!result.valid) {
      res.status(401).json({ error: "invalid webhook signature", reason: result.reason });
      return;
    }
    req.webhook = result;
    next();
  };
}
