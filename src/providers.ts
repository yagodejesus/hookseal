import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

import { checkTimestamp, decode, fail, hmac, ok, safeEqual, sha256Hex, type Context, type Provider, type VerifyResult } from "./core.js";

type Algorithm = "sha1" | "sha256" | "sha512";

export interface HmacConfig {
  name: string;
  /** Header that carries the signature. */
  signatureHeader: string;
  algorithm?: Algorithm;
  encoding?: "hex" | "base64";
  /** Prefix before the signature, e.g. "sha256=" or "v0=". */
  prefix?: string;
  /** Header with a Unix timestamp that is part of the signed content. */
  timestampHeader?: string;
  /** Builds the signed content. Default: the raw body. */
  content?: (body: Buffer, timestamp: string | undefined) => Buffer | string;
  idHeader?: string;
}

/** Build a verifier for any "HMAC of the body (+ timestamp)" scheme. */
export function hmacProvider(cfg: HmacConfig): Provider {
  const alg = cfg.algorithm ?? "sha256";
  const enc = cfg.encoding ?? "hex";
  const prefix = cfg.prefix ?? "";
  const content = cfg.content ?? ((body: Buffer) => body);
  return {
    name: cfg.name,
    verify(ctx) {
      const raw = ctx.header(cfg.signatureHeader);
      const id = cfg.idHeader ? ctx.header(cfg.idHeader) : undefined;
      if (!raw) return fail(cfg.name, `missing ${cfg.signatureHeader} header`);
      let timestamp: number | undefined;
      let tsRaw: string | undefined;
      if (cfg.timestampHeader) {
        tsRaw = ctx.header(cfg.timestampHeader);
        if (!tsRaw) return fail(cfg.name, `missing ${cfg.timestampHeader} header`);
        timestamp = Number(tsRaw);
        const bad = checkTimestamp(timestamp, ctx);
        if (bad) return fail(cfg.name, bad, { timestamp, id });
      }
      const candidates = raw.split(",").map((s) => s.trim()).filter((s) => !prefix || s.startsWith(prefix));
      const sigs = candidates.map((s) => decode(s.slice(prefix.length), enc)).filter((b): b is Buffer => b !== null);
      if (!sigs.length) return fail(cfg.name, `malformed ${cfg.signatureHeader} header`, { timestamp, id });
      const data = content(ctx.body, tsRaw);
      for (const secret of ctx.secrets) {
        const expected = hmac(alg, secret, data);
        if (sigs.some((s) => safeEqual(s, expected))) return ok(cfg.name, { timestamp, id });
      }
      return fail(cfg.name, "signature mismatch", { timestamp, id });
    },
    sign({ body, secret, timestamp }) {
      const ts = String(timestamp);
      const sig = hmac(alg, secret, content(body, cfg.timestampHeader ? ts : undefined)).toString(enc);
      const headers: Record<string, string> = { [cfg.signatureHeader]: prefix + sig };
      if (cfg.timestampHeader) headers[cfg.timestampHeader] = ts;
      return headers;
    },
  };
}

const github = hmacProvider({
  name: "github",
  signatureHeader: "x-hub-signature-256",
  prefix: "sha256=",
  idHeader: "x-github-delivery",
});

const slack = hmacProvider({
  name: "slack",
  signatureHeader: "x-slack-signature",
  prefix: "v0=",
  timestampHeader: "x-slack-request-timestamp",
  content: (body, ts) => Buffer.concat([Buffer.from(`v0:${ts}:`), body]),
});

const zoom = hmacProvider({
  name: "zoom",
  signatureHeader: "x-zm-signature",
  prefix: "v0=",
  timestampHeader: "x-zm-request-timestamp",
  content: (body, ts) => Buffer.concat([Buffer.from(`v0:${ts}:`), body]),
});

const shopify = hmacProvider({
  name: "shopify",
  signatureHeader: "x-shopify-hmac-sha256",
  encoding: "base64",
  idHeader: "x-shopify-webhook-id",
});

const intercom = hmacProvider({ name: "intercom", signatureHeader: "x-hub-signature", algorithm: "sha1", prefix: "sha1=" });

const linearBase = hmacProvider({ name: "linear", signatureHeader: "linear-signature", idHeader: "linear-delivery" });
const linear: Provider = {
  ...linearBase,
  verify(ctx) {
    const r = linearBase.verify(ctx);
    if (!r.valid) return r;
    try {
      const ms = JSON.parse(ctx.body.toString("utf8")).webhookTimestamp;
      if (typeof ms === "number") {
        const bad = checkTimestamp(ms / 1000, ctx);
        if (bad) return fail("linear", bad, { timestamp: ms / 1000, id: r.id });
        return { ...r, timestamp: ms / 1000 };
      }
    } catch {
      /* body is not JSON: signature already verified */
    }
    return r;
  },
};

/** Parses "t=1,v1=a,v1=b" (Stripe) or "ts=1;h1=a" (Paddle). */
function parsePairs(header: string, sep: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of header.split(sep)) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    out.set(k, [...(out.get(k) ?? []), part.slice(i + 1).trim()]);
  }
  return out;
}

function timestampedHex(
  name: string,
  header: string,
  sep: string,
  tsKey: string,
  sigKey: string,
  join: string,
): Provider {
  return {
    name,
    verify(ctx) {
      const raw = ctx.header(header);
      if (!raw) return fail(name, `missing ${header} header`);
      const pairs = parsePairs(raw, sep);
      const timestamp = Number(pairs.get(tsKey)?.[0]);
      const sigs = (pairs.get(sigKey) ?? []).map((s) => decode(s, "hex")).filter((b): b is Buffer => b !== null);
      if (!pairs.has(tsKey) || !sigs.length) return fail(name, `malformed ${header} header`);
      const bad = checkTimestamp(timestamp, ctx);
      if (bad) return fail(name, bad, { timestamp });
      const data = Buffer.concat([Buffer.from(`${pairs.get(tsKey)![0]}${join}`), ctx.body]);
      for (const secret of ctx.secrets) {
        const expected = hmac("sha256", secret, data);
        if (sigs.some((s) => safeEqual(s, expected))) return ok(name, { timestamp });
      }
      return fail(name, "signature mismatch", { timestamp });
    },
    sign({ body, secret, timestamp }) {
      const sig = hmac("sha256", secret, Buffer.concat([Buffer.from(`${timestamp}${join}`), body])).toString("hex");
      return { [header]: `${tsKey}=${timestamp}${sep}${sigKey}=${sig}` };
    },
  };
}

const stripe = timestampedHex("stripe", "stripe-signature", ",", "t", "v1", ".");
const paddle = timestampedHex("paddle", "paddle-signature", ";", "ts", "h1", ":");

function standardKey(secret: string): Buffer {
  return Buffer.from(secret.startsWith("whsec_") ? secret.slice(6) : secret, "base64");
}

/** Standard Webhooks (https://www.standardwebhooks.com) — used by Svix and the many services built on it. */
const standard: Provider = {
  name: "standard",
  verify(ctx) {
    const pick = (n: string) => ctx.header(`webhook-${n}`) ?? ctx.header(`svix-${n}`);
    const id = pick("id");
    const ts = pick("timestamp");
    const sigHeader = pick("signature");
    if (!id || !ts || !sigHeader) return fail("standard", "missing webhook-id, webhook-timestamp or webhook-signature header");
    const timestamp = Number(ts);
    const bad = checkTimestamp(timestamp, ctx);
    if (bad) return fail("standard", bad, { timestamp, id });
    const sigs = sigHeader
      .split(" ")
      .map((s) => s.split(","))
      .filter(([v]) => v === "v1")
      .map(([, sig]) => decode(sig ?? "", "base64"))
      .filter((b): b is Buffer => b !== null);
    if (!sigs.length) return fail("standard", "no v1 signature in webhook-signature", { timestamp, id });
    const data = Buffer.concat([Buffer.from(`${id}.${ts}.`), ctx.body]);
    for (const secret of ctx.secrets) {
      const expected = hmac("sha256", standardKey(secret), data);
      if (sigs.some((s) => safeEqual(s, expected))) return ok("standard", { timestamp, id });
    }
    return fail("standard", "signature mismatch", { timestamp, id });
  },
  sign({ body, secret, timestamp, id }) {
    const msgId = id ?? `msg_${timestamp}`;
    const sig = hmac("sha256", standardKey(secret), Buffer.concat([Buffer.from(`${msgId}.${timestamp}.`), body])).toString("base64");
    return { "webhook-id": msgId, "webhook-timestamp": String(timestamp), "webhook-signature": `v1,${sig}` };
  },
};

function twilioData(url: string, body: Buffer): { data: string; bodyHash?: string } {
  const u = new URL(url);
  const bodyHash = u.searchParams.get("bodySHA256") ?? undefined;
  if (bodyHash !== undefined) return { data: url, bodyHash };
  const params = new URLSearchParams(body.toString("utf8"));
  const keys = [...new Set(params.keys())].sort();
  let data = url;
  for (const k of keys) for (const v of params.getAll(k).sort()) data += k + v;
  return { data };
}

/** Twilio: HMAC-SHA1 of the URL plus the sorted POST parameters (or of the URL with ?bodySHA256 for JSON). */
const twilio: Provider = {
  name: "twilio",
  verify(ctx) {
    const raw = ctx.header("x-twilio-signature");
    if (!raw) return fail("twilio", "missing x-twilio-signature header");
    if (!ctx.url) return fail("twilio", "Twilio signatures need the full request URL (pass `url`)");
    const sig = decode(raw, "base64");
    if (!sig) return fail("twilio", "malformed x-twilio-signature header");
    const { data, bodyHash } = twilioData(ctx.url, ctx.body);
    if (bodyHash !== undefined && bodyHash !== sha256Hex(ctx.body)) return fail("twilio", "body does not match bodySHA256");
    for (const secret of ctx.secrets) if (safeEqual(sig, hmac("sha1", secret, data))) return ok("twilio");
    return fail("twilio", "signature mismatch");
  },
  sign({ body, secret, url }) {
    if (!url) throw new Error("twilio signing needs `url`");
    return { "x-twilio-signature": hmac("sha1", secret, twilioData(url, body).data).toString("base64") };
  },
};

function discordKey(secret: string): KeyObject {
  if (secret.includes("BEGIN")) return createPublicKey(secret);
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(secret, "hex").toString("base64url") }, format: "jwk" });
}

/** Discord interactions: Ed25519 signature of timestamp + body. The "secret" is your application's public key (hex). */
const discord: Provider = {
  name: "discord",
  verify(ctx) {
    const sigHex = ctx.header("x-signature-ed25519");
    const ts = ctx.header("x-signature-timestamp");
    if (!sigHex || !ts) return fail("discord", "missing x-signature-ed25519 or x-signature-timestamp header");
    const sig = decode(sigHex, "hex");
    if (!sig || sig.length !== 64) return fail("discord", "malformed x-signature-ed25519 header");
    const timestamp = Number(ts);
    const bad = checkTimestamp(timestamp, ctx);
    if (bad) return fail("discord", bad, { timestamp });
    const msg = Buffer.concat([Buffer.from(ts), ctx.body]);
    for (const secret of ctx.secrets) {
      try {
        if (edVerify(null, msg, discordKey(secret), sig)) return ok("discord", { timestamp });
      } catch {
        return fail("discord", "invalid public key");
      }
    }
    return fail("discord", "signature mismatch", { timestamp });
  },
  sign({ body, secret, timestamp }) {
    const sig = edSign(null, Buffer.concat([Buffer.from(String(timestamp)), body]), createPrivateKey(secret)).toString("hex");
    return { "x-signature-ed25519": sig, "x-signature-timestamp": String(timestamp) };
  },
};

export const PROVIDERS: Record<string, Provider> = {
  github, stripe, slack, shopify, standard, svix: { ...standard, name: "svix" }, linear, paddle, zoom, intercom, twilio, discord,
};

export type ProviderName = keyof typeof PROVIDERS;
export type { VerifyResult, Context };
