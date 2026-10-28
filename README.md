<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="hookseal" width="400">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/yagodejesus/hookseal/actions/workflows/ci.yml"><img src="https://github.com/yagodejesus/hookseal/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/hookseal"><img src="https://img.shields.io/npm/v/hookseal.svg" alt="npm"></a>
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="zero dependencies">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT"></a>
</p>

**Verify webhook signatures from a dozen providers with one API.** Constant-time comparisons, timestamp tolerance against replays, key rotation, and zero dependencies.

> 🇧🇷 *Verifica a assinatura de webhooks do GitHub, Stripe, Slack, Shopify, Twilio, Discord e outros com uma única API — comparação em tempo constante, proteção contra replay e rotação de chaves.*

Every webhook endpoint must check that the request really came from the provider. Each provider signs differently — hex or base64, SHA-1 or SHA-256, with or without a timestamp, in a different header — and the classic bugs are always the same: comparing with `===` (timing attack), verifying re-serialized JSON instead of the raw body, forgetting the timestamp check (replay attack). `hookseal` gets them right once.

```ts
import { verify } from "hookseal";

const result = verify("stripe", {
  payload: rawBody,                 // the raw body — not JSON.stringify(req.body)
  headers: req.headers,             // Node headers, Fetch Headers or a Map
  secret: process.env.STRIPE_WEBHOOK_SECRET!,
});

if (!result.valid) return res.status(401).send(result.reason);   // "timestamp is too old (412s > 300s)"
```

## Providers

| Provider | Scheme |
|---|---|
| `github` | HMAC-SHA256 hex, `X-Hub-Signature-256` (+ delivery id) |
| `stripe` | HMAC-SHA256 of `t.body`, multiple `v1` signatures, 5-minute tolerance |
| `slack` | HMAC-SHA256 of `v0:ts:body`, `X-Slack-Signature` + timestamp |
| `shopify` | HMAC-SHA256 base64, `X-Shopify-Hmac-Sha256` (+ webhook id) |
| `standard` / `svix` | [Standard Webhooks](https://www.standardwebhooks.com): `webhook-*` or `svix-*` headers, `whsec_` secrets |
| `twilio` | HMAC-SHA1 of URL + sorted params, or `bodySHA256` for JSON |
| `discord` | Ed25519 of `timestamp + body` with your application's public key |
| `linear`, `paddle`, `zoom`, `intercom` | their HMAC schemes, with timestamps where the provider sends one |

Anything else that signs "an HMAC of the body (plus a timestamp)" takes four lines:

```ts
import { hmacProvider, verify } from "hookseal";

const acme = hmacProvider({ name: "acme", signatureHeader: "x-acme-signature", algorithm: "sha512", encoding: "base64", prefix: "sha512=" });
verify(acme, { payload, headers, secret });
```

## Frameworks

**Next.js (App Router), Hono, Remix, Bun, Deno** — anything with the Fetch API `Request`:

```ts
import { verifyRequest } from "hookseal";

export async function POST(request: Request) {
  const { valid, reason, body } = await verifyRequest("github", request, { secret: process.env.GITHUB_WEBHOOK_SECRET! });
  if (!valid) return new Response(reason, { status: 401 });
  const event = JSON.parse(body);
  // ...
}
```

**Express** — use the raw body:

```ts
import express from "express";
import { middleware } from "hookseal";

app.post("/webhooks/shopify", express.raw({ type: "*/*" }), middleware("shopify", { secret }), (req, res) => {
  const order = JSON.parse(req.body.toString());
  res.sendStatus(200);
});
```

## Replays, rotation and testing

```ts
import { ReplayGuard, sign, verify } from "hookseal";

const guard = new ReplayGuard(600);                        // remembers delivery ids for 10 minutes
const r = verify("standard", { payload, headers, secret: [newSecret, oldSecret] });   // rotation: any secret may match
if (r.valid && r.id && guard.check(r.id)) return;          // already processed

// In your tests: produce exactly the headers the provider would send
const headers = sign("stripe", { payload: '{"id":"evt_1"}', secret: "whsec_test" });
```

`verify()` never throws on bad input — it returns `{ valid, reason, timestamp, id }`. Use `verifyOrThrow()` if you prefer exceptions.

## Install

```bash
npm install hookseal
```

ESM, Node ≥ 20 (also Bun and Deno). Uses only `node:crypto`.

## Development

```bash
git clone https://github.com/yagodejesus/hookseal && cd hookseal
npm install
npm test
```

The test suite includes GitHub's published test vector and round trips, tampering, wrong secrets, expired timestamps and malformed headers for every provider.

## License

MIT © Yago de Jesus Martins
