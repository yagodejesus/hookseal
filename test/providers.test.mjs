import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";

import { hmacProvider, PROVIDERS, sign, verify, verifyOrThrow, WebhookVerificationError } from "../dist/index.js";

const NOW = 1_800_000_000;
const body = JSON.stringify({ id: "evt_1", type: "invoice.paid", amount: 4200 });
const SIMPLE = ["github", "stripe", "slack", "shopify", "linear", "paddle", "zoom", "intercom"];

test("round trip for every HMAC provider", () => {
  for (const p of SIMPLE) {
    const headers = sign(p, { payload: body, secret: "s3cret", timestamp: NOW });
    const r = verify(p, { payload: body, headers, secret: "s3cret", now: NOW + 10 });
    assert.equal(r.valid, true, `${p}: ${r.reason}`);
  }
});

test("tampered body, wrong secret and missing headers are rejected", () => {
  for (const p of SIMPLE) {
    const headers = sign(p, { payload: body, secret: "s3cret", timestamp: NOW });
    assert.equal(verify(p, { payload: body + " ", headers, secret: "s3cret", now: NOW }).reason, "signature mismatch");
    assert.equal(verify(p, { payload: body, headers, secret: "other", now: NOW }).valid, false);
    assert.match(verify(p, { payload: body, headers: {}, secret: "s3cret", now: NOW }).reason, /missing/);
  }
});

test("GitHub documentation test vector", () => {
  const r = verify("github", {
    payload: "Hello, World!",
    headers: { "X-Hub-Signature-256": "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17" },
    secret: "It's a Secret to Everybody",
  });
  assert.equal(r.valid, true);
});

test("timestamps outside the tolerance are rejected (replay window)", () => {
  for (const p of ["stripe", "slack", "paddle", "zoom", "standard"]) {
    const headers = sign(p, { payload: body, secret: "whsec_c2VjcmV0", timestamp: NOW });
    const old = verify(p, { payload: body, headers, secret: "whsec_c2VjcmV0", now: NOW + 301 });
    assert.match(old.reason, /too old/, p);
    assert.equal(verify(p, { payload: body, headers, secret: "whsec_c2VjcmV0", now: NOW + 301, tolerance: 600 }).valid, true);
  }
});

test("Stripe header with several v1 signatures (secret rotation on Stripe's side)", () => {
  const sig = createHmac("sha256", "new").update(`${NOW}.${body}`).digest("hex");
  const headers = { "stripe-signature": `t=${NOW},v1=${"0".repeat(64)},v1=${sig},v0=deadbeef` };
  assert.equal(verify("stripe", { payload: body, headers, secret: "new", now: NOW }).valid, true);
});

test("secret rotation on your side: any configured secret works", () => {
  const headers = sign("github", { payload: body, secret: "old" });
  assert.equal(verify("github", { payload: body, headers, secret: ["new", "old"] }).valid, true);
});

test("Standard Webhooks / Svix, including svix-* headers and id", () => {
  const secret = "whsec_" + Buffer.from("a-very-secret-key").toString("base64");
  const h = sign("standard", { payload: body, secret, timestamp: NOW, id: "msg_123" });
  const r = verify("standard", { payload: body, headers: h, secret, now: NOW });
  assert.deepEqual([r.valid, r.id, r.timestamp], [true, "msg_123", NOW]);
  const svix = { "svix-id": h["webhook-id"], "svix-timestamp": h["webhook-timestamp"], "svix-signature": `v1,${"A".repeat(44)} ${h["webhook-signature"]}` };
  assert.equal(verify("svix", { payload: body, headers: svix, secret, now: NOW }).valid, true);
});

test("headers: Fetch Headers, Map and arrays, case-insensitive", () => {
  const h = sign("slack", { payload: body, secret: "k", timestamp: NOW });
  const fetchHeaders = new Headers({ "X-Slack-Signature": h["x-slack-signature"], "X-Slack-Request-Timestamp": h["x-slack-request-timestamp"] });
  assert.equal(verify("slack", { payload: body, headers: fetchHeaders, secret: "k", now: NOW }).valid, true);
  const map = new Map(Object.entries(h));
  assert.equal(verify("slack", { payload: Buffer.from(body), headers: map, secret: "k", now: NOW }).valid, true);
  const gh = sign("github", { payload: body, secret: "k" });
  assert.equal(verify("github", { payload: body, headers: { "X-HUB-SIGNATURE-256": [gh["x-hub-signature-256"]] }, secret: "k" }).valid, true);
});

test("Twilio form posts and JSON bodies with bodySHA256", () => {
  const url = "https://example.com/sms?tenant=7";
  const form = "To=%2B15551234567&Body=Hello&From=%2B15557654321";
  const h = sign("twilio", { payload: form, secret: "authtoken", url });
  assert.equal(verify("twilio", { payload: form, headers: h, secret: "authtoken", url }).valid, true);
  assert.equal(verify("twilio", { payload: form.replace("Hello", "Hi"), headers: h, secret: "authtoken", url }).valid, false);
  assert.match(verify("twilio", { payload: form, headers: h, secret: "authtoken" }).reason, /URL/);
});

test("Twilio JSON webhooks", async () => {
  const { createHash } = await import("node:crypto");
  const json = '{"a":1}';
  const url = `https://example.com/hook?bodySHA256=${createHash("sha256").update(json).digest("hex")}`;
  const h = sign("twilio", { payload: json, secret: "tok", url });
  assert.equal(verify("twilio", { payload: json, headers: h, secret: "tok", url }).valid, true);
  assert.equal(verify("twilio", { payload: '{"a":2}', headers: h, secret: "tok", url }).reason, "body does not match bodySHA256");
});

test("Discord Ed25519 interactions", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubHex = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("hex");
  const priv = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const h = sign("discord", { payload: body, secret: priv, timestamp: NOW });
  assert.equal(verify("discord", { payload: body, headers: h, secret: pubHex, now: NOW }).valid, true);
  assert.equal(verify("discord", { payload: body + "x", headers: h, secret: pubHex, now: NOW }).valid, false);
});

test("custom providers with hmacProvider", () => {
  const acme = hmacProvider({ name: "acme", signatureHeader: "x-acme-signature", algorithm: "sha512", encoding: "base64", prefix: "sha512=" });
  const h = sign(acme, { payload: body, secret: "k" });
  assert.ok(h["x-acme-signature"].startsWith("sha512="));
  assert.equal(verify(acme, { payload: body, headers: h, secret: "k" }).valid, true);
});

test("errors and edge cases", () => {
  assert.throws(() => verify("nope", { payload: "", headers: {}, secret: "k" }), /unknown provider/);
  assert.equal(verify("github", { payload: body, headers: { "x-hub-signature-256": "sha256=zz" }, secret: "k" }).reason, "malformed x-hub-signature-256 header");
  assert.equal(verify("github", { payload: body, headers: {}, secret: "" }).reason, "no secret configured");
  assert.throws(() => verifyOrThrow("github", { payload: body, headers: {}, secret: "k" }), WebhookVerificationError);
  assert.ok(Object.keys(PROVIDERS).length >= 12);
});
