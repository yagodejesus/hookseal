import assert from "node:assert/strict";
import { test } from "node:test";

import { middleware, ReplayGuard, sign, verifyRequest } from "../dist/index.js";

test("verifyRequest with a Fetch API Request (Next.js, Hono, Bun, Deno…)", async () => {
  const body = '{"ok":true}';
  const headers = sign("github", { payload: body, secret: "k" });
  const req = new Request("https://example.com/hooks/github", { method: "POST", body, headers });
  const r = await verifyRequest("github", req, { secret: "k" });
  assert.equal(r.valid, true);
  assert.equal(JSON.parse(r.body).ok, true);
});

test("Express-style middleware", () => {
  const body = Buffer.from('{"x":1}');
  const headers = sign("shopify", { payload: body, secret: "k" });
  const mw = middleware("shopify", { secret: "k" });
  let passed = false;
  const req = { body, headers };
  mw(req, { status: () => ({ json: () => assert.fail("should not reject") }) }, (err) => {
    assert.equal(err, undefined);
    passed = true;
  });
  assert.ok(passed && req.webhook.valid);
  let status = 0;
  mw({ body: Buffer.from("tampered"), headers }, { status: (c) => ((status = c), { json: () => {} }) }, () => assert.fail());
  assert.equal(status, 401);
  mw({ body: { parsed: true }, headers }, { status: () => ({ json: () => {} }) }, (err) => assert.match(String(err), /raw body/));
});

test("ReplayGuard", () => {
  const g = new ReplayGuard(60);
  assert.equal(g.check("evt_1", 1000), false);
  assert.equal(g.check("evt_1", 1030), true);
  assert.equal(g.check("evt_1", 1061), false); // expired, accepted again and re-recorded
  const small = new ReplayGuard(60, 2);
  small.check("a", 1);
  small.check("b", 1);
  small.check("c", 1);
  assert.equal(small.size, 2);
});
