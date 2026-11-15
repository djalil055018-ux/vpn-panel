import assert from "node:assert/strict";
import test from "node:test";
import { customerRequestOriginAllowed, subscriptionOrigin, subscriptionURL } from "../src/lib/subscription-origin.ts";

const panel = "https://console.example.test";
const dedicated = "https://subscription.example.test";
const path = "/sub/syntheticToken0123456789";

test("a separate subscription origin preserves the credential and normalizes the host", () => {
  assert.equal(subscriptionURL(path, dedicated, panel), dedicated + path);
  assert.equal(subscriptionURL(path, " https://Subscription.Example.Test:443/ ", panel), dedicated + path);
  assert.equal(subscriptionURL(path, dedicated, undefined), dedicated + path);
});

test("existing installations retain the panel origin until separation is configured", () => {
  assert.equal(subscriptionURL(path, undefined, panel), panel + path);
  assert.equal(subscriptionURL(path, " ", panel), panel + path);
  assert.equal(subscriptionOrigin(undefined, "http://127.0.0.1:3000"), "http://127.0.0.1:3000");
});

test("invalid configuration cannot silently fall back to the panel or leak into another URL", () => {
  for (const invalid of ["http://public.example.test", "https://user:password@subscription.example.test", dedicated + "/other", dedicated + "?target=other", dedicated + "#fragment", "not a URL"]) {
    assert.throws(() => subscriptionURL(path, invalid, panel));
  }
  for (const invalid of ["//other.example/sub/token", "/sub/../admin", path + "?redirect=other", path + "#fragment", "/api/v1/nodes", "/sub/short", "/sub/" + "A".repeat(129)]) {
    assert.throws(() => subscriptionURL(invalid, dedicated, panel));
  }
  assert.throws(() => subscriptionURL(path, undefined, undefined));
});

test("customer actions accept only the two configured origins", () => {
  assert.equal(customerRequestOriginAllowed(panel, panel, dedicated), true);
  assert.equal(customerRequestOriginAllowed(dedicated, panel, dedicated), true);
  assert.equal(customerRequestOriginAllowed(panel, panel, undefined), true);
  for (const foreign of [null, "null", "https://other.example.test", dedicated + ".other.example", "http://subscription.example.test", dedicated + "/", "https://subscription.example.test:444"]) {
    assert.equal(customerRequestOriginAllowed(foreign, panel, dedicated), false);
  }
  assert.equal(customerRequestOriginAllowed(panel, panel, "not a URL"), false);
});
