import assert from "node:assert/strict";
import test from "node:test";
import { reserveSubscriptionLink } from "../src/lib/reserve-subscription.ts";

test("reserve URL preserves the credential path and expires", () => {
  const path = "/sub/syntheticToken0123456789";
  const until = "2026-11-06T07:09:00Z";
  const now = Date.parse("2026-11-04T08:00:00Z");
  assert.deepEqual(reserveSubscriptionLink(path, "https://147.45.126.251", until, now), {
    url: "https://147.45.126.251" + path,
    expires_at: new Date(until).toISOString(),
  });
  assert.equal(reserveSubscriptionLink(path, "https://147.45.126.251", until, Date.parse(until)), null);
  for (const origin of ["http://147.45.126.251", "https://user:secret@147.45.126.251", "https://147.45.126.251/other", "https://147.45.126.251?target=other", "not a URL"]) {
    assert.equal(reserveSubscriptionLink(path, origin, until, now), null);
  }
  for (const invalid of ["//other.example/sub/token", "/sub/../admin", "/sub/syntheticToken0123456789?redirect=other", "/api/v1/tenants"]) {
    assert.equal(reserveSubscriptionLink(invalid, "https://147.45.126.251", until, now), null);
  }
});
