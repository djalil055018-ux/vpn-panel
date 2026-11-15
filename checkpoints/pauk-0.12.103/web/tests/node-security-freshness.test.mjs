import assert from "node:assert/strict";
import test from "node:test";
import { nodeSecurityReportFreshAt } from "../src/lib/node-security.ts";

const at = Date.parse("2026-11-09T18:00:00Z");
const snapshot = { fresh: true, received_at: new Date(at).toISOString(), report: {} };

test("last successful protection snapshot expires during a connection outage", () => {
  assert.equal(nodeSecurityReportFreshAt(snapshot, at), true);
  assert.equal(nodeSecurityReportFreshAt(snapshot, at + 149_999), true);
  assert.equal(nodeSecurityReportFreshAt(snapshot, at + 150_000), false);
  assert.equal(nodeSecurityReportFreshAt(snapshot, at + 86_400_000), false);
  assert.equal(snapshot.fresh, true, "the stored server response was not modified");
});

test("unknown, future and server-stale reports never confirm protection", () => {
  for (const value of [
    { ...snapshot, fresh: false },
    { ...snapshot, report: null },
    { ...snapshot, received_at: null },
    { ...snapshot, received_at: "invalid" },
    { ...snapshot, received_at: new Date(at + 1).toISOString() },
  ]) assert.equal(nodeSecurityReportFreshAt(value, at), false);
  assert.equal(nodeSecurityReportFreshAt(snapshot, NaN), false);
});
