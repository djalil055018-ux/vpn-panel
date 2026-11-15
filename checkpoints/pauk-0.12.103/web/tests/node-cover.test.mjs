import assert from "node:assert/strict";
import test from "node:test";
import { globallyRoutableIPv4, ownCoverDomain } from "../src/lib/node-cover.ts";

test("the local HTTPS flow is limited to dedicated node domains", () => {
  for (const valid of ["l.pauk.click", "nl-2.pauk.click", "new.fi.pauk.click"]) assert(ownCoverDomain(valid));
  for (const invalid of ["panel.pauk.click", "sub.pauk.click", "pauk.click", "x.pauk.click.evil.test",
    "l.pauk.click/path", "https://l.pauk.click", "-l.pauk.click", "l.pauk.click\n"]) assert(!ownCoverDomain(invalid));
});

test("the cover check cannot connect to private or reserved IPv4 addresses", () => {
  for (const ip of ["0.0.0.0", "10.1.2.3", "127.0.0.1", "169.254.169.254", "172.31.0.1",
    "192.168.1.2", "100.100.100.200", "192.0.2.1", "198.18.1.2", "203.0.113.1",
    "224.0.0.1", "255.255.255.255", "::ffff:127.0.0.1", "192.168.1.256"]) assert(!globallyRoutableIPv4(ip));
  assert(globallyRoutableIPv4("157.228.64.90"));
});
