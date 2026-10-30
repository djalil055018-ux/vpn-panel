import assert from 'node:assert/strict';
import { monthlyBytesFromGiB, GIB, MAX_MONTHLY_BYTES } from './usage-limit.ts';
for (const bytes of [0, 1, 150, 500000000, GIB, GIB + 1, MAX_MONTHLY_BYTES]) {
  assert.equal(monthlyBytesFromGiB(String(bytes / GIB)), bytes);
}
for (const input of ['', '-1', 'Infinity', 'NaN', '0x100', '9000000000000001', '1e-30', '1 2']) {
  assert.equal(monthlyBytesFromGiB(input), null);
}
assert.equal(monthlyBytesFromGiB('1.5'), 1610612736);
console.log('USAGE_LIMIT_EXACT_ROUNDTRIP=GREEN');
