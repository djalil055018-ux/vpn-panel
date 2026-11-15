import assert from 'node:assert/strict';
import { clientListMetadata } from './client-list-metadata.ts';
const record = {
  id: 'client-id', tenant_id: 'tenant-id', name: 'Synthetic client', status: 'disabled',
  effective_status: 'disabled', expires_at: null, created_at: '2026-01-01', updated_at: '2026-09-26', remnawave_hold: true,
  vless_uuid: 'SYNTHETIC-VLESS-SECRET', trojanPassword: 'SYNTHETIC-TROJAN-SECRET',
  futureCredential: { value: 'SYNTHETIC-FUTURE-SECRET' },
};
const result = clientListMetadata(record);
assert.equal(result.name, record.name);
assert.equal(result.remnawave_hold, true);
assert.equal(JSON.stringify(result).includes('SECRET'), false);
assert.equal(clientListMetadata({ ...record, remnawave_hold: undefined }).remnawave_hold, false);
assert.equal(record.vless_uuid, 'SYNTHETIC-VLESS-SECRET');
console.log('CLIENT_LIST_CREDENTIAL_WHITELIST=PASS');

const withDirectory = { ...record, directory: { numeric_id: 145, telegram_id: '123456789', groups: ['Основная'], first_connected_at: null, connection_state: 'never', private_key: 'NESTED-SECRET', extra: { credential: 'NESTED-SECRET' } } };
const projected = clientListMetadata(withDirectory);
assert.equal(JSON.stringify(projected).includes('SECRET'), false);
assert.equal(projected.directory.first_connected_at, null);
assert.equal(projected.directory.last_online_at, undefined);
assert.equal(projected.directory.telegram_id, '123456789');
assert.deepEqual(projected.directory.groups, ['Основная']);
assert.notEqual(projected.directory.groups, withDirectory.directory.groups);
