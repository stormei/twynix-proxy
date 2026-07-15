'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  rewriteThingsBoardRpcPath,
  dispatchRpcAudit
} = require('../src/rpc-forwarding');

test('rewrites legacy two-way RPC route for current ThingsBoard API', () => {
  assert.equal(
    rewriteThingsBoardRpcPath('/api/plugins/rpc/twoway/81245070-5a6a-11f1-b1e4-8d0b37cab0a1'),
    '/api/rpc/twoway/81245070-5a6a-11f1-b1e4-8d0b37cab0a1'
  );
});

test('rewrites legacy one-way RPC route and preserves query strings', () => {
  assert.equal(
    rewriteThingsBoardRpcPath('/api/plugins/rpc/oneway/device-id?timeout=5000'),
    '/api/rpc/oneway/device-id?timeout=5000'
  );
});

test('does not rewrite unrelated ThingsBoard routes', () => {
  const path = '/api/plugins/telemetry/DEVICE/device-id/values/timeseries';
  assert.equal(rewriteThingsBoardRpcPath(path), path);
});

test('optional audit does not wait for a stalled journal write', async () => {
  let resolveAudit;
  const stalledAudit = new Promise((resolve) => { resolveAudit = resolve; });

  const result = await dispatchRpcAudit({
    requireAudit: false,
    emitAudit: () => stalledAudit
  }, {}, {});

  assert.deepEqual(result, { ok: true, deferred: true });
  resolveAudit({ ok: true });
});

test('required audit waits for and returns the journal result', async () => {
  const expected = { ok: false, reason: 'unavailable' };
  const result = await dispatchRpcAudit({
    requireAudit: true,
    emitAudit: async () => expected
  }, {}, {});

  assert.equal(result, expected);
});
