const { test } = require('node:test');
const assert = require('node:assert/strict');
const { DiscoverySessions } = require('../src/opcua-engineering/session-manager');
const { parseConnections } = require('../src/opcua-engineering/connection-policy');
const tenantId = '11111111-1111-1111-1111-111111111111';
const user = { tenantId, userId: 'user1', authority: 'TENANT_ADMIN' };
const connection = { id: 'test', name: 'Test', revision: 1, tenantId, endpoint: 'opc.tcp://192.0.2.10:4840', securityMode: 'None', allowInsecureDiscovery: true };
function setup(t, overrides = {}) {
  let closes = 0;
  const transport = { open: async () => ['urn:test'], close: async () => { closes++; },
    browse: async () => ({ nodes: [], continuationPoint: Buffer.from('cursor') }), inspect: async () => [] };
  const manager = new DiscoverySessions({ connections: [connection], createClient: () => transport, ...overrides });
  t.after(() => manager.shutdown());
  return { manager, transport, closes: () => closes };
}
test('registry rejects unapproved security and arbitrary DNS or metadata hosts', () => {
  assert.equal(parseConnections(JSON.stringify([connection]))[0].id, 'test');
  for (const endpoint of ['http://192.0.2.10:80', 'opc.tcp://localhost:4840', 'opc.tcp://169.254.169.254:4840', 'opc.tcp://127.0.0.1:4840']) {
    assert.throws(() => parseConnections(JSON.stringify([{ ...connection, endpoint }])));
  }
  assert.throws(() => parseConnections(JSON.stringify([{ ...connection, allowInsecureDiscovery: false }])));
});
test('list strips endpoints and denies nonadministrators', t => {
  const { manager } = setup(t);
  assert.equal(manager.list(user)[0].endpoint, undefined);
  assert.throws(() => manager.list({ ...user, authority: 'CUSTOMER_USER' }), { status: 403 });
  assert.deepEqual(manager.list({ ...user, tenantId: 'other' }), []);
});
test('requires matching connection revision and owner tenant', async t => {
  const { manager } = setup(t);
  await assert.rejects(manager.open(user, 'test', 2), { status: 409 });
  await assert.rejects(manager.open({ ...user, tenantId: 'other' }, 'test', 1), { status: 404 });
});
test('sessions are private to user and tenant; duplicate open rejected', async t => {
  const { manager } = setup(t); const session = await manager.open(user, 'test', 1);
  await assert.rejects(manager.open(user, 'test', 1), { status: 409 });
  assert.throws(() => manager.row({ ...user, userId: 'other' }, session.id), { status: 404 });
  assert.throws(() => manager.row({ ...user, tenantId: 'other' }, session.id), { status: 404 });
});
test('browse cursors are opaque and single-use', async t => {
  const { manager } = setup(t); const { id } = await manager.open(user, 'test', 1);
  const page = await manager.browse(user, id, { nodeId: 'ns=0;i=85' });
  assert.notEqual(page.cursor, 'cursor');
  await manager.browse(user, id, { cursor: page.cursor });
  await assert.rejects(manager.browse(user, id, { cursor: page.cursor }), { status: 400 });
});
test('idle expiry closes transport', async t => {
  let now = 0; const { manager, closes } = setup(t, { now: () => now });
  const { id } = await manager.open(user, 'test', 1); now = 61000;
  await manager.sweep(); assert.equal(closes(), 1);
  assert.throws(() => manager.row(user, id), { status: 404 });
});
test('inspection rejects oversized requests and malformed node IDs', async t => {
  const { manager } = setup(t); const { id } = await manager.open(user, 'test', 1);
  assert.throws(() => manager.inspect(user, id, { nodeIds: Array(21).fill('ns=0;i=1') }), { status: 400 });
  assert.throws(() => manager.inspect(user, id, { nodeIds: ['http://invalid'] }), { status: 400 });
});
test('concurrent requests reject without closing the active request', async t => {
  const { manager, transport } = setup(t); const { id } = await manager.open(user, 'test', 1);
  let release; transport.inspect = () => new Promise(resolve => { release = resolve; });
  const pending = manager.inspect(user, id, { nodeIds: ['ns=0;i=1'] });
  await Promise.resolve();
  await assert.rejects(manager.inspect(user, id, { nodeIds: ['ns=0;i=1'] }), { status: 409 });
  release([]); await pending; assert.equal(manager.sessions.size, 1);
});
test('timeout closes transport and late response does not revive session', async t => {
  const { manager, transport, closes } = setup(t, { operationMs: 10 });
  const { id } = await manager.open(user, 'test', 1);
  let release; transport.inspect = () => new Promise(resolve => { release = resolve; });
  await assert.rejects(manager.inspect(user, id, { nodeIds: ['ns=0;i=1'] }), { status: 504 });
  release([]); await Promise.resolve(); assert.equal(closes(), 1); assert.equal(manager.sessions.size, 0);
});
test('startup failure releases capacity', async t => {
  const { manager, transport, closes } = setup(t);
  transport.open = async () => { throw new Error('connect failed'); };
  await assert.rejects(manager.open(user, 'test', 1));
  assert.equal(closes(), 1); assert.equal(manager.sessions.size, 0);
});
test('HTTP routes authenticate every operation and expose no write endpoint', async t => {
  const express = require('express');
  const { createDiscoveryRouter } = require('../src/opcua-engineering/router');
  const { manager } = setup(t);
  let authenticated = 0;
  const app = express();
  app.use(createDiscoveryRouter({ sessions: manager, authenticate: async req => {
    authenticated++;
    if (req.headers.authorization !== 'test-identity') throw Object.assign(new Error('Authentication required'), { status: 401 });
    return user;
  } }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${base}/connections`)).status, 401);
  const headers = { authorization: 'test-identity', 'content-type': 'application/json' };
  assert.equal((await fetch(`${base}/connections`, { headers })).status, 200);
  assert.equal((await fetch(`${base}/write`, { method: 'POST', headers, body: '{}' })).status, 404);
  assert.equal(authenticated, 3);
});
test('HTTP transport failures are sanitized and customer users cannot browse', async t => {
  const express = require('express');
  const { createDiscoveryRouter } = require('../src/opcua-engineering/router');
  const { manager, transport } = setup(t);
  transport.open = async () => { throw new Error('private endpoint and credentials'); };
  const app = express();
  app.use(createDiscoveryRouter({ sessions: manager, authenticate: async req => ({ ...user,
    authority: req.headers['x-test-role'] || 'CUSTOMER_USER' }) }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${base}/connections`)).status, 403);
  const response = await fetch(`${base}/sessions`, { method: 'POST', headers: { 'x-test-role': 'TENANT_ADMIN', 'content-type': 'application/json' }, body: JSON.stringify({ connectionId: 'test', revision: 1 }) });
  assert.equal(response.status, 502); assert.doesNotMatch(await response.text(), /private endpoint|credentials/);
});
