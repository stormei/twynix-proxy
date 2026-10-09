const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { openScreenStore } = require('../src/screen-store');
const { createScreenRouter } = require('../src/screen-router');
const tenant = 'tenant-a';
const asset = { name: 'Pump', type: 'SCREEN' };
const draft = { SVG: '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>', state: 'DRAFT' };

test('SQLite round trip, tenant isolation, stale-save rejection and immutable publication', t => {
  const store = openScreenStore(':memory:');
  t.after(() => store.close());
  const row = store.create(tenant, 'admin', asset, draft);
  const id = row.asset.id.id;
  assert.equal(store.get('other-tenant', id), undefined);
  assert.deepEqual(store.get(tenant, id).attrs, draft);
  const published = store.update(tenant, 'admin', id, 1, { attrs: { state: 'PUBLISHED' } });
  assert.equal(published.revision, 2);
  assert.throws(() => store.update(tenant, 'admin', id, 1, { asset: { name: 'stale' } }), { status: 409 });
  assert.throws(() => store.update(tenant, 'admin', id, 2, { attrs: { SVG: '<svg/>' } }), { status: 409 });
  assert.throws(() => store.update(tenant, 'admin', id, 2, { attrs: { state: 'MAINTENANCE' } }), { status: 409 });
  assert.throws(() => store.remove(tenant, 'admin', id, 2), { status: 409 });
  store.update(tenant, 'admin', id, 2, { attrs: { state: 'DEPRECATED' } });
  store.remove(tenant, 'admin', id, 3);
  assert.equal(store.get(tenant, id).deleted, true);
  assert.equal(store.integrity(), 'ok');
});

test('online backup restores screen bytes and revisions with no original database', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'twynix-screen-test-'));
  const source = path.join(dir, 'source.sqlite'), target = path.join(dir, 'backup.sqlite');
  const store = openScreenStore(source);
  const row = store.create(tenant, 'admin', asset, draft);
  store.update(tenant, 'admin', row.asset.id.id, 1, { asset: { name: 'Revised' } });
  await store.backup(target);
  store.close();
  const restored = openScreenStore(target);
  t.after(() => { restored.close(); fs.rmSync(dir, { recursive: true }); });
  assert.equal(restored.integrity(), 'ok');
  assert.equal(restored.get(tenant, row.asset.id.id).revision, 2);
  assert.equal(restored.get(tenant, row.asset.id.id).attrs.SVG, draft.SVG);
});

test('screen HTTP routes enforce authentication, CAS, published visibility and safe migration/import', async t => {
  const store = openScreenStore(':memory:');
  let legacyReads = 0;
  const legacyId = '11111111-1111-4111-8111-111111111111';
  const app = express();
  app.use('/api/twynix/screens', createScreenRouter({ store,
    authenticate: async req => {
      const role = req.headers['x-test-role'];
      if (!role) throw Object.assign(new Error('Unauthorized'), { status: 401 });
      return { tenantId: req.headers['x-test-tenant'] || tenant, userId: role, authority: role === 'admin' ? 'TENANT_ADMIN' : 'CUSTOMER_USER' };
    },
    readLegacy: async (user, id) => {
      legacyReads++;
      if (user.authority !== 'TENANT_ADMIN') throw Object.assign(new Error('Denied'), { status: 403 });
      return { asset: { ...asset, id: { id }, tenantId: { id: user.tenantId } }, attrs: { ...draft, state: 'PUBLISHED' } };
    }
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); store.close(); });
  const base = `http://127.0.0.1:${server.address().port}/api/twynix/screens`;
  const request = (suffix = '', method = 'GET', body, role = 'admin', match, scope = tenant) => fetch(base + suffix, {
    method, headers: { 'content-type': 'application/json', ...(role ? { 'x-test-role': role } : {}),
      'x-test-tenant': scope, ...(match === undefined ? {} : { 'if-match': String(match) }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  assert.equal((await request('', 'GET', undefined, null)).status, 401);
  assert.equal((await request('', 'POST', asset, 'viewer')).status, 403);
  const created = await (await request('', 'POST', asset)).json();
  const id = created.asset.id.id;
  assert.equal((await request(`/${id}`, 'GET', undefined, 'viewer')).status, 403);
  assert.equal((await request(`/${id}`, 'GET', undefined, 'admin', undefined, 'other')).status, 404);
  assert.equal((await request(`/${id}`, 'PATCH', { attrs: draft })).status, 428);
  assert.equal((await request(`/${id}`, 'PATCH', { attrs: draft }, 'admin', 1)).status, 200);
  assert.equal((await request(`/${id}`, 'PATCH', { attrs: draft }, 'admin', 1)).status, 409);
  assert.equal((await request(`/${id}`, 'PATCH', { attrs: { state: 'PUBLISHED' } }, 'admin', 2)).status, 200);
  assert.equal((await request(`/${id}`, 'GET', undefined, 'viewer')).status, 200);
  assert.equal((await request(`/${id}`, 'PATCH', { attrs: draft }, 'viewer', 3)).status, 403);
  const pkg = await (await request(`/${id}/export`)).json();
  assert.equal(pkg.selfContained, false);
  // Import succeeds without looking up any original asset and cannot activate runtime.
  const imported = await (await request('/import', 'POST', pkg)).json();
  assert.notEqual(imported.asset.id.id, id);
  assert.equal(imported.attrs.screenLifecycle.state, 'DRAFT');
  assert.equal(imported.attrs.SVG, draft.SVG);
  assert.equal(legacyReads, 0);
  pkg.checksum = 'invalid';
  assert.equal((await request('/import', 'POST', pkg)).status, 400);
  assert.equal((await request(`/migrate/${legacyId}`, 'POST', {})).status, 201);
  assert.equal((await request(`/migrate/${legacyId}`, 'POST', {})).status, 200);
  assert.equal(legacyReads, 1);
  assert.equal((await request(`/${legacyId}`, 'GET', undefined, 'viewer')).status, 403);
  const list = await (await request('', 'GET', undefined, 'viewer')).json();
  assert.equal(list.data.length, 1);
  assert.ok(list.shadowIds.includes(legacyId));
});
