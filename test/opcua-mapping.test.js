const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const vm = require('node:vm');
const { openMappingStore, normalizeDraft } = require('../src/opcua-engineering/mapping-store');
const { compileMappings } = require('../src/opcua-engineering/mapping-compiler');
const { MappingService } = require('../src/opcua-engineering/mapping-service');
const user = { tenantId: randomUUID(), userId: randomUUID(), authority: 'TENANT_ADMIN' };
const deviceId = randomUUID();
function signal(overrides = {}) { return { id: randomUUID(), nodeId: 'ns=2;s=Device.tag1', parentNodeId: 'ns=2;s=Device', namespaceUri: 'urn:test', browseName: '2:tag1', displayName: 'tag1', dataType: 'UInt16', deviceId, key: 'speed', enabled: true, ...overrides }; }
function setup(t, enabled = true) {
  const store = openMappingStore(':memory:'); t.after(() => store.close());
  const m = signal(); store.save(user, 'test', 0, { name: 'Test', mappings: [m] });
  const resources = new Map(), calls = [];
  const connection = { id: 'test', tenantId: user.tenantId, endpoint: 'opc.tcp://192.0.2.10:4840', revision: 1 };
  const good = value => ({ status: 'Good', value });
  const sessions = { connections: [connection], authorize: u => { if (u.authority !== 'TENANT_ADMIN') throw Object.assign(new Error('denied'), { status: 403 }); },
    row: () => ({ connectionId: 'test' }),
    inspect: async () => [{ nodeId: m.nodeId, attributes: { BrowseName: good('Device'), NodeClass: good('Variable'), DataType: good('UInt16'), ValueRank: good(-1), UserAccessLevel: good({ read: true }), Value: good(12) } }],
    browse: async () => ({ nodes: [m], cursor: null }) };
  const service = new MappingService({ store, sessions, deploymentEnabled: enabled, request: async (u, method, path, body) => {
    calls.push({ u, method, path, body });
    if (path.startsWith('/api/integrations?')) return { data: [...resources.values()].filter(r => r.type === 'OPC_UA'), hasNext: false };
    if (path === `/api/device/${deviceId}`) return { id: { id: deviceId }, tenantId: { id: user.tenantId }, name: 'Motor', type: 'default' };
    if (method === 'POST') {
      const resource = { ...body, id: body.id || { id: randomUUID(), entityType: path.includes('converter') ? 'CONVERTER' : 'INTEGRATION' }, tenantId: { id: u.tenantId }, version: (body.version || 0) + 1 };
      resources.set(`${path}/${resource.id.id}`, resource); return resource;
    }
    if (resources.has(path)) return resources.get(path);
    throw new Error('Unexpected request ' + path);
  } });
  return { store, service, sessions, m, calls, resources };
}
test('drafts are tenant scoped and optimistic revisions preserve history', t => {
  const { store } = setup(t);
  assert.equal(store.get('other', 'test').revision, 0);
  assert.throws(() => store.save(user, 'test', 0, { name: 'stale', mappings: [] }), { status: 409 });
  store.save(user, 'test', 1, { name: 'next', mappings: [] });
  assert.deepEqual(store.history(user.tenantId, 'test').map(r => r.revision), [2, 1]);
  assert.equal(store.restore(user, 'test', 2, 1).revision, 3);
  assert.equal(store.get(user.tenantId, 'test').mappings.length, 1);
});
test('normalization rejects duplicate targets and drops credentials/unrecognized fields', () => {
  const m = signal();
  assert.throws(() => normalizeDraft({ name: 'x', mappings: [m, signal({ nodeId: 'ns=2;s=other' })] }), { status: 400 });
  const draft = normalizeDraft({ name: 'x', password: 'secret', mappings: [{ ...m, token: 'secret' }] });
  assert.equal(JSON.stringify(draft).includes('secret'), false);
});
test('compiler creates exact groups, stable aliases and routes only present values', () => {
  const m = signal(), other = signal({ nodeId: 'ns=2;s=Device.tag2', browseName: '2:tag2', key: 'temperature' });
  const compiled = compileMappings([m, other], new Map([[deviceId, { name: 'Motor', type: 'default' }]]));
  assert.equal(compiled.mapping.length, 1); assert.equal(compiled.mapping[0].deviceNodePattern, '\\QDevice\\E');
  const payload = Buffer.from(JSON.stringify({ [compiled.mapping[0].subscriptionTags[0].key]: 42 }));
  const result = vm.runInNewContext(`(function(payload){${compiled.decoder}})(payload)`, { payload });
  assert.equal(JSON.stringify(result), JSON.stringify([{ deviceName: 'Motor', deviceType: 'default', attributes: {}, telemetry: { speed: 42 } }]));
});
test('validation blocks namespace drift and unsupported type before writes', async t => {
  const { service, sessions, m, calls } = setup(t);
  sessions.browse = async () => ({ nodes: [{ ...m, namespaceUri: 'changed' }], cursor: null });
  const preview = await service.preview(user, 'test', 'session');
  assert.equal(preview.valid, false); assert.match(preview.issues.join(' '), /identity changed/);
  assert.equal(calls.filter(c => c.method === 'POST').length, 0);
});
test('disabled deployment, tenant scope and preview ownership are enforced', async t => {
  const { service, calls } = setup(t, false);
  assert.throws(() => service.get({ ...user, tenantId: 'other' }, 'test'), { status: 404 });
  const p = await service.preview(user, 'test', 'session');
  await assert.rejects(service.deploy(user, 'test', p.token), { status: 403 });
  assert.equal(calls.some(c => c.method === 'POST'), false);
});
test('deploy creates isolated resources, disables device creation and preserves caller identity', async t => {
  const { service, calls, store } = setup(t);
  const p = await service.preview(user, 'test', 'session');
  await assert.rejects(service.deploy({ ...user, userId: 'other' }, 'test', p.token), { status: 409 });
  await service.deploy(user, 'test', p.token);
  const writes = calls.filter(c => c.method === 'POST');
  assert.equal(writes.length, 2); assert.equal(writes[1].body.allowCreateDevicesOrAssets, false);
  assert.equal(writes[1].body.downlinkConverterId, null); assert.equal(writes.every(c => c.u === user), true);
  assert.equal(store.deployments(user.tenantId, 'test')[0].state, 'applied');
  await assert.rejects(service.deploy(user, 'test', p.token), { status: 409 });
});
test('external edits block deployment rather than overwrite external configuration', async t => {
  const { service, resources } = setup(t);
  const p = await service.preview(user, 'test', 'session'); await service.deploy(user, 'test', p.token);
  const integration = [...resources.values()].find(r => r.type === 'OPC_UA'); integration.name = 'Changed externally';
  await assert.rejects(service.preview(user, 'test', 'session'), { status: 409 });
});
test('partial or unknown save is journalled and blocks duplicate retry', async t => {
  const { service, store } = setup(t);
  const request = service.request;
  service.request = async (...args) => { if (args[1] === 'POST' && args[2] === '/api/integration') throw new Error('timeout'); return request(...args); };
  const p = await service.preview(user, 'test', 'session');
  await assert.rejects(service.deploy(user, 'test', p.token), { status: 409 });
  const d = store.deployments(user.tenantId, 'test')[0]; assert.equal(d.state, 'attention'); assert.ok(d.resources.converterId);
  assert.throws(() => store.begin(user, 'test', 1), { status: 409 });
});
test('saving another draft invalidates reviewed deployment', async t => {
  const { service, store, calls } = setup(t);
  const p = await service.preview(user, 'test', 'session');
  store.save(user, 'test', 1, { name: 'changed', mappings: [] });
  await assert.rejects(service.deploy(user, 'test', p.token), { status: 409 });
  assert.equal(calls.some(c => c.method === 'POST'), false);
});
test('updates create a new converter without mutating the previous version', async t => {
  const { service, store, m, resources, calls } = setup(t);
  let p = await service.preview(user, 'test', 'session'); await service.deploy(user, 'test', p.token);
  const initial = store.deployments(user.tenantId, 'test')[0], old = JSON.stringify(resources.get(`/api/converter/${initial.resources.converterId}`));
  store.save(user, 'test', 1, { name: 'Test', mappings: [{ ...m, key: 'newSpeed' }] });
  p = await service.preview(user, 'test', 'session'); assert.equal(p.changes[0].change, 'update');
  await service.deploy(user, 'test', p.token);
  assert.equal(JSON.stringify(resources.get(`/api/converter/${initial.resources.converterId}`)), old);
  const integrations = calls.filter(c => c.method === 'POST' && c.path === '/api/integration');
  assert.equal(integrations[1].body.id.id, initial.resources.integrationId);
  assert.equal(integrations[1].body.version, 1);
});
test('disabling all mappings disables only the managed Integration and retains resources', async t => {
  const { service, store, calls } = setup(t);
  let p = await service.preview(user, 'test', 'session'); await service.deploy(user, 'test', p.token);
  store.save(user, 'test', 1, { name: 'Test', mappings: [] });
  p = await service.preview(user, 'test', 'session'); assert.equal(p.changes[0].change, 'remove');
  await service.deploy(user, 'test', p.token);
  assert.equal(calls.filter(c => c.method === 'POST' && c.path === '/api/converter').length, 1);
  assert.equal(calls.filter(c => c.method === 'POST' && c.path === '/api/integration').at(-1).body.enabled, false);
  assert.equal(calls.some(c => c.method === 'DELETE'), false);
});
test('twenty mappings preserve Unicode values and skip missing inputs', () => {
  const signals = Array.from({ length: 20 }, (_, i) => signal({ nodeId: `ns=2;s=Device.tag${i}`, browseName: `2:tag${i}`, key: `signal${i}` }));
  const compiled = compileMappings(signals, new Map([[deviceId, { name: 'Motor', type: 'default' }]]));
  const payload = Buffer.from(JSON.stringify({ [compiled.mapping[0].subscriptionTags[0].key]: 'Måling 温度' }));
  const output = vm.runInNewContext(`(function(payload){${compiled.decoder}})(payload)`, { payload });
  assert.equal(output[0].telemetry.signal0, 'Måling 温度'); assert.equal(Object.keys(output[0].telemetry).length, 1);
});
test('online backup preserves drafts and revision history', async t => {
  const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), Database = require('better-sqlite3');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'twynix-opcua-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true }));
  const { store } = setup(t); const file = path.join(directory, 'backup.sqlite'); await store.backup(file);
  const copy = new Database(file, { readonly: true });
  try { assert.equal(copy.pragma('integrity_check', { simple: true }), 'ok'); assert.equal(copy.prepare('SELECT COUNT(*) AS n FROM mapping_revisions').get().n, 1); }
  finally { copy.close(); }
});
