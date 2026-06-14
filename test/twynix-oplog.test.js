const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  JOURNAL_KEY_PREFIX,
  JOURNAL_TS_KEY,
  sanitizeEntry,
  createTwynixOplogHandlers
} = require('../src/twynix-oplog');
const { createTelemetryWriteGuard } = require('../src/telemetry-write-policy');
const {
  createProxyRoutePolicy,
  getBearerTokenFromHeaders,
  isReadOnlyIotdbQuery,
  scrubInboundHeaders
} = require('../src/security-policy');
const { validateProxyBodySize } = require('../src/request-size-policy');
const { readEnvSecret } = require('../src/config-secrets');
const { validateConfig } = require('../src/config-validation');
const { buildRpcPolicy, validateRpcBody } = require('../src/rpc-policy');
const {
  buildGroupSql,
  buildLatestSeriesSql,
  buildSeriesSql,
  buildShowDeviceTimeseriesSql,
  buildShowTimeseriesSql,
  chooseDataMode,
  executeTrendQuery,
  normalizeRequest
} = require('../src/iotdb-trend-query');
const { createIotdbSchemaHandler } = require('../src/iotdb-schema');

function createMockRes() {
  return {
    statusCode: 200,
    sent: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.sent = payload;
      return this;
    },
    send(payload) {
      this.sent = payload;
      return this;
    }
  };
}

async function runHandler(handler, req) {
  const res = createMockRes();
  await handler(req, res);
  return res;
}

function createFakeTb() {
  const state = {
    tenantAttrs: new Map(),
    assetsByTenant: new Map(),
    assetTs: new Map(),
    nextAsset: 1
  };

  function ensureTenantAssets(tenantId) {
    if (!state.assetsByTenant.has(tenantId)) state.assetsByTenant.set(tenantId, []);
    return state.assetsByTenant.get(tenantId);
  }

  function ensureAssetTs(assetId) {
    if (!state.assetTs.has(assetId)) state.assetTs.set(assetId, []);
    return state.assetTs.get(assetId);
  }

  async function get(url) {
    const u = new URL(url);
    const p = u.pathname;

    let m = p.match(/^\/api\/plugins\/telemetry\/TENANT\/([^/]+)\/values\/attributes\/SERVER_SCOPE$/);
    if (m) {
      const tenantId = m[1];
      const key = u.searchParams.get('keys');
      const attrs = [];
      const tenantData = state.tenantAttrs.get(tenantId);
      if (tenantData && key && Object.prototype.hasOwnProperty.call(tenantData, key)) {
        attrs.push({ key, value: tenantData[key] });
      }
      return { data: attrs };
    }

    m = p.match(/^\/api\/tenant\/([^/]+)\/assets$/);
    if (m) {
      const tenantId = m[1];
      const type = u.searchParams.get('type');
      const textSearch = u.searchParams.get('textSearch');
      const all = ensureTenantAssets(tenantId);
      const data = all.filter((a) => (!type || a.type === type) && (!textSearch || a.name.includes(textSearch)));
      return { data: { data, hasNext: false } };
    }

    m = p.match(/^\/api\/plugins\/telemetry\/ASSET\/([^/]+)\/values\/timeseries$/);
    if (m) {
      const assetId = m[1];
      const keys = String(u.searchParams.get('keys') || '');
      const keyList = keys.split(',').map((k) => k.trim()).filter(Boolean);
      const startTs = Number(u.searchParams.get('startTs') || 0);
      const endTs = Number(u.searchParams.get('endTs') || Number.MAX_SAFE_INTEGER);
      const limit = Number(u.searchParams.get('limit') || 100);
      const orderBy = String(u.searchParams.get('orderBy') || 'DESC').toUpperCase();
      const rows = ensureAssetTs(assetId)
        .filter((r) => r.ts >= startTs && r.ts <= endTs)
        .sort((a, b) => (orderBy === 'ASC' ? a.ts - b.ts : b.ts - a.ts));
      const out = {};
      for (const k of keyList) out[k] = [];
      for (const r of rows) {
        for (const k of keyList) {
          if (r.values && Object.prototype.hasOwnProperty.call(r.values, k)) {
            out[k].push({ ts: r.ts, value: r.values[k] });
          }
        }
      }
      for (const k of keyList) out[k] = out[k].slice(0, limit);
      return { data: out };
    }

    throw new Error(`Unhandled GET ${url}`);
  }

  async function post(url, body) {
    const u = new URL(url);
    const p = u.pathname;

    let m = p.match(/^\/api\/plugins\/telemetry\/TENANT\/([^/]+)\/SERVER_SCOPE$/);
    if (m) {
      const tenantId = m[1];
      const prev = state.tenantAttrs.get(tenantId) || {};
      state.tenantAttrs.set(tenantId, { ...prev, ...(body || {}) });
      return { data: { ok: true } };
    }

    if (p === '/api/asset') {
      const tenantId = body && body.tenantId && body.tenantId.id;
      const id = `asset-${state.nextAsset++}`;
      const asset = {
        id: { id, entityType: 'ASSET' },
        name: body.name,
        type: body.type
      };
      ensureTenantAssets(tenantId).push(asset);
      return { data: asset };
    }

    m = p.match(/^\/api\/plugins\/telemetry\/ASSET\/([^/]+)\/timeseries\/ANY$/);
    if (m) {
      const assetId = m[1];
      const prev = ensureAssetTs(assetId);
      const ts = Number(body?.ts);
      const values = body?.values && typeof body.values === 'object' ? body.values : {};
      prev.push({ ts: Number.isFinite(ts) ? ts : Date.now(), values });
      return { data: { ok: true } };
    }

    throw new Error(`Unhandled POST ${url}`);
  }

  return {
    state,
    ax: { get, post }
  };
}

function requireValidUser(req, res) {
  const h = req.headers['x-authorization'];
  if (!h || !h.startsWith('Bearer ')) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }
  const token = h.slice('Bearer '.length);
  if (token === 'tokenA') return { userId: 'user-a', tenantId: 'tenant-a', userToken: token };
  if (token === 'tokenB') return { userId: 'user-b', tenantId: 'tenant-b', userToken: token };
  res.status(401).json({ error: 'unauthorized' });
  return null;
}

function makeReq({ headers = {}, body = {}, query = {} } = {}) {
  return { headers, body, query };
}

test('sanitizeEntry redacts and truncates sensitive fields safely', () => {
  const longDetail = 'x'.repeat(700);
  const hugeParams = { token: 'abc', nested: { password: 'p' }, buf: 'a'.repeat(5000) };
  const out = sanitizeEntry({
    ts: 123,
    action: { params: hugeParams },
    result: { detail: longDetail }
  });

  assert.equal(out.ts, 123);
  assert.deepEqual(out.action.params, { _truncated: true });
  assert.equal(out.result.detail.length, 512);
});

test('oplog write success and read filtering', async () => {
  const fakeTb = createFakeTb();
  const { writeHandler, readHandler } = createTwynixOplogHandlers({
    config: { THINGSBOARD_URL: 'http://tb.local', INTERNAL_PROXY_SECRET: 'internal', AUDIT_HMAC_SECRET: 'test-hmac-secret' },
    ax: fakeTb.ax,
    getAdminToken: async () => 'admin-token',
    requireValidUser,
    logger: () => {}
  });

  const headersA = { 'x-authorization': 'Bearer tokenA' };
  const w1 = await runHandler(writeHandler, makeReq({
    headers: headersA,
    body: {
      tenantId: 'tenant-a',
      entry: {
        ts: 1000,
        type: 'cmd.exec',
        userId: 'operator-1',
        targetType: 'DEVICE',
        targetId: 'dev-1',
        action: { params: { authorization: 'Bearer x', value: 42 } },
        result: { detail: 'ok' }
      }
    }
  }));
  assert.equal(w1.statusCode, 200);
  assert.equal(w1.sent.ok, true);
  assert.equal(w1.sent.telemetryKey, 'twynix.oplog');
  const row = fakeTb.state.assetTs.get(w1.sent.assetId)[0];
  assert.equal(typeof row.values[JOURNAL_TS_KEY], 'string');
  assert.equal(row.values[`${JOURNAL_KEY_PREFIX}type`], 'cmd.exec');
  assert.equal(row.values[`${JOURNAL_KEY_PREFIX}userId`], 'operator-1');
  assert.equal(row.values[`${JOURNAL_KEY_PREFIX}targetType`], 'DEVICE');
  assert.equal(row.values[`${JOURNAL_KEY_PREFIX}targetId`], 'dev-1');
  assert.equal(row.values[`${JOURNAL_KEY_PREFIX}outcome`], '');
  assert.equal(typeof row.values[`${JOURNAL_KEY_PREFIX}corr`], 'string');
  const storedEvent = JSON.parse(row.values[JOURNAL_TS_KEY]);
  assert.equal(storedEvent.v, 2);
  assert.equal(storedEvent.sigAlg, 'hmac-sha256');
  assert.equal(typeof storedEvent.sig, 'string');

  const w2 = await runHandler(writeHandler, makeReq({
    headers: headersA,
    body: {
      tenantId: 'tenant-a',
      entry: {
        ts: 2000,
        type: 'alarm.shelve',
        userId: 'operator-2',
        targetType: 'DEVICE',
        targetId: 'dev-2',
        action: { params: { token: 'hidden' } },
        result: { detail: 'done' }
      }
    }
  }));
  assert.equal(w2.statusCode, 200);

  const read = await runHandler(readHandler, makeReq({
    headers: headersA,
    query: {
      fromTs: '500',
      toTs: '2500',
      targetId: 'dev-2',
      typeCsv: 'alarm.shelve',
      limit: '10'
    }
  }));
  assert.equal(read.statusCode, 200);
  assert.equal(read.sent.data.length, 1);
  assert.equal(read.sent.data[0].targetId, 'dev-2');
  assert.equal(read.sent.data[0].type, 'alarm.shelve');
});

test('tenant isolation and unauthenticated denial', async () => {
  const fakeTb = createFakeTb();
  const baseTs = Date.now();
  const { writeHandler, readHandler } = createTwynixOplogHandlers({
    config: { THINGSBOARD_URL: 'http://tb.local', INTERNAL_PROXY_SECRET: 'internal' },
    ax: fakeTb.ax,
    getAdminToken: async () => 'admin-token',
    requireValidUser,
    logger: () => {}
  });

  const deniedWrite = await runHandler(writeHandler, makeReq({
    headers: { 'x-authorization': 'Bearer tokenA' },
    body: {
      tenantId: 'tenant-b',
      entry: { ts: 123, action: { params: {} } }
    }
  }));
  assert.equal(deniedWrite.statusCode, 403);

  const okWriteTenantB = await runHandler(writeHandler, makeReq({
    headers: { 'x-authorization': 'Bearer tokenB' },
    body: {
      tenantId: 'tenant-b',
      entry: {
        ts: baseTs,
        type: 'cmd.exec',
        userId: 'operator-b',
        targetType: 'DEVICE',
        targetId: 'dev-b',
        action: { params: { secret: 's' } }
      }
    }
  }));
  assert.equal(okWriteTenantB.statusCode, 200);

  const okWriteTenantA = await runHandler(writeHandler, makeReq({
    headers: { 'x-authorization': 'Bearer tokenA' },
    body: {
      tenantId: 'tenant-a',
      entry: {
        ts: baseTs + 1,
        type: 'cmd.exec',
        userId: 'operator-a',
        targetType: 'DEVICE',
        targetId: 'dev-a',
        action: { params: { secret: 's' } }
      }
    }
  }));
  assert.equal(okWriteTenantA.statusCode, 200);

  const readA = await runHandler(readHandler, makeReq({
    headers: { 'x-authorization': 'Bearer tokenA' },
    query: { limit: '50', fromTs: String(baseTs - 1000), toTs: String(baseTs + 10000) }
  }));
  assert.equal(readA.statusCode, 200);
  assert.equal(readA.sent.data.length, 1);
  assert.equal(readA.sent.data[0].targetId, 'dev-a');

  const unauthWrite = await runHandler(writeHandler, makeReq({
    body: { tenantId: 'tenant-a', entry: {} }
  }));
  assert.equal(unauthWrite.statusCode, 401);

  const unauthRead = await runHandler(readHandler, makeReq({}));
  assert.equal(unauthRead.statusCode, 401);
});

test('non-journal telemetry writes remain denied by policy', async () => {
  const guard = createTelemetryWriteGuard({
    auditToThingsBoard: async () => {}
  });

  const deniedReq = {
    method: 'POST',
    path: '/api/plugins/telemetry/ASSET/abc/CLIENT_SCOPE'
  };
  const deniedRes = createMockRes();
  let deniedNext = false;
  await guard(deniedReq, deniedRes, () => { deniedNext = true; });
  assert.equal(deniedNext, false);
  assert.equal(deniedRes.statusCode, 403);
  assert.match(String(deniedRes.sent), /SHARED_SCOPE/);

  const allowedReq = {
    method: 'POST',
    path: '/api/plugins/telemetry/ASSET/abc/SHARED_SCOPE'
  };
  const allowedRes = createMockRes();
  let allowedNext = false;
  await guard(allowedReq, allowedRes, () => { allowedNext = true; });
  assert.equal(allowedNext, true);
});

test('proxy route policy denies unsafe routes by default', () => {
  const policy = createProxyRoutePolicy();

  assert.deepEqual(policy('POST', '/api/auth/login'), { allowed: true, public: true });
  assert.deepEqual(policy('GET', '/api/auth/user'), { allowed: true, public: false });
  assert.equal(policy('GET', '/api/tenant/deviceInfos').allowed, true);
  assert.equal(policy('GET', '/api/tenant/assetInfos').allowed, true);
  assert.equal(policy('GET', '/api/device/types').allowed, true);
  assert.equal(policy('GET', '/api/relations/info').allowed, true);
  assert.equal(policy('POST', '/api/relation').allowed, true);
  assert.equal(policy('POST', '/api/relations').allowed, true);
  assert.equal(policy('DELETE', '/api/relation').allowed, true);
  assert.equal(policy('POST', '/api/relation/delete').allowed, true);
  assert.deepEqual(policy('GET', '/api/any/thingsboard/read/path'), { allowed: true, public: false });
  assert.equal(policy('DELETE', '/api/user/11111111-1111-1111-1111-111111111111').allowed, false);
  assert.equal(policy('POST', '/api/ruleChain').allowed, false);
  assert.equal(policy('POST', '/api/plugins/rpc/oneway/11111111-1111-1111-1111-111111111111').allowed, true);
});

test('proxied write body size policy blocks oversized and chunked bodies', () => {
  assert.equal(validateProxyBodySize({
    method: 'GET',
    headers: {}
  }, 1024), null);

  assert.equal(validateProxyBodySize({
    method: 'POST',
    headers: { 'content-length': '1024' }
  }, 1024), null);

  assert.deepEqual(validateProxyBodySize({
    method: 'POST',
    headers: { 'content-length': '1025' }
  }, 1024), {
    status: 413,
    reason: 'content_length_too_large',
    message: 'Request body too large'
  });

  assert.deepEqual(validateProxyBodySize({
    method: 'PUT',
    headers: { 'transfer-encoding': 'chunked' }
  }, 1024), {
    status: 411,
    reason: 'missing_content_length',
    message: 'Content-Length is required for proxied write requests'
  });
});

test('docker build context excludes operational secrets and local state', () => {
  const dockerignore = fs.readFileSync(path.join(__dirname, '..', '.dockerignore'), 'utf8');
  for (const expected of ['secrets', 'data', 'node_modules', '*.log', '.env']) {
    assert.match(dockerignore, new RegExp(`(^|\\n)${expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\n|$)`));
  }
});

test('security policy strips trusted headers and supports bearer auth forms', () => {
  const headers = {
    authorization: 'Bearer standard',
    'x-twynix-internal-admin': 'attacker-controlled',
    'x-user-id': 'spoofed'
  };

  assert.equal(getBearerTokenFromHeaders(headers), 'standard');
  scrubInboundHeaders(headers);
  assert.equal(headers['x-twynix-internal-admin'], undefined);
  assert.equal(headers['x-user-id'], undefined);
});

test('iotdb query allowlist permits reads and blocks writes', () => {
  assert.equal(isReadOnlyIotdbQuery({ sql: 'SELECT temperature FROM root.sg.d1' }), true);
  assert.equal(isReadOnlyIotdbQuery({ query: 'SHOW TIMESERIES root.sg.**' }), true);
  assert.equal(isReadOnlyIotdbQuery({ sql: 'SELECT * FROM root.sg; DELETE FROM root.sg' }), false);
  assert.equal(isReadOnlyIotdbQuery({ sql: 'DELETE FROM root.sg.d1 WHERE time < now()' }), false);
});

test('iotdb trend structured query builds raw SQL safely', () => {
  const req = normalizeRequest({
    series: [{ id: 'insideTemp', path: 'root.site.line1.device1.temperature' }],
    startTs: 1778200000000,
    endTs: 1778200900000,
    mode: 'raw',
    maxPoints: 2000
  });
  const selected = chooseDataMode(req);

  assert.equal(selected.dataMode, 'RAW');
  assert.equal(
    buildSeriesSql(req.series[0], req, selected),
    'SELECT temperature FROM root.site.line1.device1 WHERE time >= 2026-05-08T00:26:40.000+00:00 AND time < 2026-05-08T00:41:40.000+00:00 LIMIT 2001'
  );
  assert.equal(
    buildShowTimeseriesSql(req.series[0]),
    'SHOW TIMESERIES root.site.line1.device1.temperature'
  );
  assert.equal(
    buildShowDeviceTimeseriesSql(req.series[0]),
    'SHOW TIMESERIES root.site.line1.device1.**'
  );
  assert.equal(
    buildLatestSeriesSql(req.series[0]),
    'SELECT temperature FROM root.site.line1.device1 ORDER BY time DESC LIMIT 5'
  );
});

test('iotdb trend groups raw series on same device into one bounded query', async () => {
  const req = normalizeRequest({
    series: [
      { id: 'temp', path: 'root.site.d1.temperature' },
      { id: 'pressure', path: 'root.site.d1.pressure' }
    ],
    startTs: 100,
    endTs: 500,
    mode: 'raw',
    maxPoints: 2
  });
  const selected = chooseDataMode(req);
  assert.equal(
    buildGroupSql(req.series, req, selected),
    'SELECT temperature, pressure FROM root.site.d1 WHERE time >= 1970-01-01T00:00:00.100+00:00 AND time < 1970-01-01T00:00:00.500+00:00 LIMIT 3'
  );

  const requests = [];
  const ax = {
    post: async (_url, body) => {
      requests.push(body);
      return {
        data: {
          expressions: ['root.site.d1.temperature', 'root.site.d1.pressure'],
          timestamps: [100, 300],
          values: [[21.5, 22], [7.1, 7.2]]
        }
      };
    }
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.equal(requests.length, 1);
  assert.equal(requests[0].row_limit, 3);
  assert.deepEqual(result.series[0].points.map((p) => p.value), [21.5, 22]);
  assert.deepEqual(result.series[1].points.map((p) => p.value), [7.1, 7.2]);
});

test('iotdb trend grouped raw query drops alignment nulls per series', async () => {
  const req = normalizeRequest({
    series: [
      { id: 'temp', path: 'root.site.d1.temperature' },
      { id: 'pressure', path: 'root.site.d1.pressure' }
    ],
    startTs: 100,
    endTs: 500,
    mode: 'raw',
    maxPoints: 10
  });
  const ax = {
    post: async () => ({
      data: {
        expressions: ['root.site.d1.temperature', 'root.site.d1.pressure'],
        timestamps: [100, 200, 300, 400],
        values: [[21.5, null, 22, null], [null, 7.1, null, 7.2]]
      }
    })
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.deepEqual(result.series[0].points.map((p) => ({ ts: p.ts, value: p.value })), [
    { ts: 100, value: 21.5 },
    { ts: 300, value: 22 }
  ]);
  assert.deepEqual(result.series[1].points.map((p) => ({ ts: p.ts, value: p.value })), [
    { ts: 200, value: 7.1 },
    { ts: 400, value: 7.2 }
  ]);
});

test('iotdb trend rejects SQL injection in path', () => {
  assert.throws(() => normalizeRequest({
    series: [{ id: 'bad', path: 'root.site.d1.temperature; DELETE FROM root.sg' }],
    startTs: 1,
    endTs: 2
  }), /Invalid IoTDB path/);
  assert.throws(() => normalizeRequest({
    series: [{ id: 'bad', path: 'root.site.SELECT.temperature' }],
    startTs: 1,
    endTs: 2
  }), /Invalid IoTDB path/);
});

test('iotdb trend rejects invalid time ranges', () => {
  assert.throws(() => normalizeRequest({
    series: [{ id: 'temp', path: 'root.site.d1.temperature' }],
    startTs: 20,
    endTs: 20
  }), /startTs must be less than endTs/);
});

test('iotdb trend auto mode chooses aggregation when estimated raw points exceed maxPoints', () => {
  const req = normalizeRequest({
    series: [{ id: 'temp', path: 'root.site.d1.temperature' }],
    startTs: 0,
    endTs: 60_000,
    mode: 'auto',
    maxPoints: 10,
    aggregation: 'minmax'
  });
  const selected = chooseDataMode(req, { estimatedSampleMs: 1000 });

  assert.equal(selected.dataMode, 'DOWNSAMPLED');
  assert.equal(selected.intervalMs, 6000);
  assert.equal(
    buildSeriesSql(req.series[0], req, selected),
    'SELECT min_value(temperature), max_value(temperature), avg(temperature) FROM root.site.d1 GROUP BY ([1970-01-01T00:00:00.000+00:00, 1970-01-01T00:01:00.000+00:00), 6000ms)'
  );
});

test('iotdb trend supports industrial trend aggregate SQL functions', () => {
  const base = {
    series: [{ id: 'temp', path: 'root.site.d1.temperature' }],
    startTs: 0,
    endTs: 60_000,
    mode: 'aggregated',
    maxPoints: 10
  };
  const selected = { dataMode: 'AGGREGATED', intervalMs: 6000 };

  const cases = [
    ['avg', 'SELECT avg(temperature) FROM root.site.d1 GROUP BY ([1970-01-01T00:00:00.000+00:00, 1970-01-01T00:01:00.000+00:00), 6000ms)'],
    ['min', 'SELECT min_value(temperature) FROM root.site.d1 GROUP BY ([1970-01-01T00:00:00.000+00:00, 1970-01-01T00:01:00.000+00:00), 6000ms)'],
    ['max', 'SELECT max_value(temperature) FROM root.site.d1 GROUP BY ([1970-01-01T00:00:00.000+00:00, 1970-01-01T00:01:00.000+00:00), 6000ms)'],
    ['last', 'SELECT last_value(temperature) FROM root.site.d1 GROUP BY ([1970-01-01T00:00:00.000+00:00, 1970-01-01T00:01:00.000+00:00), 6000ms)'],
    ['range', 'SELECT min_value(temperature), max_value(temperature), avg(temperature) FROM root.site.d1 GROUP BY ([1970-01-01T00:00:00.000+00:00, 1970-01-01T00:01:00.000+00:00), 6000ms)']
  ];

  for (const [aggregation, sql] of cases) {
    const req = normalizeRequest({ ...base, aggregation });
    assert.equal(buildSeriesSql(req.series[0], req, selected), sql);
  }
});

test('iotdb trend minmax aggregation preserves min and max result shape', async () => {
  const req = normalizeRequest({
    series: [{ id: 'temp', path: 'root.site.d1.temperature' }],
    startTs: 0,
    endTs: 60_000,
    mode: 'aggregated',
    maxPoints: 2,
    aggregation: 'minmax'
  });
  const ax = {
    post: async () => ({
      data: {
        columns: ['Time', 'min_value(root.site.d1.temperature)', 'max_value(root.site.d1.temperature)', 'avg(root.site.d1.temperature)'],
        values: [[0, 10, 30, 20], [30000, 12, 42, 24]]
      }
    })
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.equal(result.dataMode, 'AGGREGATED');
  assert.deepEqual(result.series[0].points[0], {
    ts: 0,
    value: 20,
    min: 10,
    max: 30,
    avg: 20,
    quality: 'GOOD',
    dataMode: 'AGGREGATED'
  });
});

test('iotdb trend range aggregation derives value from min and max', async () => {
  const req = normalizeRequest({
    series: [{ id: 'temp', path: 'root.site.d1.temperature' }],
    startTs: 0,
    endTs: 60_000,
    mode: 'aggregated',
    maxPoints: 2,
    aggregation: 'range'
  });
  const ax = {
    post: async () => ({
      data: {
        columns: ['Time', 'min_value(root.site.d1.temperature)', 'max_value(root.site.d1.temperature)', 'avg(root.site.d1.temperature)'],
        values: [[0, 10, 30, 20], [30000, 12, 42, 24]]
      }
    })
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.equal(result.dataMode, 'AGGREGATED');
  assert.deepEqual(result.series[0].points[0], {
    ts: 0,
    value: 20,
    min: 10,
    max: 30,
    avg: 20,
    quality: 'GOOD',
    dataMode: 'AGGREGATED'
  });
});

test('iotdb trend returns separate point arrays for multiple series', async () => {
  const req = normalizeRequest({
    series: [
      { id: 'temp', path: 'root.site.d1.temperature' },
      { id: 'pressure', path: 'root.site.d2.pressure' }
    ],
    startTs: 100,
    endTs: 500,
    mode: 'raw'
  });
  const ax = {
    post: async (_url, body) => {
      if (body.sql.includes('temperature')) {
        return { data: { timestamps: [100, 300], values: [[21.5, 22]] } };
      }
      return { data: { timestamps: [200], values: [[7.2]] } };
    }
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.equal(result.series.length, 2);
  assert.deepEqual(result.series[0].points.map((p) => p.ts), [100, 300]);
  assert.deepEqual(result.series[1].points.map((p) => p.ts), [200]);
});

test('iotdb trend normalizes column-oriented values with columns', async () => {
  const req = normalizeRequest({
    series: [{ id: 'temp', path: 'root.site.d1.temperature' }],
    startTs: 100,
    endTs: 500,
    mode: 'raw'
  });
  const ax = {
    post: async () => ({
      data: {
        columns: ['Time', 'root.site.d1.temperature'],
        values: [[100, 300], [21.5, 22]]
      }
    })
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.deepEqual(result.series[0].points.map((p) => ({ ts: p.ts, value: p.value })), [
    { ts: 100, value: 21.5 },
    { ts: 300, value: 22 }
  ]);
});

test('iotdb trend reports IoTDB body-level errors as failed series', async () => {
  const req = normalizeRequest({
    series: [{ id: 'temp', path: 'root.site.d1.temperature' }],
    startTs: 100,
    endTs: 500,
    mode: 'raw'
  });
  const ax = {
    post: async () => ({ data: { code: 407, message: 'unsupported query' } })
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.equal(result.series.length, 0);
  assert.deepEqual(result.errors, [{
    id: 'temp',
    path: 'root.site.d1.temperature',
    error: 'COMM_LOST',
    message: 'Failed to query series'
  }]);
});

test('iotdb trend reports partial results when one series fails', async () => {
  const req = normalizeRequest({
    series: [
      { id: 'temp', path: 'root.site.d1.temperature' },
      { id: 'pressure', path: 'root.site.d2.pressure' }
    ],
    startTs: 100,
    endTs: 500,
    mode: 'raw'
  });
  const ax = {
    post: async (_url, body) => {
      if (body.sql.includes('pressure')) throw new Error('iotdb unavailable');
      return { data: { columns: ['Time', 'temperature'], values: [[100, 21.5]] } };
    }
  };

  const result = await executeTrendQuery(req, {
    ax,
    config: { IOTDB_URL: 'http://iotdb.local', IOTDB_AUTH: 'basic' }
  });

  assert.equal(result.dataMode, 'PARTIAL');
  assert.equal(result.series.length, 1);
  assert.deepEqual(result.errors, [{
    id: 'pressure',
    path: 'root.site.d2.pressure',
    error: 'COMM_LOST',
    message: 'Failed to query series'
  }]);
});

test('iotdb schema handler caches collected schema', async () => {
  let calls = 0;
  const handler = createIotdbSchemaHandler({
    requireValidUser: async () => ({ userId: 'u1' }),
    config: {
      IOTDB_URL: 'http://iotdb.local',
      IOTDB_AUTH: 'basic',
      IOTDB_SCHEMA_CACHE_TTL_MS: 60_000,
      IOTDB_SCHEMA_ROW_LIMIT: 50
    },
    ax: {
      post: async (_url, body) => {
        calls += 1;
        assert.equal(body.row_limit, 50);
        if (body.sql === 'SHOW DATABASES') {
          return { data: { column_names: ['Database'], values: [['root.site']] } };
        }
        if (body.sql === 'SHOW STORAGE GROUP') {
          return { data: { code: 407, message: 'unsupported' } };
        }
        if (body.sql === 'SHOW DEVICES root.site.**') {
          return { data: { column_names: ['Device'], values: [['root.site.d1']] } };
        }
        if (body.sql === 'SHOW TIMESERIES root.site.**') {
          return {
            data: {
              column_names: ['Timeseries', 'DataType', 'Encoding', 'Compression'],
              values: [['root.site.d1.temperature'], ['FLOAT'], ['GORILLA'], ['SNAPPY']]
            }
          };
        }
        throw new Error(`unexpected sql ${body.sql}`);
      }
    }
  });

  const first = await runHandler(handler, { headers: {} });
  const second = await runHandler(handler, { headers: {} });

  assert.equal(first.statusCode, 200);
  assert.deepEqual(second.sent, first.sent);
  assert.equal(calls, 4);
  assert.deepEqual(first.sent.devices, ['root.site.d1']);
  assert.deepEqual(first.sent.timeseries.map((row) => row.path), ['root.site.d1.temperature']);
});

test('readEnvSecret prefers file-based secrets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iotdbproxy-secret-'));
  const file = path.join(dir, 'secret.txt');
  fs.writeFileSync(file, ' file-secret \n', 'utf8');

  assert.equal(readEnvSecret('TB_ADMIN_PASSWORD', {
    TB_ADMIN_PASSWORD: 'env-secret',
    TB_ADMIN_PASSWORD_FILE: file
  }), 'file-secret');
  assert.equal(readEnvSecret('TB_ADMIN_PASSWORD', {
    TB_ADMIN_PASSWORD: 'env-secret'
  }), 'env-secret');
});

test('rpc policy validates method, tags, scalar params, and method rules', () => {
  const policy = buildRpcPolicy({
    RPC_ALLOWED_METHODS: ['writeTag'],
    RPC_ALLOWED_TAGS: 'pump.speed,pump.enabled',
    RPC_TIMEOUT_MAX_MS: 5000,
    RPC_METHOD_PARAM_RULES: JSON.stringify({
      writeTag: {
        required: ['tag', 'value'],
        allowedKeys: ['tag', 'value'],
        types: { tag: 'string', value: 'number' },
        ranges: { value: { min: 0, max: 100 } }
      }
    })
  });

  assert.equal(validateRpcBody({
    method: 'writeTag',
    params: { tag: 'pump.speed', value: 42 },
    timeout: 1000
  }, 'twoway', policy), null);

  assert.match(validateRpcBody({
    method: 'reboot',
    params: {}
  }, 'oneway', policy), /method/);

  assert.match(validateRpcBody({
    method: 'writeTag',
    params: { tag: 'pump.secret', value: 42 }
  }, 'oneway', policy), /tag/);

  assert.match(validateRpcBody({
    method: 'writeTag',
    params: { tag: 'pump.speed', value: 200 }
  }, 'oneway', policy), /above maximum/);
});

test('config validation catches production unsafe settings', () => {
  const base = {
    NODE_ENV: 'production',
    PORT: 8787,
    THINGSBOARD_URL: 'http://tb.local',
    TB_ADMIN_USERNAME: 'svc@example.local',
    TB_ADMIN_PASSWORD: 'secret',
    IOTDB_URL: 'http://iotdb.local',
    IOTDB_AUTH: 'basic',
    ACL_TTL_MS: 60000,
    MAX_CACHE_ENTRIES: 5000,
    AXIOS_TIMEOUT_MS: 15000,
    PROXY_MAX_BODY_BYTES: 1048576,
    RPC_ALLOWED_METHODS: ['writeTag'],
    RPC_TIMEOUT_MAX_MS: 15000,
    RPC_RATE_WINDOW_MS: 1000,
    RPC_RATE_MAX: 5,
    RPC_MAX_BODY_BYTES: 16384,
    RPC_ACL_ENABLED: true,
    INTERNAL_PROXY_SECRET: 'internal',
    AUDIT_HMAC_SECRET: 'audit',
    OPLOG_MAX_WINDOW_MS: 60000,
    IOTDB_SCHEMA_CACHE_TTL_MS: 60000,
    IOTDB_SCHEMA_ROW_LIMIT: 10000
  };

  assert.deepEqual(validateConfig(base).errors, []);

  const unsafe = validateConfig({ ...base, RPC_ACL_ENABLED: false, AUDIT_HMAC_SECRET: '' });
  assert(unsafe.errors.includes('RPC_ACL_ENABLED cannot be disabled in production'));
  assert(unsafe.errors.includes('Missing required env var in production: AUDIT_HMAC_SECRET'));
});
