'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createProxyRoutePolicy, getBearerTokenFromHeaders } = require('../src/security-policy');
const { buildRpcPolicy, validateRpcBody } = require('../src/rpc-policy');
const { rewriteThingsBoardRpcPath } = require('../src/rpc-forwarding');
const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
const deviceId = '11111111-2222-4333-8444-555555555555';

// Exercise the actual middleware and proxy hooks, without starting production
// services, loading credentials, reading security attributes or sending device RPC.
function harness(options = {}) {
  const events = [], logs = [], tokens = [];
  const context = {
    config: { RPC_REQUIRE_AUDIT: !!options.requireAudit, THINGSBOARD_URL: 'http://unused.invalid' },
    rpcPolicy: buildRpcPolicy({ RPC_ALLOWED_METHODS: ['writeTag'], RPC_ALLOWED_TAGS: 'speed', RPC_TIMEOUT_MAX_MS: 30000 }),
    validateRpcBody, getBearerTokenFromHeaders, rewriteThingsBoardRpcPath,
    assertTokenValid: async token => { tokens.push(token); if (options.invalid) throw new Error('Invalid token'); },
    getTenantIdFromToken: () => 'tenant-a', getUserIdFromToken: () => options.missingUser ? null : 'user-a',
    checkRpcRateLimit: (user, device) => { assert.equal(user, 'user-a'); assert.equal(device, deviceId); return !options.rateLimited; },
    emitRpcAuditEvent: async (_req, event) => { events.push(event); return { ok: !options.auditFailure }; },
    emitAuditEvent: async (_req, event) => { events.push(event); if (options.responseAuditFailure) throw new Error('Journal offline'); return { ok: true }; },
    logSecurityEvent: (type, event) => logs.push({ type, ...event }),
    // Any remaining dependency on the legacy ACL must fail this test.
    fetchServerAttributesArrayCached: () => { throw new Error('Must not read attribute ACL'); },
    getAdminToken: () => { throw new Error('Must not elevate identity'); },
    serviceState: {}, console: { log() {}, error() {} },
    createProxyMiddleware: config => config, fixRequestBody() {}
  };
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf('async function rpcPermissionMiddleware('), source.indexOf('\n/*', source.indexOf('function auditRpcResponse('))), context);
  vm.runInContext(source.slice(source.indexOf('const tbProxy ='), source.indexOf('const tbWsProxy =')).replace('const tbProxy =', 'var proxyOptions ='), context);
  assert.match(source, /app\.use\(\['\/api\/plugins\/rpc', '\/api\/rpc'\], express\.json/);
  assert.match(source, /rpcPermissionMiddleware\(req, res, next\)/);
  return { context, events, logs, tokens, run: context.rpcPermissionMiddleware, proxy: context.proxyOptions };
}

function request(prefix = '/api/rpc', mode = 'twoway', headers = { 'x-authorization': 'Bearer caller-token' }) {
  const route = `${prefix}/${mode}/${deviceId}`;
  return { path: route, url: route, method: 'POST', headers, body: { method: 'writeTag', params: { tag: 'speed', value: 1200 }, timeout: 10000 } };
}
function response() { return { statusCode: 200, status(code) { this.statusCode = code; return this; }, send(body) { this.body = body; return this; } }; }

test('native and legacy RPC paths require the transport guard and POST', () => {
  const policy = createProxyRoutePolicy();
  for (const prefix of ['/api/rpc', '/api/plugins/rpc']) for (const mode of ['oneway', 'twoway']) {
    const route = request(prefix, mode).path;
    assert.deepEqual(policy('POST', route), { allowed: true, public: false, guard: 'native-rpc' });
    for (const method of ['PUT', 'PATCH', 'DELETE']) assert.equal(policy(method, route).allowed, false);
  }
});

test('forwards both RPC APIs with the original user token without attribute ACL or administrator identity', async () => {
  for (const prefix of ['/api/rpc', '/api/plugins/rpc']) for (const mode of ['oneway', 'twoway']) {
    const h = harness(), req = request(prefix, mode, { authorization: 'Bearer caller-token' });
    let forwarded = false;
    await h.run(req, response(), () => forwarded = true);
    assert.equal(forwarded, true);
    assert.deepEqual(h.tokens, ['caller-token']);
    assert.equal(req.headers['x-authorization'], 'Bearer caller-token');
    assert.equal(req.headers.authorization, undefined);
    assert.equal(req.__twynixProxyGuard, 'native-rpc');
    assert.equal(h.events[0].outcome, 'forwarded');
    assert.equal(h.events[0].reason, 'pending_thingsboard_authorization');
    assert.equal(h.proxy.pathRewrite(req.path), `/api/rpc/${mode}/${deviceId}`);
  }
});

test('validation, authentication, rate limits and required pre-forward audit still fail closed', async () => {
  for (const scenario of [
    { headers: {}, status: 401 }, { invalid: true, status: 401 }, { missingUser: true, status: 401 },
    { rateLimited: true, status: 429 }, { requireAudit: true, auditFailure: true, status: 503 },
    { body: { method: 'unlisted', params: {} }, status: 400 },
    { body: { method: 'writeTag', params: { tag: 'other' } }, status: 400 },
    { body: { method: 'writeTag', params: {}, timeout: 999999 }, status: 400 }
  ]) {
    const h = harness(scenario), req = request(), res = response();
    if (scenario.headers) req.headers = scenario.headers;
    if (scenario.body) req.body = scenario.body;
    let forwarded = false;
    await h.run(req, res, () => forwarded = true);
    assert.equal(res.statusCode, scenario.status);
    assert.equal(forwarded, false);
    assert.equal(req.__twynixProxyGuard, undefined);
  }
});

test('the proxy hooks preserve upstream status/body and audit denial separately from forwarding', async () => {
  for (const statusCode of [200, 401, 403, 504]) {
    const h = harness(), req = request();
    await h.run(req, response(), () => {});
    const upstream = { statusCode, body: '{"message":"response from TB"}' };
    const before = JSON.stringify(upstream);
    h.proxy.on.proxyRes(upstream, req);
    assert.equal(JSON.stringify(upstream), before);
    assert.equal(h.proxy.selfHandleResponse, undefined);
    assert.equal(h.events[1].reason, `thingsboard_http_${statusCode}`);
    assert.equal(h.events[1].outcome, statusCode === 200 ? 'response_received' : statusCode === 504 ? 'error' : 'denied');
  }
});

test('proxy request hook does not inject credentials; X-Authorization wins over conflicting Authorization', async () => {
  const h = harness(), req = request('/api/rpc', 'twoway', { 'x-authorization': 'Bearer caller-token', authorization: 'Bearer conflicting-token' });
  await h.run(req, response(), () => {});
  const headers = { ...req.headers };
  h.proxy.on.proxyReq({ removeHeader: key => delete headers[key] }, req);
  assert.equal(headers['x-authorization'], 'Bearer caller-token');
  assert.equal(headers.authorization, undefined);
});

test('response audit failures do not throw or retry an RPC, transport failures report uncertain delivery', async () => {
  const h = harness({ responseAuditFailure: true }), req = request();
  await h.run(req, response(), () => {});
  h.proxy.on.proxyRes({ statusCode: 200 }, req);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.context.serviceState.lastAuditError, 'Journal offline');
  const res = response(); h.proxy.on.error(new Error('Connection lost'), req, res);
  assert.equal(res.statusCode, 502);
  assert.equal(h.events.at(-1).reason, 'upstream_transport_error_delivery_uncertain');
  await new Promise(resolve => setImmediate(resolve));
});

test('HTTP integration preserves caller identity, JSON body, and ThingsBoard 403 responses', async t => {
  const http = require('node:http');
  const express = require('express');
  const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
  const received = [];
  const upstream = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      received.push({ url: req.url, headers: req.headers, body: JSON.parse(body) });
      res.writeHead(req.headers['x-authorization'] === 'Bearer denied-user' ? 403 : 200, { 'content-type': 'application/json' });
      res.end(req.headers['x-authorization'] === 'Bearer denied-user' ? '{"message":"RPC Call denied"}' : '{"accepted":true}');
    });
  });
  async function listen(server) {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
    return `http://127.0.0.1:${server.address().port}`;
  }
  const target = await listen(upstream), h = harness();
  h.context.fixRequestBody = fixRequestBody;
  const app = express(), policy = createProxyRoutePolicy();
  app.use(express.json());
  app.use((req, res, next) => Promise.resolve(h.run(req, res, next)).catch(next));
  app.use((req, res, next) => {
    const result = policy(req.method, req.path);
    if (!result.allowed || result.guard !== req.__twynixProxyGuard) return res.sendStatus(403);
    next();
  });
  app.use(createProxyMiddleware({ ...h.proxy, target }));
  const proxyUrl = await listen(http.createServer(app));
  for (const [prefix, token, expected] of [['/api/plugins/rpc', 'caller-token', 200], ['/api/rpc', 'denied-user', 403]]) {
    const body = request().body;
    const response = await fetch(`${proxyUrl}${prefix}/twoway/${deviceId}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'x-twynix-internal-admin': 'spoofed' }, body: JSON.stringify(body) });
    assert.equal(response.status, expected);
    assert.deepEqual(await response.json(), expected === 403 ? { message: 'RPC Call denied' } : { accepted: true });
    assert.equal(received.at(-1).headers['x-authorization'], `Bearer ${token}`);
    assert.equal(received.at(-1).headers['x-twynix-internal-admin'], undefined);
    assert.equal(received.at(-1).url, `/api/rpc/twoway/${deviceId}`);
    assert.deepEqual(received.at(-1).body, body);
  }
  assert.equal(received.length, 2); // no retries, ACL fetches or administrator calls
});
