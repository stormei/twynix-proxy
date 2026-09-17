const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {
  createProxyRoutePolicy,
  TWIN_CONFIGURATION_RULES,
  hasAllowedManagementRole,
  getBearerTokenFromHeaders
} = require('../src/security-policy');

const routes = [
  '/api/calculatedField',
  '/api/calculatedField/testScript',
  '/api/alarm/rule/testScript'
];

test('twin configuration permits only the required authenticated POST routes', () => {
  const policy = createProxyRoutePolicy();
  for (const route of routes) {
    assert.deepEqual(policy('POST', route), { allowed: true, public: false });
    assert.deepEqual(policy('POST', `${route}?example=1`), { allowed: true, public: false });
    for (const method of ['PUT', 'PATCH', 'DELETE']) assert.equal(policy(method, route).allowed, false);
    for (const suffix of ['/', '/delete', '/recalculate', 'Other']) assert.equal(policy('POST', route + suffix).allowed, false);
    assert.equal(policy('POST', route.toLowerCase()).allowed, false);
  }
  for (const route of ['/api/calculatedFields', '/api/alarm/rule', '/api/ruleChain', '/api/calculatedField/11111111-2222-4333-8444-555555555555']) {
    assert.equal(policy('POST', route).allowed, false);
  }
});

test('twin read APIs remain authenticated and existing relation and manifest policies remain intact', () => {
  const policy = createProxyRoutePolicy();
  const id = '11111111-2222-4333-8444-555555555555';
  for (const route of [
    `/api/calculatedField/ASSET/${id}?page=0&pageSize=100`,
    `/api/relations?fromId=${id}&fromType=ASSET`,
    `/api/plugins/telemetry/ASSET/${id}/values/attributes/SERVER_SCOPE?keys=twynixCeDeployment`
  ]) assert.deepEqual(policy('GET', route), { allowed: true, public: false });
  assert.deepEqual(policy('POST', '/api/relation'), { allowed: true, public: false });
  assert.deepEqual(policy('POST', `/api/plugins/telemetry/ASSET/${id}/SERVER_SCOPE`), { allowed: true, public: false });
});

test('twin configuration requires tenant admin even with broader configured management roles', () => {
  for (const policy of TWIN_CONFIGURATION_RULES) {
    assert.equal(hasAllowedManagementRole(['TENANT_ADMIN'], ['TENANT_ADMIN'], policy), true);
    assert.equal(hasAllowedManagementRole(['CUSTOMER_USER'], ['CUSTOMER_USER'], policy), false);
    assert.equal(hasAllowedManagementRole(['SYS_ADMIN'], ['SYS_ADMIN'], policy), false);
    assert.equal(hasAllowedManagementRole([], ['TENANT_ADMIN'], policy), false);
    assert.equal(hasAllowedManagementRole(['TENANT_ADMIN'], [], policy), false);
  }
  assert.equal(hasAllowedManagementRole(['CUSTOM_ROLE'], ['CUSTOM_ROLE'], {}), true);
});

// Exercise the actual middleware without starting the app, creating databases,
// loading credentials, or contacting ThingsBoard. Keep the wiring assertion so a
// policy-only test cannot pass while the live middleware omits these rules.
function managementMiddleware(options = {}) {
  const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  const begin = source.indexOf("const UUID_RX = '[0-9a-fA-F-]{36}';");
  const end = source.indexOf('app.use(writePolicyMiddleware);', begin);
  assert.ok(begin >= 0 && end > begin);
  const code = source.slice(begin, end);
  assert.match(code, /\.\.\.TWIN_CONFIGURATION_RULES/);
  const events = [];
  const context = {
    TWIN_CONFIGURATION_RULES, hasAllowedManagementRole, getBearerTokenFromHeaders,
    config: { MGMT_ALLOWED_ROLES: options.roles || ['TENANT_ADMIN'] },
    assertTokenValid: async () => { if (options.invalid) throw new Error('Invalid token'); },
    getTenantIdFromToken: () => 'tenant-a', getUserIdFromToken: () => 'user-a',
    getUserAuthoritiesFromToken: () => options.authorities || ['TENANT_ADMIN'],
    emitAuditEvent: async (_req, event) => events.push(event),
    console: { error: () => {} }
  };
  vm.createContext(context);
  vm.runInContext(code, context);
  return { run: context.writePolicyMiddleware, events };
}

test('management middleware authenticates, authorizes and audits all three twin routes', async () => {
  for (const route of routes) {
    for (const scenario of [
      { token: true, expected: 200 },
      { token: false, expected: 401 },
      { token: true, authorities: ['CUSTOMER_USER'], roles: ['CUSTOMER_USER'], expected: 403 },
      { token: true, invalid: true, expected: 500 }
    ]) {
      const { run, events } = managementMiddleware(scenario);
      const req = { path: route, method: 'POST', headers: scenario.token ? { 'x-authorization': 'Bearer test-user-token' } : {} };
      const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, send() { return this; } };
      let forwarded = false;
      await run(req, res, () => { forwarded = true; });
      assert.equal(res.statusCode, scenario.expected);
      assert.equal(forwarded, scenario.expected === 200);
      assert.equal(req.__allowedMgmtWrite === true, scenario.expected === 200);
      assert.equal(events.length, 1);
      assert.equal(events[0].type, 'mgmt_write');
      assert.equal(req.headers['x-authorization'], scenario.token ? 'Bearer test-user-token' : undefined);
    }
  }
});
