const test = require('node:test');
const assert = require('node:assert/strict');
const { createProxyRoutePolicy } = require('../src/security-policy');

test('entity search permits only the exact authenticated POST query', () => {
  const policy = createProxyRoutePolicy();
  assert.deepEqual(policy('POST', '/api/entitiesQuery/find'), { allowed: true, public: false });
  for (const method of ['PUT', 'PATCH', 'DELETE']) {
    assert.equal(policy(method, '/api/entitiesQuery/find').allowed, false);
  }
  assert.equal(policy('POST', '/api/entitiesQuery/delete').allowed, false);
  assert.equal(policy('POST', '/api/entitiesQuery/find/other').allowed, false);
});
