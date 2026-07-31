const test = require('node:test');
const assert = require('node:assert/strict');

const { createAlarmAckGuard } = require('../src/alarm-ack-guard');

const ALARM_ID = '11111111-2222-4333-8444-555555555555';

function response() {
  return {
    statusCode: 200,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    }
  };
}

function request(path = `/api/alarm/${ALARM_ID}/ack`) {
  return { method: 'POST', path };
}

function auth(tenantId = 'tenant-a') {
  return async (req) => {
    req.__twynixAuth = { tenantId, userId: 'user-a' };
    return { tenantId, userId: 'user-a', userToken: 'jwt-a' };
  };
}

test('alarm ACK guard verifies alarm access and tenant before forwarding', async () => {
  let checkedUrl = '';
  let checkedHeaders;
  const events = [];
  const guard = createAlarmAckGuard({
    ax: {
      async get(url, options) {
        checkedUrl = url;
        checkedHeaders = options.headers;
        return { data: { tenantId: { entityType: 'TENANT', id: 'tenant-a' } } };
      }
    },
    thingsboardUrl: 'http://thingsboard/',
    requireValidUser: auth(),
    emitAuditEvent: async (req, event) => events.push(event)
  });
  const req = request();
  const res = response();
  let forwarded = false;

  await guard(req, res, () => { forwarded = true; });

  assert.equal(forwarded, true);
  assert.equal(req.__twynixProxyGuard, 'alarmAck');
  assert.equal(checkedUrl, `http://thingsboard/api/alarm/${ALARM_ID}`);
  assert.equal(checkedHeaders['X-Authorization'], 'Bearer jwt-a');
  assert.equal(events.at(-1).outcome, 'allowed');
});

test('alarm ACK guard rejects cross-tenant alarms', async () => {
  const guard = createAlarmAckGuard({
    ax: { get: async () => ({ data: { tenantId: { id: 'tenant-b' } } }) },
    thingsboardUrl: 'http://thingsboard',
    requireValidUser: auth('tenant-a')
  });
  const req = request();
  const res = response();
  let forwarded = false;

  await guard(req, res, () => { forwarded = true; });

  assert.equal(forwarded, false);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { error: 'Forbidden: alarm tenant mismatch' });
});

test('alarm ACK guard preserves access denial without forwarding', async () => {
  const guard = createAlarmAckGuard({
    ax: {
      async get() {
        const error = new Error('denied');
        error.response = { status: 404 };
        throw error;
      }
    },
    thingsboardUrl: 'http://thingsboard',
    requireValidUser: auth()
  });
  const req = request();
  const res = response();
  let forwarded = false;

  await guard(req, res, () => { forwarded = true; });

  assert.equal(forwarded, false);
  assert.equal(res.statusCode, 404);
  assert.deepEqual(res.body, { error: 'Alarm access denied' });
});

test('alarm ACK guard ignores malformed IDs and unrelated routes', async () => {
  let authCalled = false;
  const guard = createAlarmAckGuard({
    ax: { get: async () => ({ data: {} }) },
    thingsboardUrl: 'http://thingsboard',
    requireValidUser: async () => {
      authCalled = true;
      return null;
    }
  });
  const res = response();
  let forwarded = false;

  await guard(request('/api/alarm/not-a-uuid/ack'), res, () => { forwarded = true; });

  assert.equal(forwarded, true);
  assert.equal(authCalled, false);
});
