const test = require('node:test');
const assert = require('node:assert/strict');

const {
  CAMERA_ASSET_TYPE,
  buildDirectSnapshotRequest,
  buildServerAttributes,
  buildServerPatch,
  buildSharedAttributes,
  buildShinobiSnapshotUrl,
  nonImagePreviewError,
  sanitizeCamera
} = require('../src/camera-assets');

test('sanitizeCamera returns only safe camera DTO fields', () => {
  const dto = sanitizeCamera(
    {
      id: { id: 'camera-1', entityType: 'ASSET' },
      name: 'North Gate',
      type: CAMERA_ASSET_TYPE,
      createdTime: 123
    },
    {
      label: 'Gate',
      location: 'North entrance',
      description: 'Overview camera',
      enabled: true,
      supportsLive: true
    },
    {
      provider: 'shinobi',
      preferredStream: 'hls',
      shinobiApiKey: 'must-not-leak',
      shinobiGroupKey: 'must-not-leak',
      shinobiBaseUrl: 'http://secret.local'
    }
  );

  assert.deepEqual(dto, {
    id: 'camera-1',
    name: 'North Gate',
    type: CAMERA_ASSET_TYPE,
    createdTime: 123,
    provider: 'shinobi',
    preferredStream: 'hls',
    label: 'Gate',
    location: 'North entrance',
    description: 'Overview camera',
    enabled: true,
    supportsLive: true
  });
  assert.equal(Object.hasOwn(dto, 'shinobiApiKey'), false);
  assert.equal(Object.hasOwn(dto, 'shinobiGroupKey'), false);
  assert.equal(Object.hasOwn(dto, 'shinobiBaseUrl'), false);
});

test('buildServerAttributes validates required Shinobi fields on create', () => {
  assert.throws(
    () => buildServerAttributes({ provider: 'shinobi', preferredStream: 'mjpeg' }, { requireSecrets: true }),
    /Missing required camera field/
  );

  const attrs = buildServerAttributes({
    provider: 'shinobi',
    preferredStream: 'mp4',
    shinobiBaseUrl: 'http://shinobi.local',
    shinobiApiKey: 'api',
    shinobiGroupKey: 'group',
    shinobiMonitorId: 'monitor',
    shinobiChannel: '0'
  }, { requireSecrets: true });

  assert.equal(attrs.provider, 'shinobi');
  assert.equal(attrs.preferredStream, 'mp4');
  assert.equal(attrs.shinobiApiKey, 'api');
});

test('buildServerAttributes validates required direct snapshot fields on create', () => {
  assert.throws(
    () => buildServerAttributes({ provider: 'direct', preferredStream: 'mjpeg' }, { requireSecrets: true }),
    /Direct snapshot URL/
  );

  assert.throws(
    () => buildServerAttributes({
      provider: 'direct',
      preferredStream: 'mjpeg',
      directSnapshotUrl: 'http://camera.local/snapshot.jpg',
      directAuthMode: 'basic',
      directUsername: 'operator'
    }, { requireSecrets: true }),
    /Direct camera password/
  );

  const attrs = buildServerAttributes({
    provider: 'direct',
    preferredStream: 'mjpeg',
    directSnapshotUrl: 'http://camera.local/snapshot.jpg',
    directAuthMode: 'none'
  }, { requireSecrets: true });

  assert.equal(attrs.provider, 'direct');
  assert.equal(attrs.directSnapshotUrl, 'http://camera.local/snapshot.jpg');
  assert.equal(attrs.directAuthMode, 'none');
});

test('camera attribute builders trim strings and ignore blank secret updates', () => {
  assert.deepEqual(buildSharedAttributes({
    label: '  Packaging  ',
    description: '  Line overview  ',
    enabled: true,
    supportsPtz: false
  }), {
    label: 'Packaging',
    description: 'Line overview',
    enabled: true,
    supportsPtz: false
  });

  assert.deepEqual(buildServerPatch({
    provider: 'shinobi',
    preferredStream: 'hls',
    shinobiApiKey: '   ',
    shinobiMonitorId: ' mon-1 '
  }), {
    provider: 'shinobi',
    preferredStream: 'hls',
    shinobiMonitorId: 'mon-1'
  });
});

test('buildShinobiSnapshotUrl builds preview URL without query secrets', () => {
  assert.equal(buildShinobiSnapshotUrl({
    shinobiBaseUrl: 'https://shinobi.local/',
    shinobiApiKey: 'api key',
    shinobiGroupKey: 'group',
    shinobiMonitorId: 'monitor/1',
    shinobiChannel: '1'
  }), 'https://shinobi.local/api%20key/jpeg/group/monitor%2F1/s.jpg?channel=1');
});

test('buildShinobiSnapshotUrl rejects unsafe Shinobi base URLs', () => {
  assert.throws(
    () => buildShinobiSnapshotUrl({
      shinobiBaseUrl: 'ftp://shinobi.local',
      shinobiApiKey: 'api',
      shinobiGroupKey: 'group',
      shinobiMonitorId: 'monitor'
    }),
    /http or https/
  );

  assert.throws(
    () => buildShinobiSnapshotUrl({
      shinobiBaseUrl: 'https://user:pass@shinobi.local',
      shinobiApiKey: 'api',
      shinobiGroupKey: 'group',
      shinobiMonitorId: 'monitor'
    }),
    /embedded credentials/
  );
});

test('buildDirectSnapshotRequest supports optional Basic Auth without embedded URL credentials', () => {
  const req = buildDirectSnapshotRequest({
    directSnapshotUrl: 'http://camera.local/snapshot.jpg?quality=80',
    directAuthMode: 'basic',
    directUsername: 'viewer',
    directPassword: 'secret'
  });

  assert.equal(req.url, 'http://camera.local/snapshot.jpg?quality=80');
  assert.equal(req.headers.authorization, 'Basic dmlld2VyOnNlY3JldA==');

  assert.throws(
    () => buildDirectSnapshotRequest({
      directSnapshotUrl: 'http://user:pass@camera.local/snapshot.jpg',
      directAuthMode: 'none'
    }),
    /embedded credentials/
  );
});

test('nonImagePreviewError maps Shinobi authorization JSON to clean 401', () => {
  const err = nonImagePreviewError('application/json', Buffer.from(JSON.stringify({
    ok: false,
    msg: 'Not Authorized'
  })));

  assert.equal(err.status, 401);
  assert.equal(err.message, 'Shinobi rejected camera snapshot request: Not Authorized.');
});
