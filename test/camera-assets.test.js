const test = require('node:test');
const assert = require('node:assert/strict');

const {
  CAMERA_ASSET_TYPE,
  buildServerAttributes,
  buildServerPatch,
  buildSharedAttributes,
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
