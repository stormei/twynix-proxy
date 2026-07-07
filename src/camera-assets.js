const CAMERA_ASSET_TYPE = '$CAMERA';

const CAMERA_SHARED_KEYS = [
  'label',
  'location',
  'description',
  'manufacturer',
  'model',
  'supportsLive',
  'supportsSnapshot',
  'supportsPlayback',
  'supportsPtz',
  'enabled'
];

const CAMERA_SERVER_KEYS = [
  'provider',
  'shinobiBaseUrl',
  'shinobiApiKey',
  'shinobiGroupKey',
  'shinobiMonitorId',
  'shinobiChannel',
  'directSnapshotUrl',
  'directAuthMode',
  'directUsername',
  'directPassword',
  'preferredStream'
];

const SAFE_SERVER_KEYS = ['provider', 'preferredStream'];
const CAMERA_PROVIDERS = new Set(['shinobi', 'direct']);
const CAMERA_STREAM_KINDS = new Set(['mjpeg', 'hls', 'mp4']);
const DIRECT_AUTH_MODES = new Set(['none', 'basic']);
const CAMERA_PREVIEW_TIMEOUT_MS = 10000;
const CAMERA_PREVIEW_MAX_BYTES = 10 * 1024 * 1024;

function text(value, max = 512) {
  if (value === undefined || value === null) return undefined;
  const out = String(value).trim();
  return out ? out.slice(0, max) : undefined;
}

function bool(value) {
  if (value === undefined || value === null) return undefined;
  return value === true;
}

function attrsArrayToMap(attrs) {
  const out = {};
  for (const attr of Array.isArray(attrs) ? attrs : []) {
    if (attr && typeof attr.key === 'string') out[attr.key] = attr.value;
  }
  return out;
}

function entityId(entity) {
  if (!entity) return '';
  if (typeof entity.id === 'string') return entity.id;
  if (entity.id && typeof entity.id.id === 'string') return entity.id.id;
  return '';
}

function sanitizeShinobiBaseUrl(value) {
  const raw = text(value, 1024);
  if (!raw) throw new Error('Shinobi base URL is required.');

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('Shinobi base URL must be a valid URL.');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Shinobi base URL must use http or https.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Shinobi base URL must not contain embedded credentials.');
  }
  parsed.hash = '';
  parsed.search = '';
  return parsed.toString().replace(/\/$/, '');
}

function sanitizeDirectSnapshotUrl(value) {
  const raw = text(value, 2048);
  if (!raw) throw new Error('Direct snapshot URL is required.');

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('Direct snapshot URL must be a valid URL.');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Direct snapshot URL must use http or https.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Direct snapshot URL must not contain embedded credentials.');
  }
  parsed.hash = '';
  return parsed.toString();
}

function validateDirectAuthMode(mode) {
  const value = text(mode || 'none', 32) || 'none';
  if (!DIRECT_AUTH_MODES.has(value)) {
    throw new Error('Direct camera auth mode must be none or basic.');
  }
  return value;
}

function pathPart(value, label) {
  const raw = text(value, 256);
  if (!raw) throw new Error(`${label} is required.`);
  return encodeURIComponent(raw);
}

function buildShinobiSnapshotUrl(attrs) {
  const base = sanitizeShinobiBaseUrl(attrs.shinobiBaseUrl);
  const apiKey = pathPart(attrs.shinobiApiKey, 'Shinobi API key');
  const groupKey = pathPart(attrs.shinobiGroupKey, 'Shinobi group key');
  const monitorId = pathPart(attrs.shinobiMonitorId, 'Shinobi monitor ID');
  const channel = text(attrs.shinobiChannel, 256);
  const url = `${base}/${apiKey}/jpeg/${groupKey}/${monitorId}/s.jpg`;
  return channel ? `${url}?channel=${encodeURIComponent(channel)}` : url;
}

function buildDirectSnapshotRequest(attrs) {
  const url = sanitizeDirectSnapshotUrl(attrs.directSnapshotUrl);
  const authMode = validateDirectAuthMode(attrs.directAuthMode);
  const headers = { accept: 'image/jpeg,image/*;q=0.8,*/*;q=0.5' };

  if (authMode === 'basic') {
    const username = text(attrs.directUsername, 256);
    const password = text(attrs.directPassword, 512);
    if (!username) throw new Error('Direct camera username is required for Basic Auth.');
    if (!password) throw new Error('Direct camera password is required for Basic Auth.');
    headers.authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  }

  return { url, headers };
}

function nonImagePreviewError(contentType, body) {
  const type = String(contentType || '').toLowerCase();
  const data = Buffer.isBuffer(body) ? body : Buffer.from(body || '');
  const textBody = data.toString('utf8', 0, Math.min(data.length, 4096)).trim();
  let upstreamMessage = '';

  if (type.includes('json') && textBody) {
    try {
      const parsed = JSON.parse(textBody);
      upstreamMessage = text(parsed?.msg || parsed?.message || parsed?.error, 256) || '';
    } catch {
      upstreamMessage = '';
    }
  }

  const err = new Error(upstreamMessage
    ? `Shinobi rejected camera snapshot request: ${upstreamMessage}.`
    : `Camera provider returned ${contentType || 'a non-image response'} instead of a camera snapshot.`);
  err.status = /not authorized/i.test(upstreamMessage) ? 401 : 502;
  return err;
}

function validateProvider(provider) {
  const value = text(provider, 32);
  if (!value || !CAMERA_PROVIDERS.has(value)) {
    throw new Error('Camera provider is required. Supported providers: shinobi, direct.');
  }
  return value;
}

function validateStreamKind(kind) {
  const value = text(kind, 32);
  if (!value || !CAMERA_STREAM_KINDS.has(value)) {
    throw new Error('Preferred stream is required. Supported streams: mjpeg, hls, mp4.');
  }
  return value;
}

function buildSharedAttributes(body = {}) {
  const attrs = {};
  const stringFields = ['label', 'location', 'description', 'manufacturer', 'model'];
  for (const key of stringFields) {
    const value = text(body[key], key === 'description' ? 2048 : 256);
    if (value !== undefined) attrs[key] = value;
  }
  for (const key of ['supportsLive', 'supportsSnapshot', 'supportsPlayback', 'supportsPtz', 'enabled']) {
    const value = bool(body[key]);
    if (value !== undefined) attrs[key] = value;
  }
  return attrs;
}

function buildServerAttributes(body = {}, { requireSecrets = false } = {}) {
  const provider = validateProvider(body.provider);
  const preferredStream = validateStreamKind(body.preferredStream);
  const attrs = { provider, preferredStream };

  for (const key of [
    'shinobiBaseUrl',
    'shinobiApiKey',
    'shinobiGroupKey',
    'shinobiMonitorId',
    'shinobiChannel',
    'directSnapshotUrl',
    'directAuthMode',
    'directUsername',
    'directPassword'
  ]) {
    const value = text(body[key], key === 'directSnapshotUrl' ? 2048 : key === 'shinobiBaseUrl' ? 1024 : 512);
    if (value !== undefined) attrs[key] = value;
  }

  if (requireSecrets) {
    const missing = [];
    if (provider === 'shinobi') {
      if (!attrs.shinobiBaseUrl) missing.push('Shinobi base URL');
      if (!attrs.shinobiApiKey) missing.push('Shinobi API key');
      if (!attrs.shinobiGroupKey) missing.push('Shinobi group key');
      if (!attrs.shinobiMonitorId) missing.push('Shinobi monitor ID');
    }
    if (provider === 'direct') {
      if (!attrs.directSnapshotUrl) missing.push('Direct snapshot URL');
      if (attrs.directSnapshotUrl) attrs.directSnapshotUrl = sanitizeDirectSnapshotUrl(attrs.directSnapshotUrl);
      const authMode = validateDirectAuthMode(attrs.directAuthMode);
      attrs.directAuthMode = authMode;
      if (authMode === 'basic') {
        if (!attrs.directUsername) missing.push('Direct camera username');
        if (!attrs.directPassword) missing.push('Direct camera password');
      }
    }
    if (missing.length) throw new Error(`Missing required camera field(s): ${missing.join(', ')}.`);
  }

  return attrs;
}

function buildServerPatch(body = {}) {
  const attrs = {};
  if (body.provider !== undefined) attrs.provider = validateProvider(body.provider);
  if (body.preferredStream !== undefined) attrs.preferredStream = validateStreamKind(body.preferredStream);

  for (const key of [
    'shinobiBaseUrl',
    'shinobiApiKey',
    'shinobiGroupKey',
    'shinobiMonitorId',
    'shinobiChannel',
    'directSnapshotUrl',
    'directAuthMode',
    'directUsername',
    'directPassword'
  ]) {
    const value = text(body[key], key === 'directSnapshotUrl' ? 2048 : key === 'shinobiBaseUrl' ? 1024 : 512);
    if (value !== undefined) attrs[key] = value;
  }
  if (attrs.directAuthMode !== undefined) attrs.directAuthMode = validateDirectAuthMode(attrs.directAuthMode);
  return attrs;
}

function requireTenantAdmin(auth, getUserAuthoritiesFromToken, hasAllowedRole) {
  if (!auth || !hasAllowedRole(getUserAuthoritiesFromToken(auth.userToken))) {
    const err = new Error('Forbidden: insufficient role');
    err.status = 403;
    throw err;
  }
}

function sanitizeCamera(asset, sharedAttrs, safeServerAttrs) {
  return {
    id: entityId(asset),
    name: String(asset?.name || ''),
    type: CAMERA_ASSET_TYPE,
    createdTime: asset?.createdTime,
    provider: validateProvider(safeServerAttrs.provider || 'shinobi'),
    preferredStream: safeServerAttrs.preferredStream ? validateStreamKind(safeServerAttrs.preferredStream) : undefined,
    ...buildSharedAttributes(sharedAttrs)
  };
}

function createCameraAssetsRouter(deps) {
  const {
    express,
    ax,
    config,
  getAdminToken,
  requireValidUser,
  getUserAuthoritiesFromToken,
  getCustomerIdFromToken,
  hasAllowedRole,
  emitAuditEvent
} = deps;

  const router = express.Router();
  router.use(express.json({ limit: config.LOCAL_JSON_LIMIT }));

  async function tbGet(path, params) {
    const adminTok = await getAdminToken();
    return ax.get(`${config.THINGSBOARD_URL}${path}`, {
      params,
      headers: { 'X-Authorization': `Bearer ${adminTok}` },
      __tbAdmin: true
    });
  }

  async function tbGetAsUser(path, userToken, params) {
    return ax.get(`${config.THINGSBOARD_URL}${path}`, {
      params,
      headers: { 'X-Authorization': `Bearer ${userToken}` }
    });
  }

  async function tbPost(path, body) {
    const adminTok = await getAdminToken();
    return ax.post(`${config.THINGSBOARD_URL}${path}`, body, {
      headers: {
        'X-Authorization': `Bearer ${adminTok}`,
        'Content-Type': 'application/json'
      },
      __tbAdmin: true
    });
  }

  async function tbDelete(path) {
    const adminTok = await getAdminToken();
    return ax.delete(`${config.THINGSBOARD_URL}${path}`, {
      headers: { 'X-Authorization': `Bearer ${adminTok}` },
      __tbAdmin: true
    });
  }

  async function readCamera(id, userToken) {
    const [assetResp, sharedResp, serverResp] = await Promise.all([
      tbGetAsUser(`/api/asset/info/${encodeURIComponent(id)}`, userToken),
      tbGetAsUser(`/api/plugins/telemetry/ASSET/${encodeURIComponent(id)}/values/attributes/SHARED_SCOPE`, userToken, {
        keys: CAMERA_SHARED_KEYS.join(',')
      }),
      tbGet(`/api/plugins/telemetry/ASSET/${encodeURIComponent(id)}/values/attributes/SERVER_SCOPE`, {
        keys: SAFE_SERVER_KEYS.join(',')
      })
    ]);
    if (assetResp.data?.type !== CAMERA_ASSET_TYPE) {
      const err = new Error('The selected asset is not a camera asset.');
      err.status = 404;
      throw err;
    }
    return sanitizeCamera(assetResp.data, attrsArrayToMap(sharedResp.data), attrsArrayToMap(serverResp.data));
  }

  async function readCameraServerAttributes(id, userToken) {
    const [assetResp, serverResp] = await Promise.all([
      tbGetAsUser(`/api/asset/info/${encodeURIComponent(id)}`, userToken),
      tbGet(`/api/plugins/telemetry/ASSET/${encodeURIComponent(id)}/values/attributes/SERVER_SCOPE`, {
        keys: CAMERA_SERVER_KEYS.join(',')
      })
    ]);
    if (assetResp.data?.type !== CAMERA_ASSET_TYPE) {
      const err = new Error('The selected asset is not a camera asset.');
      err.status = 404;
      throw err;
    }
    const attrs = attrsArrayToMap(serverResp.data);
    return attrs;
  }

  router.get('/', async (req, res) => {
    const auth = await requireValidUser(req, res);
    if (!auth) return;

    try {
      const params = {
        pageSize: Math.min(1000, Math.max(1, Number(req.query.pageSize || 1000))),
        page: Math.max(0, Number(req.query.page || 0)),
        sortProperty: 'createdTime',
        sortOrder: 'DESC',
        type: CAMERA_ASSET_TYPE
      };
      const authorities = getUserAuthoritiesFromToken(auth.userToken);
      const customerId = getCustomerIdFromToken(auth.userToken);
      const endpoint = authorities.includes('CUSTOMER_USER') && customerId
        ? `/api/customer/${encodeURIComponent(customerId)}/assetInfos`
        : '/api/tenant/assetInfos';
      const list = await tbGetAsUser(endpoint, auth.userToken, params);
      const rows = Array.isArray(list.data?.data) ? list.data.data : [];
      const cameras = await Promise.all(rows.map((asset) => readCamera(entityId(asset), auth.userToken)));
      return res.json({ data: cameras, hasNext: Boolean(list.data?.hasNext), totalElements: list.data?.totalElements });
    } catch (e) {
      return res.status(e.status || e?.response?.status || 502).json({ error: e.message || 'Failed to list cameras' });
    }
  });

  router.get('/:id', async (req, res) => {
    const auth = await requireValidUser(req, res);
    if (!auth) return;

    try {
      return res.json(await readCamera(String(req.params.id || ''), auth.userToken));
    } catch (e) {
      return res.status(e.status || e?.response?.status || 502).json({ error: e.message || 'Failed to read camera' });
    }
  });

  router.get('/:id/snapshot', async (req, res) => {
    const auth = await requireValidUser(req, res);
    if (!auth) return;

    try {
      const id = String(req.params.id || '').trim();
      if (!id) return res.status(400).json({ error: 'Camera id is required.' });
      const attrs = await readCameraServerAttributes(id, auth.userToken);
      const provider = validateProvider(attrs.provider);
      const snapshot = provider === 'direct'
        ? buildDirectSnapshotRequest(attrs)
        : { url: buildShinobiSnapshotUrl(attrs), headers: { accept: 'image/jpeg,image/*;q=0.8,*/*;q=0.5' } };
      const upstream = await ax.get(snapshot.url, {
        responseType: 'arraybuffer',
        timeout: CAMERA_PREVIEW_TIMEOUT_MS,
        maxContentLength: CAMERA_PREVIEW_MAX_BYTES,
        maxBodyLength: CAMERA_PREVIEW_MAX_BYTES,
        headers: snapshot.headers
      });
      const contentType = upstream.headers['content-type'] || 'image/jpeg';
      if (!String(contentType).toLowerCase().startsWith('image/')) {
        throw nonImagePreviewError(contentType, upstream.data);
      }
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Content-Type', contentType);
      return res.send(Buffer.from(upstream.data));
    } catch (e) {
      const status = e.status || e?.response?.status || 502;
      const message = e.status ? e.message : 'Failed to read camera snapshot.';
      return res.status(status).json({ error: message });
    }
  });

  router.post('/', async (req, res) => {
    const auth = await requireValidUser(req, res);
    if (!auth) return;

    try {
      requireTenantAdmin(auth, getUserAuthoritiesFromToken, hasAllowedRole);
      const name = text(req.body?.name, 256);
      if (!name) return res.status(400).json({ error: 'Camera name is required.' });

      const shared = buildSharedAttributes({ enabled: true, ...req.body });
      const server = buildServerAttributes(req.body, { requireSecrets: true });
      const assetResp = await tbPost('/api/asset', {
        name,
        type: CAMERA_ASSET_TYPE,
        label: shared.label,
        additionalInfo: {
          description: shared.description,
          kind: 'camera'
        }
      });
      const id = entityId(assetResp.data);
      if (!id) throw new Error('Camera created without asset id.');

      await Promise.all([
        tbPost(`/api/plugins/telemetry/ASSET/${encodeURIComponent(id)}/SHARED_SCOPE`, shared),
        tbPost(`/api/plugins/telemetry/ASSET/${encodeURIComponent(id)}/SERVER_SCOPE`, server)
      ]);
      await emitAuditEvent(req, {
        type: 'camera_create', outcome: 'allowed', userId: auth.userId, entityType: 'ASSET', entityId: id,
        method: req.method, path: req.path
      });
      return res.status(201).json(await readCamera(id, auth.userToken));
    } catch (e) {
      return res.status(e.status || 400).json({ error: e.message || 'Failed to create camera' });
    }
  });

  router.put('/:id', async (req, res) => {
    const auth = await requireValidUser(req, res);
    if (!auth) return;

    try {
      requireTenantAdmin(auth, getUserAuthoritiesFromToken, hasAllowedRole);
      const id = String(req.params.id || '').trim();
      if (!id) return res.status(400).json({ error: 'Camera id is required.' });

      const current = (await tbGet(`/api/asset/info/${encodeURIComponent(id)}`)).data;
      if (current?.type !== CAMERA_ASSET_TYPE) return res.status(404).json({ error: 'The selected asset is not a camera asset.' });

      const shared = buildSharedAttributes(req.body || {});
      const server = buildServerPatch(req.body || {});
      const name = req.body?.name !== undefined ? text(req.body.name, 256) : current.name;
      if (!name) return res.status(400).json({ error: 'Camera name cannot be empty.' });

      await tbPost('/api/asset', {
        ...current,
        name,
        label: shared.label !== undefined ? shared.label : current.label,
        additionalInfo: {
          ...(current.additionalInfo || {}),
          description: shared.description !== undefined ? shared.description : current.additionalInfo?.description,
          kind: 'camera'
        }
      });

      const writes = [];
      if (Object.keys(shared).length) writes.push(tbPost(`/api/plugins/telemetry/ASSET/${encodeURIComponent(id)}/SHARED_SCOPE`, shared));
      if (Object.keys(server).length) writes.push(tbPost(`/api/plugins/telemetry/ASSET/${encodeURIComponent(id)}/SERVER_SCOPE`, server));
      await Promise.all(writes);
      await emitAuditEvent(req, {
        type: 'camera_update', outcome: 'allowed', userId: auth.userId, entityType: 'ASSET', entityId: id,
        method: req.method, path: req.path
      });
      return res.json(await readCamera(id, auth.userToken));
    } catch (e) {
      return res.status(e.status || e?.response?.status || 400).json({ error: e.message || 'Failed to update camera' });
    }
  });

  router.delete('/:id', async (req, res) => {
    const auth = await requireValidUser(req, res);
    if (!auth) return;

    try {
      requireTenantAdmin(auth, getUserAuthoritiesFromToken, hasAllowedRole);
      const id = String(req.params.id || '').trim();
      if (!id) return res.status(400).json({ error: 'Camera id is required.' });
      const current = (await tbGet(`/api/asset/info/${encodeURIComponent(id)}`)).data;
      if (current?.type !== CAMERA_ASSET_TYPE) return res.status(404).json({ error: 'The selected asset is not a camera asset.' });
      await tbDelete(`/api/asset/${encodeURIComponent(id)}`);
      await emitAuditEvent(req, {
        type: 'camera_delete', outcome: 'allowed', userId: auth.userId, entityType: 'ASSET', entityId: id,
        method: req.method, path: req.path
      });
      return res.status(204).send();
    } catch (e) {
      return res.status(e.status || e?.response?.status || 400).json({ error: e.message || 'Failed to delete camera' });
    }
  });

  return router;
}

module.exports = {
  CAMERA_ASSET_TYPE,
  CAMERA_SHARED_KEYS,
  CAMERA_SERVER_KEYS,
  SAFE_SERVER_KEYS,
  attrsArrayToMap,
  buildServerAttributes,
  buildServerPatch,
  buildSharedAttributes,
  buildDirectSnapshotRequest,
  buildShinobiSnapshotUrl,
  createCameraAssetsRouter,
  nonImagePreviewError,
  sanitizeCamera,
  sanitizeDirectSnapshotUrl,
  sanitizeShinobiBaseUrl,
  validateProvider,
  validateStreamKind
};
