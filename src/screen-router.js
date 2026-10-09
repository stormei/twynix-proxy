const express = require('express');
const crypto = require('node:crypto');
const { stateOf, fail } = require('./screen-store');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function createScreenRouter({ store, authenticate, readLegacy }) {
  const router = express.Router();
  router.use(async (req, res, next) => {
    try {
      req.screenUser = await authenticate(req);
      if (!req.screenUser?.tenantId || !req.screenUser?.userId) fail(401, 'Valid tenant user required');
      res.setHeader('Cache-Control', 'no-store');
      next();
    } catch (error) { next(error); }
  });
  router.use(express.json({ limit: '11mb' }));
  const route = fn => (req, res, next) => Promise.resolve().then(() => fn(req, res)).catch(next);
  function admin(user) { if (user.authority !== 'TENANT_ADMIN') fail(403, 'Tenant administrator required for screen authoring'); }
  function idOf(req) { if (!UUID.test(req.params.id)) fail(400, 'Invalid screen ID'); return req.params.id; }
  async function readable(user, row) {
    if (user.authority === 'TENANT_ADMIN') return true;
    if (row.deleted || stateOf(row.attrs) !== 'PUBLISHED') return false;
    if (row.sourceAssetId) {
      // Migration must not silently broaden the source asset's access boundary.
      try { await readLegacy(user, row.sourceAssetId, true); }
      catch (error) { if ([403,404].includes(error.status || error.response?.status)) return false; throw error; }
    }
    return true;
  }
  async function load(req) {
    const row = store.get(req.screenUser.tenantId, idOf(req));
    if (!row) fail(404, 'Screen not found');
    if (!await readable(req.screenUser, row)) fail(403, 'Screen is not available to this user');
    if (row.deleted) fail(410, 'Screen was deleted; its history is retained');
    return row;
  }
  function expected(req) {
    const value = req.headers['if-match'];
    if (typeof value !== 'string' || !/^"?\d+"?$/.test(value)) fail(428, 'If-Match revision is required');
    return Number(value.replace(/"/g, ''));
  }
  function send(res, row, status = 200) { res.setHeader('ETag', `"${row.revision}"`); return res.status(status).json(row); }
  router.get('/', route(async (req, res) => {
    const rows = store.list(req.screenUser.tenantId);
    const data = [];
    for (const row of rows) if (await readable(req.screenUser, row)) data.push({
      asset: row.asset, revision: row.revision, deleted: row.deleted,
      sourceAssetId: row.sourceAssetId, state: stateOf(row.attrs)
    });
    // Suppress legacy originals, including local tombstones and non-published copies.
    res.json({ data, shadowIds: rows.map(row => row.asset.id.id) });
  }));
  router.post('/', route(async (req, res) => {
    admin(req.screenUser);
    let source = null;
    if (req.body?.sourceScreenId) {
      if (!UUID.test(req.body.sourceScreenId)) fail(400, 'Invalid source screen ID');
      const local = store.get(req.screenUser.tenantId, req.body.sourceScreenId);
      if (local) {
        if (local.deleted) fail(410, 'Source screen was deleted');
        source = local.sourceAssetId;
      } else {
        const legacy = await readLegacy(req.screenUser, req.body.sourceScreenId);
        if (legacy.asset.type !== 'SCREEN' || legacy.asset.tenantId?.id !== req.screenUser.tenantId) fail(403, 'Invalid source screen');
        source = req.body.sourceScreenId;
      }
    }
    send(res, store.create(req.screenUser.tenantId, req.screenUser.userId, req.body, {}, source), 201);
  }));
  router.post('/migrate/:id', route(async (req, res) => {
    admin(req.screenUser);
    const id = idOf(req);
    const existing = store.get(req.screenUser.tenantId, id);
    if (existing) return send(res, existing); // Idempotent, never overwrites edits/deletions.
    const { asset, attrs } = await readLegacy(req.screenUser, id);
    if (asset.type !== 'SCREEN' || asset.tenantId?.id !== req.screenUser.tenantId) fail(403, 'Only same-tenant SCREEN assets can be migrated');
    // Legacy screens with no explicit lifecycle were treated as published by Twynix.
    if (!attrs.screenLifecycle && !attrs.state && !attrs.screenState) attrs.state = 'PUBLISHED';
    send(res, store.create(req.screenUser.tenantId, req.screenUser.userId, asset, attrs, id, id), 201);
  }));
  router.get('/:id', route(async (req, res) => {
    const row = await load(req);
    if (typeof req.query.keys === 'string') {
      const keys = new Set(req.query.keys.split(',').filter(Boolean));
      row.attrs = Object.fromEntries(Object.entries(row.attrs).filter(([key]) => keys.has(key)));
    }
    send(res, row);
  }));
  router.patch('/:id', route(async (req, res) => {
    admin(req.screenUser);
    await load(req);
    send(res, store.update(req.screenUser.tenantId, req.screenUser.userId, idOf(req), expected(req), req.body));
  }));
  router.delete('/:id', route(async (req, res) => {
    admin(req.screenUser);
    await load(req);
    send(res, store.remove(req.screenUser.tenantId, req.screenUser.userId, idOf(req), expected(req)));
  }));
  // Recovery snapshots are deliberately not advertised as self-contained HMI packages:
  // linked templates/media remain external in this first screen-only migration.
  router.get('/:id/export', route(async (req, res) => {
    admin(req.screenUser);
    const row = await load(req);
    const document = { asset: row.asset, attrs: row.attrs };
    const serialized = JSON.stringify(document);
    res.setHeader('Content-Disposition', `attachment; filename="screen-${idOf(req)}.twx-screen.json"`);
    res.json({ format: 'twynix-screen-snapshot', version: 1, selfContained: false,
      checksum: crypto.createHash('sha256').update(serialized).digest('hex'), document });
  }));
  router.post('/import', route((req, res) => {
    admin(req.screenUser);
    const pkg = req.body;
    if (pkg?.format !== 'twynix-screen-snapshot' || pkg.version !== 1 || !pkg.document?.asset || !pkg.document?.attrs) fail(400, 'Unsupported screen snapshot');
    if (crypto.createHash('sha256').update(JSON.stringify(pkg.document)).digest('hex') !== pkg.checksum) fail(400, 'Screen snapshot checksum mismatch');
    const id = crypto.randomUUID();
    const lifecycle = { screenId: id, version: 0, state: 'DRAFT', hash: '', createdAt: new Date().toISOString(), createdBy: req.screenUser.userId };
    const attrs = { ...pkg.document.attrs, screenLifecycle: lifecycle, screenId: id, screenVersion: 0,
      screenState: 'DRAFT', state: 'DRAFT', screenHash: '', publishedAt: null, publishedBy: null };
    attrs.SVG = String(attrs.SVG || '').replace(/<metadata\b[^>]*id=["']nexasense-screen-metadata["'][^>]*>[\s\S]*?<\/metadata>/gi, '');
    send(res, store.create(req.screenUser.tenantId, req.screenUser.userId, pkg.document.asset, attrs, null, id), 201);
  }));
  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = error.status || error.response?.status || 500;
    res.status(status >= 400 && status < 600 ? status : 500).json({ message: status < 500 ? error.message : 'Screen storage unavailable; no fallback write was attempted' });
  });
  return router;
}
module.exports = { createScreenRouter };
