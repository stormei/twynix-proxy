const Database = require('better-sqlite3');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
const states = new Set(['DRAFT', 'MAINTENANCE', 'PUBLISHED', 'DEPRECATED']);
function stateOf(attrs) { return attrs.screenLifecycle?.state || attrs.screenState || attrs.state || 'DRAFT'; }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }

// A dedicated document database: no ThingsBoard tables or credentials live here.
function openScreenStore(filename) {
  if (filename !== ':memory:') fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const db = new Database(filename);
  if (filename !== ':memory:') fs.chmodSync(filename, 0o600);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = FULL');
  db.pragma('busy_timeout = 5000');
  db.pragma('foreign_keys = ON');
  const version = db.pragma('user_version', { simple: true });
  if (version > 1) { db.close(); throw new Error('Screen database is newer than this proxy; refusing to open'); }
  db.transaction(() => {
    db.exec(`CREATE TABLE IF NOT EXISTS screens (
      tenant_id TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
      asset_json TEXT NOT NULL, attrs_json TEXT NOT NULL, source_asset_id TEXT,
      deleted INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL,
      PRIMARY KEY (tenant_id, id));
      CREATE TABLE IF NOT EXISTS screen_revisions (
      tenant_id TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
      asset_json TEXT NOT NULL, attrs_json TEXT NOT NULL, actor_id TEXT NOT NULL,
      updated_at INTEGER NOT NULL, deleted INTEGER NOT NULL,
      PRIMARY KEY (tenant_id, id, revision));`);
    db.pragma('user_version = 1');
  })();
  function decode(row) {
    return row && { asset: JSON.parse(row.asset_json), attrs: JSON.parse(row.attrs_json),
      revision: row.revision, sourceAssetId: row.source_asset_id, deleted: !!row.deleted };
  }
  function get(tenant, id) { return decode(db.prepare('SELECT * FROM screens WHERE tenant_id=? AND id=?').get(tenant, id)); }
  function validate(asset, attrs) {
    if (!object(asset) || typeof asset.name !== 'string' || !asset.name.trim() || asset.name.length > 255) fail(400, 'A screen name of 1–255 characters is required');
    if (!object(attrs) || !states.has(stateOf(attrs))) fail(400, 'Invalid screen attributes or lifecycle');
    if (attrs.SVG !== undefined && typeof attrs.SVG !== 'string') fail(400, 'SVG must be text');
    if (stateOf(attrs) === 'PUBLISHED' && !/<svg[\s/>]/i.test(attrs.SVG || '')) fail(400, 'Cannot publish an empty screen');
    if (Buffer.byteLength(JSON.stringify({ asset, attrs })) > 10 * 1024 * 1024) fail(413, 'Screen exceeds 10 MiB');
  }
  function persist(tenant, id, asset, attrs, source, revision, actor, deleted = false) {
    validate(asset, attrs);
    const now = Date.now();
    const a = JSON.stringify(asset), b = JSON.stringify(attrs);
    db.prepare(`INSERT INTO screens VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,id)
      DO UPDATE SET revision=excluded.revision,asset_json=excluded.asset_json,attrs_json=excluded.attrs_json,
      deleted=excluded.deleted,updated_at=excluded.updated_at`).run(tenant, id, revision, a, b, source, Number(deleted), now);
    db.prepare('INSERT INTO screen_revisions VALUES (?,?,?,?,?,?,?,?)').run(tenant, id, revision, a, b, actor, now, Number(deleted));
    return get(tenant, id);
  }
  const create = db.transaction((tenant, actor, asset, attrs = {}, source = null, fixedId = null) => {
    const id = fixedId || crypto.randomUUID();
    if (get(tenant, id)) fail(409, 'Screen already exists; migration never overwrites a local screen');
    const normalized = { name: asset.name, label: asset.label || '', additionalInfo: asset.additionalInfo || {},
      type: 'SCREEN', id: { entityType: 'ASSET', id }, createdTime: asset.createdTime || Date.now(),
      tenantId: { entityType: 'TENANT', id: tenant }, storage: 'sqlite' };
    const initial = Object.keys(attrs).length ? attrs : { state: 'DRAFT', screenState: 'DRAFT' };
    return persist(tenant, id, normalized, initial, source, 1, actor);
  });
  const update = db.transaction((tenant, actor, id, expected, patch) => {
    const row = get(tenant, id);
    if (!row || row.deleted) fail(404, 'Screen not found');
    if (!Number.isInteger(expected) || expected !== row.revision) fail(409, 'Screen changed in another session. Reload before saving; your edits were not overwritten.');
    if (!object(patch) || (patch.attrs !== undefined && !object(patch.attrs))) fail(400, 'Invalid update');
    const asset = { ...row.asset };
    if (patch.asset) for (const key of ['name', 'label', 'additionalInfo']) {
      if (Object.hasOwn(patch.asset, key)) asset[key] = patch.asset[key];
    }
    const attrs = { ...row.attrs, ...patch.attrs };
    if (patch.attrs && (patch.attrs.screenLifecycle?.state || patch.attrs.screenState || patch.attrs.state)) {
      const state = stateOf(patch.attrs);
      attrs.state = attrs.screenState = state;
      if (attrs.screenLifecycle) attrs.screenLifecycle = { ...attrs.screenLifecycle, state };
    }
    const from = stateOf(row.attrs), to = stateOf(attrs);
    const transitions = { DRAFT: ['DRAFT','MAINTENANCE','PUBLISHED','DEPRECATED'], MAINTENANCE: ['MAINTENANCE','PUBLISHED','DEPRECATED'], PUBLISHED: ['PUBLISHED','DEPRECATED'], DEPRECATED: ['DEPRECATED','MAINTENANCE'] };
    if (!transitions[from]?.includes(to)) fail(409, 'Create a maintenance copy to edit a published screen');
    if (from === 'PUBLISHED' || from === 'DEPRECATED') {
      // Only lifecycle metadata may change on frozen content. SVG embeds that metadata,
      // so compare its non-metadata content as well rather than trusting the browser.
      const strip = svg => String(svg || '').replace(/<metadata\b[^>]*id=["']nexasense-screen-metadata["'][^>]*>[\s\S]*?<\/metadata>/gi, '');
      if (strip(attrs.SVG) !== strip(row.attrs.SVG)) fail(409, 'Published screen content is immutable');
      for (const key of Object.keys(patch.attrs || {})) {
        if (!['SVG','screenLifecycle','state','screenState','screenHash','screenVersion','publishedAt','publishedBy','derivedFrom','createdAt','createdBy','screenId','generatedFrom','thumbnail'].includes(key)
          && JSON.stringify(attrs[key]) !== JSON.stringify(row.attrs[key])) fail(409, 'Published screen attributes are immutable');
      }
    }
    return persist(tenant, id, asset, attrs, row.sourceAssetId, row.revision + 1, actor);
  });
  const remove = db.transaction((tenant, actor, id, expected) => {
    const row = get(tenant, id);
    if (!row || row.deleted) fail(404, 'Screen not found');
    if (expected !== row.revision) fail(409, 'Screen changed; reload before deleting');
    if (!['DRAFT','MAINTENANCE','DEPRECATED'].includes(stateOf(row.attrs))) fail(409, 'Deprecate the screen before deleting');
    return persist(tenant, id, row.asset, row.attrs, row.sourceAssetId, row.revision + 1, actor, true);
  });
  return { get, create, update, remove,
    // List metadata only: never materialize every screen SVG/revision to render the gallery.
    list: tenant => db.prepare(`SELECT asset_json, revision, source_asset_id, deleted,
      COALESCE(json_extract(attrs_json, '$.screenLifecycle.state'), json_extract(attrs_json, '$.screenState'),
        json_extract(attrs_json, '$.state'), 'DRAFT') AS state
      FROM screens WHERE tenant_id=? ORDER BY updated_at DESC`).all(tenant).map(row => ({
      asset: JSON.parse(row.asset_json), revision: row.revision, sourceAssetId: row.source_asset_id,
      deleted: !!row.deleted, attrs: { state: row.state }
    })),
    backup: destination => db.backup(destination),
    integrity: () => db.pragma('integrity_check', { simple: true }),
    close: () => db.close() };
}
module.exports = { openScreenStore, stateOf, fail };
