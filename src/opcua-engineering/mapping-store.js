const Database = require('better-sqlite3');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { fail } = require('./session-manager');

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function text(value, max = 1024) { return typeof value === 'string' && value.length > 0 && value.length <= max; }
function normalizeDraft(input) {
  if (!input || !text(input.name, 120) || !Array.isArray(input.mappings) || input.mappings.length > 100) fail(400, 'A mapping set needs a name and at most 100 signals');
  const ids = new Set(), sources = new Set(), targets = new Set();
  const mappings = input.mappings.map(m => {
    if (!m || !uuid.test(m.id) || ids.has(m.id) || !text(m.nodeId) || !text(m.parentNodeId)
      || !/^ns=\d+;[is]=.+$/.test(m.nodeId) || !/^ns=\d+;[is]=.+$/.test(m.parentNodeId)
      || !text(m.namespaceUri) || !text(m.browseName) || !text(m.displayName, 256)
      || typeof m.enabled !== 'boolean' || (m.deviceId !== '' && !uuid.test(m.deviceId))
      || typeof m.key !== 'string' || m.key.length > 128 || ['__proto__', 'constructor', 'prototype'].includes(m.key) || (m.key && !/^[A-Za-z0-9_.-]+$/.test(m.key))) fail(400, 'Invalid signal identity or telemetry key');
    if (sources.has(m.nodeId)) fail(400, 'A source node may only occur once in this mapping set');
    if (m.enabled && m.deviceId && m.key) {
      const target = `${m.deviceId}/${m.key}`;
      if (targets.has(target)) fail(400, 'Duplicate destination device and telemetry key');
      targets.add(target);
    }
    ids.add(m.id); sources.add(m.nodeId);
    return { id: m.id, nodeId: m.nodeId, parentNodeId: m.parentNodeId, namespaceUri: m.namespaceUri,
      browseName: m.browseName, displayName: m.displayName, dataType: typeof m.dataType === 'string' ? m.dataType.slice(0, 120) : '',
      deviceId: m.deviceId, key: m.key, enabled: m.enabled };
  });
  return { name: input.name.trim(), mappings };
}

function openMappingStore(filename) {
  if (filename !== ':memory:') fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const db = new Database(filename);
  if (filename !== ':memory:') fs.chmodSync(filename, 0o600);
  db.pragma('journal_mode = WAL'); db.pragma('synchronous = FULL'); db.pragma('busy_timeout = 5000');
  if (db.pragma('user_version', { simple: true }) > 1) { db.close(); throw new Error('Engineering database is newer than this proxy'); }
  db.exec(`CREATE TABLE IF NOT EXISTS mapping_sets(tenant TEXT NOT NULL, connection TEXT NOT NULL, revision INTEGER NOT NULL,
    document TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(tenant,connection));
    CREATE TABLE IF NOT EXISTS mapping_revisions(tenant TEXT NOT NULL, connection TEXT NOT NULL, revision INTEGER NOT NULL,
    document TEXT NOT NULL, actor TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(tenant,connection,revision));
    CREATE TABLE IF NOT EXISTS deployments(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, connection TEXT NOT NULL,
    revision INTEGER NOT NULL, actor TEXT NOT NULL, state TEXT NOT NULL, stage TEXT NOT NULL,
    resources TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS deployment_lock ON deployments(tenant,connection) WHERE state IN ('applying','attention');`);
  db.pragma('user_version = 1');
  function get(tenant, connection) {
    const r = db.prepare('SELECT * FROM mapping_sets WHERE tenant=? AND connection=?').get(tenant, connection);
    return r ? { ...JSON.parse(r.document), revision: r.revision, updatedAt: r.updated_at } : { name: 'OPC UA mapping', mappings: [], revision: 0, updatedAt: null };
  }
  const save = db.transaction((user, connection, expected, input) => {
    const current = get(user.tenantId, connection);
    if (!Number.isInteger(expected) || expected !== current.revision) fail(409, 'Mapping changed in another session. Reload before saving.');
    const document = JSON.stringify(normalizeDraft(input)), revision = current.revision + 1, now = Date.now();
    db.prepare('INSERT INTO mapping_sets VALUES(?,?,?,?,?) ON CONFLICT(tenant,connection) DO UPDATE SET revision=excluded.revision,document=excluded.document,updated_at=excluded.updated_at').run(user.tenantId, connection, revision, document, now);
    db.prepare('INSERT INTO mapping_revisions VALUES(?,?,?,?,?,?)').run(user.tenantId, connection, revision, document, user.userId, now);
    return get(user.tenantId, connection);
  });
  function history(tenant, connection) {
    return db.prepare('SELECT revision,actor,created_at AS createdAt FROM mapping_revisions WHERE tenant=? AND connection=? ORDER BY revision DESC LIMIT 100').all(tenant, connection);
  }
  function restore(user, connection, expected, revision) {
    if (!Number.isInteger(revision)) fail(400, 'Invalid revision');
    const row = db.prepare('SELECT document FROM mapping_revisions WHERE tenant=? AND connection=? AND revision=?').get(user.tenantId, connection, revision);
    if (!row) fail(404, 'Revision not found');
    return save(user, connection, expected, JSON.parse(row.document));
  }
  function deployments(tenant, connection) {
    return db.prepare('SELECT * FROM deployments WHERE tenant=? AND connection=? ORDER BY created_at DESC LIMIT 25').all(tenant, connection)
      .map(r => ({ id: r.id, revision: r.revision, state: r.state, stage: r.stage, resources: JSON.parse(r.resources), createdAt: r.created_at, updatedAt: r.updated_at }));
  }
  const begin = db.transaction((user, connection, revision, expectedHead = null) => {
    if (get(user.tenantId, connection).revision !== revision) fail(409, 'Draft changed; preview again');
    const head = db.prepare("SELECT id FROM deployments WHERE tenant=? AND connection=? AND state='applied' ORDER BY created_at DESC LIMIT 1").get(user.tenantId, connection)?.id || null;
    if (head !== expectedHead) fail(409, 'Another deployment completed since preview; preview again');
    const id = randomUUID(), now = Date.now();
    try { db.prepare('INSERT INTO deployments VALUES(?,?,?,?,?,?,?,?,?,?)').run(id, user.tenantId, connection, revision, user.userId, 'applying', 'preflight', '{}', now, now); }
    catch (e) { if (e.code?.startsWith('SQLITE_CONSTRAINT')) fail(409, 'An unfinished deployment requires reconciliation before another deployment'); throw e; }
    return id;
  });
  function update(id, state, stage, resources) { db.prepare('UPDATE deployments SET state=?,stage=?,resources=?,updated_at=? WHERE id=?').run(state, stage, JSON.stringify(resources), Date.now(), id); }
  // An interrupted save is not safe to retry, particularly resource creation.
  db.prepare("UPDATE deployments SET state='attention',stage='Proxy restarted during deployment' WHERE state='applying'").run();
  return { get, save, restore, history, deployments, begin, update, close: () => db.close(), backup: destination => db.backup(destination) };
}
module.exports = { openMappingStore, normalizeDraft };
