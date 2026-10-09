const Database = require('better-sqlite3');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { fail } = require('./screen-store');
const TYPE = '$FACEPLATE_TEMPLATE';

// Shares the screen database/online backup, but not its lifecycle or tables.
function openFaceplateStore(filename) {
  if (filename !== ':memory:') fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const db = new Database(filename);
  if (filename !== ':memory:') fs.chmodSync(filename, 0o600);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = FULL');
  db.pragma('busy_timeout = 5000');
  db.exec(`CREATE TABLE IF NOT EXISTS faceplates (
    tenant TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
    document TEXT NOT NULL, source TEXT, deleted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(tenant,id));
    CREATE TABLE IF NOT EXISTS faceplate_revisions (
    tenant TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
    document TEXT NOT NULL, actor TEXT NOT NULL, timestamp INTEGER NOT NULL,
    PRIMARY KEY(tenant,id,revision));`);
  function decode(row) { return row && { ...JSON.parse(row.document), revision: row.revision, sourceAssetId: row.source, deleted: !!row.deleted }; }
  function get(tenant, id) { return decode(db.prepare('SELECT * FROM faceplates WHERE tenant=? AND id=?').get(tenant, id)); }
  function validate(template) {
    if (!template || typeof template !== 'object' || Array.isArray(template)
      || typeof template.templateId !== 'string' || !template.templateId.trim() || template.templateId.length > 255
      || typeof template.name !== 'string' || !template.name.trim() || template.name.length > 255
      || !Number.isInteger(template.version) || template.version < 1
      || typeof template.assetType !== 'string' || !Array.isArray(template.sections)
      || template.sections.some(s => !s || typeof s.id !== 'string' || typeof s.title !== 'string'
        || !Array.isArray(s.items) || s.items.some(i => !i || !['signal','command','status','text'].includes(i.type)))) {
      fail(400, 'Invalid faceplate template');
    }
    if (Buffer.byteLength(JSON.stringify(template)) > 5 * 1024 * 1024) fail(413, 'Template exceeds 5 MiB');
  }
  function persist(tenant, actor, id, row) {
    const document = JSON.stringify({ asset: row.asset, attrs: row.attrs, deleted: row.deleted });
    db.prepare(`INSERT INTO faceplates VALUES (?,?,?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET
      revision=excluded.revision,document=excluded.document,deleted=excluded.deleted`).run(tenant,id,row.revision,document,row.sourceAssetId,Number(row.deleted));
    db.prepare('INSERT INTO faceplate_revisions VALUES (?,?,?,?,?,?)').run(tenant,id,row.revision,document,actor,Date.now());
    return get(tenant,id);
  }
  const create = db.transaction((tenant, actor, template, source = null, fixedId = null) => {
    validate(template);
    const id = fixedId || crypto.randomUUID();
    if (get(tenant,id)) fail(409, 'Template already exists');
    return persist(tenant,actor,id,{ asset: { id: { id, entityType: 'ASSET' }, type: TYPE,
      name: template.templateId, label: template.name, storage: 'sqlite', createdTime: Date.now(),
      additionalInfo: { assetType: template.assetType, description: template.description || '' } },
      attrs: { faceplateTemplate: template }, revision: 1, sourceAssetId: source, deleted: false });
  });
  const update = db.transaction((tenant,actor,id,revision,template,remove = false) => {
    const row = get(tenant,id);
    if (!row || row.deleted) fail(404,'Template not found');
    if (revision !== row.revision) fail(409,'Template changed in another session. Reload before saving.');
    if (!remove) {
      validate(template);
      row.attrs.faceplateTemplate = template;
      row.asset.name = template.templateId;
      row.asset.label = template.name;
      row.asset.additionalInfo = { assetType: template.assetType, description: template.description || '' };
    }
    row.deleted = remove;
    row.revision++;
    return persist(tenant,actor,id,row);
  });
  return { get, create, update,
    list: tenant => db.prepare('SELECT * FROM faceplates WHERE tenant=?').all(tenant).map(decode),
    close: () => db.close() };
}
module.exports = { openFaceplateStore, TYPE };
