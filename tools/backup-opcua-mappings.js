// Run in the proxy container. Destination must be a separate backed-up mount.
// Uses SQLite online backup; copying only a live .sqlite file can lose WAL data.
const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');
async function main() {
  const source = process.env.OPCUA_MAPPING_DB_PATH || '/app/data/opcua-engineering/mappings.sqlite';
  const directory = process.argv[2];
  if (!directory || !path.isAbsolute(directory)) throw new Error('Usage: node tools/backup-opcua-mappings.js /absolute/backup/directory');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const destination = path.join(directory, `opcua-mappings-${Date.now()}.sqlite`);
  const db = new Database(source, { readonly: true, fileMustExist: true });
  try {
    await db.backup(destination);
    fs.chmodSync(destination, 0o600);
    const check = new Database(destination, { readonly: true });
    try { if (check.pragma('integrity_check', { simple: true }) !== 'ok') throw new Error('Backup integrity check failed'); }
    finally { check.close(); }
    console.log(`Verified backup: ${destination}`);
  } finally { db.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
