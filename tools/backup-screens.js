// Run inside the proxy container against its local persistent volume.
// Uses SQLite online backup; copying only the live .sqlite file is unsafe with WAL.
const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');

async function main() {
  const source = process.env.SCREEN_DB_PATH || '/app/data/screens.sqlite';
  const destination = process.argv[2];
  if (!destination || path.resolve(source) === path.resolve(destination)) throw new Error('Specify a distinct backup destination');
  if (fs.existsSync(destination)) throw new Error('Destination already exists; backups are never overwritten');
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
  const db = new Database(source, { readonly: true, fileMustExist: true });
  try {
    await db.backup(destination);
    fs.chmodSync(destination, 0o600);
    const backup = new Database(destination, { readonly: true });
    try { if (backup.pragma('integrity_check', { simple: true }) !== 'ok') throw new Error('Backup integrity check failed'); }
    finally { backup.close(); }
    console.log(`Verified screen backup: ${destination}`);
  } finally { db.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
