const { isIP } = require('node:net');

// Operator-managed registry, not browser configuration. Literal IPv4 only in v1:
// this prevents DNS rebinding and keeps the approved socket destination exact.
function parseConnections(text) {
  const rows = JSON.parse(text);
  if (!Array.isArray(rows) || rows.length > 100) throw new Error('OPC UA registry must contain at most 100 connections');
  const seen = new Set();
  return rows.map(row => {
    if (!row || typeof row !== 'object') throw new Error('Invalid OPC UA connection');
    const url = new URL(row.endpoint);
    const octets = url.hostname.split('.').map(Number);
    if (url.protocol !== 'opc.tcp:' || isIP(url.hostname) !== 4 || !url.port || url.username || url.password || url.search || url.hash
      || [0, 127, 169].includes(octets[0]) || octets[0] >= 224) throw new Error('OPC UA requires an approved unicast IPv4 endpoint');
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(row.id) || seen.has(row.id)
      || typeof row.name !== 'string' || !row.name.trim() || row.name.length > 120
      || typeof row.tenantId !== 'string' || !/^[0-9a-f-]{36}$/i.test(row.tenantId)
      || !Number.isSafeInteger(row.revision) || row.revision < 1) throw new Error('Invalid OPC UA connection identity');
    // Secure certificate provisioning is a separate milestone. Fail closed rather
    // than silently downgrading an intended secure production connection.
    if (row.securityMode !== 'None' || row.allowInsecureDiscovery !== true) throw new Error('This discovery preview requires explicit None/Anonymous approval');
    seen.add(row.id);
    return Object.freeze({ id: row.id, name: row.name, tenantId: row.tenantId, revision: row.revision, endpoint: url.href, securityMode: 'None' });
  });
}
module.exports = { parseConnections };
