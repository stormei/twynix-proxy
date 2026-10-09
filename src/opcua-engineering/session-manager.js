const { randomUUID } = require('node:crypto');
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };

// No acquisition loop: the only timer reclaims idle discovery sessions.
class DiscoverySessions {
  constructor({ connections, createClient, now = Date.now, idleMs = 60000, lifetimeMs = 600000, operationMs = 10000 }) {
    Object.assign(this, { connections, createClient, now, idleMs, lifetimeMs, operationMs });
    this.sessions = new Map();
    this.timer = setInterval(() => this.sweep(), Math.min(idleMs, 5000));
    this.timer.unref();
  }
  authorize(user) {
    if (!user?.tenantId || !user?.userId) fail(401, 'Authenticated tenant user required');
    if (user.authority !== 'TENANT_ADMIN') fail(403, 'Tenant administrator required for discovery');
  }
  list(user) {
    this.authorize(user);
    return this.connections.filter(c => c.tenantId === user.tenantId).map(({ id, name, revision, securityMode }) => ({ id, name, revision, securityMode }));
  }
  async open(user, connectionId, revision) {
    this.authorize(user);
    const connection = this.connections.find(c => c.id === connectionId && c.tenantId === user.tenantId);
    if (!connection) fail(404, 'Connection not found');
    if (connection.revision !== revision) fail(409, 'Connection changed; reload connections');
    const rows = [...this.sessions.values()];
    if (rows.length >= 16 || rows.filter(s => s.tenantId === user.tenantId).length >= 8) fail(429, 'Discovery capacity reached');
    if (rows.some(s => s.userId === user.userId && s.tenantId === user.tenantId && s.connectionId === connectionId)) fail(409, 'Close the existing discovery session first');
    const row = { id: randomUUID(), tenantId: user.tenantId, userId: user.userId, connectionId,
      expires: this.now() + this.lifetimeMs, touched: this.now(), busy: false, closed: false, cursors: new Map(), client: this.createClient(connection) };
    this.sessions.set(row.id, row); // Reserve before connecting, including concurrent opens.
    try {
      const namespaces = await this.run(row, () => row.client.open());
      return { id: row.id, namespaces, expiresAt: row.expires, idleTimeoutMs: this.idleMs };
    } catch (error) { await this.closeRow(row); throw error; }
  }
  row(user, id) {
    this.authorize(user);
    const row = this.sessions.get(id);
    if (!row || row.tenantId !== user.tenantId || row.userId !== user.userId) fail(404, 'Discovery session not found');
    if (this.now() >= row.expires || this.now() - row.touched >= this.idleMs) {
      void this.closeRow(row); fail(410, 'Discovery session expired; reconnect');
    }
    return row;
  }
  async run(row, work) {
    if (row.busy) fail(409, 'A discovery operation is already in progress');
    row.busy = true;
    row.touched = this.now();
    let timer;
    try {
      const result = await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('Discovery timed out; reconnect'), { status: 504 })), this.operationMs);
      })]);
      if (row.closed) fail(410, 'Discovery session closed');
      if (Buffer.byteLength(JSON.stringify(result)) > 512000) fail(413, 'Discovery response exceeds limit');
      row.touched = this.now();
      return result;
    } catch (error) {
      await this.closeRow(row);
      throw error;
    } finally { clearTimeout(timer); row.busy = false; }
  }
  async browse(user, id, body) {
    const row = this.row(user, id);
    if (row.busy) fail(409, 'A discovery operation is already in progress');
    let point;
    if (body.cursor !== undefined) {
      point = row.cursors.get(body.cursor);
      if (!point) fail(400, 'Invalid or consumed browse cursor');
      row.cursors.delete(body.cursor);
    } else {
      this.node(body.nodeId);
      if (row.cursors.size >= 32) fail(429, 'Too many unfinished browse pages; reconnect');
    }
    return this.run(row, async () => {
      const result = await row.client.browse(body.nodeId, point);
      let cursor = null;
      if (result.continuationPoint?.length) {
        cursor = randomUUID(); row.cursors.set(cursor, result.continuationPoint);
      }
      return { nodes: result.nodes, cursor };
    });
  }
  node(id) {
    if (typeof id !== 'string' || id.length > 1024 || !/^ns=\d+;[isgb]=.+$/.test(id)) fail(400, 'Invalid node ID');
  }
  inspect(user, id, body) {
    const row = this.row(user, id);
    if (!Array.isArray(body.nodeIds) || !body.nodeIds.length || body.nodeIds.length > 20) fail(400, 'Inspect requires 1–20 nodes');
    body.nodeIds.forEach(node => this.node(node));
    return this.run(row, () => row.client.inspect(body.nodeIds));
  }
  async closeRow(row) {
    if (row.closed) return;
    row.closed = true;
    row.cursors.clear();
    // Keep capacity reserved until transport cleanup has completed.
    try { await row.client.close(); } finally { this.sessions.delete(row.id); }
  }
  async close(user, id) { await this.closeRow(this.row(user, id)); }
  async sweep() {
    await Promise.allSettled([...this.sessions.values()].filter(s => this.now() >= s.expires || this.now() - s.touched >= this.idleMs).map(s => this.closeRow(s)));
  }
  async shutdown() {
    clearInterval(this.timer);
    await Promise.allSettled([...this.sessions.values()].map(s => this.closeRow(s)));
  }
}
module.exports = { DiscoverySessions, fail };
