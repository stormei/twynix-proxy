const { randomUUID, createHash } = require('node:crypto');
const { fail } = require('./session-manager');
const { compileMappings } = require('./mapping-compiler');
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
}
function hash(value) { return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex'); }

class MappingService {
  constructor({ store, sessions, request, deploymentEnabled = false, now = Date.now }) {
    Object.assign(this, { store, sessions, request, deploymentEnabled, now });
    this.plans = new Map();
  }
  connection(user, id) {
    this.sessions.authorize(user);
    const connection = this.sessions.connections.find(c => c.id === id && c.tenantId === user.tenantId);
    if (!connection) fail(404, 'Connection not found');
    return connection;
  }
  async devices(user, search = '', page = 0) {
    if (typeof search !== 'string' || search.length > 100 || !Number.isSafeInteger(page) || page < 0 || page > 10000) fail(400, 'Invalid device search');
    const result = await this.request(user, 'GET', `/api/tenant/deviceInfos?pageSize=50&page=${page}&textSearch=${encodeURIComponent(search)}&sortProperty=name&sortOrder=ASC`);
    return { data: result.data.map(d => ({ id: d.id.id, name: d.name, type: d.type })), hasNext: result.hasNext };
  }
  get(user, id) {
    this.connection(user, id);
    return { ...this.store.get(user.tenantId, id), history: this.store.history(user.tenantId, id), deployments: this.store.deployments(user.tenantId, id), deploymentEnabled: this.deploymentEnabled };
  }
  save(user, id, body) { this.connection(user, id); this.store.save(user, id, body.revision, body); return this.get(user, id); }
  restore(user, id, body) { this.connection(user, id); this.store.restore(user, id, body.expectedRevision, body.revision); return this.get(user, id); }
  async assertNoOrphan(user, id) {
    for (let page = 0; page < 10; page++) {
      const result = await this.request(user, 'GET', `/api/integrations?pageSize=100&page=${page}`);
      if (!Array.isArray(result.data)) fail(409, 'Cannot check for existing managed Integrations');
      if (result.data.some(r => r.additionalInfo?.managedBy === 'twynix-opcua' && r.additionalInfo?.connectionId === id)) fail(409, 'A managed Integration already exists without matching local deployment history. Reconcile storage before creating another.');
      if (!result.hasNext) return;
    }
    fail(409, 'Integration inventory exceeds the recovery check limit');
  }
  async validate(user, id, sessionId) {
    const deadline = Date.now() + 30000;
    const budget = () => { if (Date.now() > deadline) fail(400, 'Validation exceeded 30 seconds; use a smaller mapping set'); };
    const connection = this.connection(user, id), row = this.sessions.row(user, sessionId);
    if (row.connectionId !== id) fail(400, 'Discovery session belongs to another connection');
    const draft = this.store.get(user.tenantId, id);
    const enabled = draft.mappings.filter(m => m.enabled);
    if (!enabled.length) return { connection, draft, issues: [], devices: new Map(), types: [], compiled: { mapping: [], decoder: 'return [];' } };
    const issues = [], devices = new Map(), inspections = new Map();
    for (const deviceId of new Set(enabled.map(m => m.deviceId))) {
      budget();
      if (!deviceId) { issues.push('Choose a ThingsBoard device for every enabled signal'); continue; }
      const device = await this.request(user, 'GET', `/api/device/${deviceId}`);
      if (device.tenantId?.id !== user.tenantId || device.id?.id !== deviceId) fail(403, 'Target device tenant does not match');
      devices.set(deviceId, { name: device.name, type: device.type });
    }
    for (let i = 0; i < enabled.length; i += 20) {
      budget();
      for (const item of await this.sessions.inspect(user, sessionId, { nodeIds: enabled.slice(i, i + 20).map(m => m.nodeId) })) inspections.set(item.nodeId, item);
    }
    const parents = new Map(), parentNames = new Map(), resolvedPaths = new Map();
    for (const parent of new Set(enabled.map(m => m.parentNodeId))) {
      budget();
      const parentInfo = (await this.sessions.inspect(user, sessionId, { nodeIds: [parent] }))[0];
      const parentName = parentInfo?.attributes.BrowseName;
      if (!parentName?.status?.startsWith('Good') || typeof parentName.value !== 'string' || !parentName.value) fail(400, 'Parent browse name unavailable');
      parentNames.set(parent, parentName.value);
      const page = await this.sessions.browse(user, sessionId, { nodeId: parent }), nodes = [...page.nodes];
      if (page.cursor) fail(400, 'Source parent requires pagination unsupported by the ThingsBoard runtime adapter');
      parents.set(parent, nodes);
      // TB resolves tag paths recursively by identifier suffix, falling back to
      // BrowseName. Reproduce that resolution and reject ambiguous descendants.
      const pending = [...nodes], visited = new Set([parent]), paths = new Map();
      let browsed = 0;
      while (pending.length) {
        budget();
        const child = pending.shift();
        if (visited.has(child.nodeId)) continue;
        visited.add(child.nodeId);
        const identifier = child.nodeId.replace(/^ns=\d+;[isgb]=/, '');
        const name = identifier.includes(parentName.value) ? identifier.slice(identifier.indexOf(parentName.value) + parentName.value.length + 1) : child.browseName.replace(/^\d+:/, '');
        if (!paths.has(name)) paths.set(name, new Set());
        paths.get(name).add(child.nodeId);
        if (++browsed > 300) fail(400, 'Source subtree exceeds the verified adapter limit (300 nodes); choose a narrower parent');
        const children = await this.sessions.browse(user, sessionId, { nodeId: child.nodeId });
        // TB 4.4 lookupTags does not consume continuation points. Do not deploy
        // a mapping whose resolution depends on a truncated runtime browse.
        if (children.cursor) fail(400, 'Source subtree requires pagination unsupported by the ThingsBoard runtime adapter');
        pending.push(...children.nodes);
      }
      resolvedPaths.set(parent, paths);
    }
    for (const m of enabled) {
      const attrs = inspections.get(m.nodeId)?.attributes || {}, siblings = parents.get(m.parentNodeId);
      const node = siblings.find(n => n.nodeId === m.nodeId);
      const identifier = m.nodeId.replace(/^ns=\d+;[is]=/, ''), parentName = parentNames.get(m.parentNodeId);
      const path = identifier.includes(parentName) ? identifier.slice(identifier.indexOf(parentName) + parentName.length + 1) : m.browseName.replace(/^\d+:/, '');
      const resolved = resolvedPaths.get(m.parentNodeId).get(path);
      if (!resolved || resolved.size !== 1 || !resolved.has(m.nodeId)) issues.push(`${m.displayName}: ThingsBoard cannot resolve this path unambiguously`);
      m.subscriptionPath = path;
      const valid = key => attrs[key]?.status?.startsWith('Good');
      if (!node || node.namespaceUri !== m.namespaceUri || node.browseName !== m.browseName) issues.push(`${m.displayName}: source identity changed; browse and select it again`);
      if (siblings.filter(n => n.browseName.replace(/^\d+:/, '') === m.browseName.replace(/^\d+:/, '')).length !== 1) issues.push(`${m.displayName}: ambiguous relative browse path`);
      if (!valid('NodeClass') || attrs.NodeClass.value !== 'Variable' || !valid('UserAccessLevel') || !attrs.UserAccessLevel.value?.read) issues.push(`${m.displayName}: source is not a readable Variable`);
      if (!valid('ValueRank') || attrs.ValueRank.value !== -1 || !valid('DataType') || !['Boolean','SByte','Byte','Int16','UInt16','Int32','UInt32','Float','Double','String'].includes(attrs.DataType.value)) issues.push(`${m.displayName}: only scalar Boolean, String and safe numeric types are supported`);
      if (m.dataType && attrs.DataType?.value !== m.dataType) issues.push(`${m.displayName}: source data type changed`);
      if (!valid('Value')) issues.push(`${m.displayName}: current OPC UA value is not Good`);
      if (!m.key || !m.deviceId) issues.push(`${m.displayName}: missing destination`);
    }
    return { connection, draft, issues, devices, types: enabled.map(m => [m.id, inspections.get(m.nodeId)?.attributes.DataType?.value]), compiled: issues.length ? null : compileMappings(draft.mappings, devices) };
  }
  async preview(user, id, sessionId) {
    const result = await this.validate(user, id, sessionId);
    if (result.issues.length) return { valid: false, issues: result.issues, signals: [], deploymentEnabled: this.deploymentEnabled };
    const { connection, draft, compiled, devices } = result;
    const previous = this.store.deployments(user.tenantId, id).find(d => d.state === 'applied');
    if (!previous && !draft.mappings.some(m => m.enabled)) fail(400, 'Enable at least one mapping for the first deployment');
    let integration, converter;
    if (!previous) await this.assertNoOrphan(user, id);
    if (previous) {
      integration = await this.request(user, 'GET', `/api/integration/${previous.resources.integrationId}`);
      converter = await this.request(user, 'GET', `/api/converter/${previous.resources.converterId}`);
      this.assertOwned(integration, user, id); this.assertOwned(converter, user, id);
      if (hash(integration) !== previous.resources.integrationHash || hash(converter) !== previous.resources.converterHash) fail(409, 'Managed ThingsBoard configuration changed outside Twynix. Reconcile it before deploying.');
    }
    for (const [key, plan] of this.plans) if (plan.expires < this.now() || (plan.tenant === user.tenantId && plan.user === user.userId && plan.connection.id === id)) this.plans.delete(key);
    if (this.plans.size >= 100) fail(429, 'Too many deployment previews');
    const token = randomUUID();
    const signals = draft.mappings.filter(m => m.enabled).map(m => ({ id: m.id, source: m.displayName, nodeId: m.nodeId, deviceId: m.deviceId, device: devices.get(m.deviceId).name, key: m.key }));
    this.plans.set(token, { tenant: user.tenantId, user: user.userId, sessionId, connection, previousId: previous?.id || null, revision: draft.revision, compiled, devices, types: result.types, signals, integration, converter, expires: this.now() + 300000 });
    const before = new Map((previous?.resources.signals || []).map(s => [s.id, s]));
    const changes = signals.map(s => ({ ...s, change: !before.has(s.id) ? 'add' : hash(before.get(s.id)) === hash(s) ? 'unchanged' : 'update' }));
    for (const old of before.values()) if (!signals.some(s => s.id === old.id)) changes.push({ ...old, change: 'remove' });
    return { valid: true, issues: [], token, revision: draft.revision, operation: previous ? 'update' : 'create', signals, changes, deploymentEnabled: this.deploymentEnabled,
      notes: ['ThingsBoard owns subscriptions. No OPC UA writes or new devices.', 'A new versioned converter is created, then the Integration is switched to it. Old converters are retained.', 'Saves are not atomic. An Integration update may interrupt acquisition.', 'Subscription timing is controlled by ThingsBoard (currently 1 s).', 'Missing values are omitted. Verification checks new timestamps, not signal health.'] };
  }
  assertOwned(resource, user, id) {
    if (resource.tenantId?.id !== user.tenantId || resource.additionalInfo?.managedBy !== 'twynix-opcua' || resource.additionalInfo?.connectionId !== id || !Number.isSafeInteger(resource.version)) fail(409, 'Resource is not an exclusively managed, versioned Twynix resource');
  }
  async deploy(user, id, token) {
    this.connection(user, id);
    if (!this.deploymentEnabled) fail(403, 'OPCUA_DEPLOYMENT_ENABLED is not enabled on this proxy');
    const p = this.plans.get(token);
    if (!p || p.tenant !== user.tenantId || p.user !== user.userId || p.connection.id !== id || p.expires < this.now()) fail(409, 'Preview expired; validate and preview again');
    this.plans.delete(token); // Single-use approval, never retry a non-idempotent save.
    if (this.store.get(user.tenantId, id).revision !== p.revision) fail(409, 'Draft changed; preview again');
    const validation = await this.validate(user, id, p.sessionId);
    if (validation.issues.length || validation.draft.revision !== p.revision || hash(validation.compiled) !== hash(p.compiled) || hash(validation.types) !== hash(p.types)) fail(409, 'Sources or draft changed since preview; validate again');
    for (const [deviceId, expected] of p.devices) {
      const d = await this.request(user, 'GET', `/api/device/${deviceId}`);
      if (d.tenantId?.id !== user.tenantId || d.name !== expected.name || d.type !== expected.type) fail(409, 'Target device changed; preview again');
    }
    for (const [kind, resource] of [['integration', p.integration], ['converter', p.converter]]) if (resource) {
      const current = await this.request(user, 'GET', `/api/${kind}/${resource.id.id}`);
      if (hash(current) !== hash(resource)) fail(409, 'ThingsBoard configuration changed; preview again');
    }
    if (!p.previousId) await this.assertNoOrphan(user, id);
    const attempt = this.store.begin(user, id, p.revision, p.previousId), resources = {};
    const ownership = { managedBy: 'twynix-opcua', connectionId: id };
    try {
      this.store.update(attempt, 'applying', 'Saving converter', resources);
      const converter = !p.signals.length ? p.converter : await this.request(user, 'POST', '/api/converter', {
        name: `Twynix OPC UA · ${id} · ${attempt.slice(0, 8)}`, type: 'UPLINK', integrationType: 'OPC_UA', converterVersion: 1, edgeTemplate: false,
        additionalInfo: ownership, configuration: { scriptLang: 'JS', decoder: p.compiled.decoder, updateOnlyKeys: [] }
      });
      if (!converter.id?.id) throw new Error('Converter save outcome is unknown');
      Object.assign(resources, { converterId: converter.id.id, converterHash: hash(converter) });
      this.store.update(attempt, 'applying', 'Saving Integration', resources);
      const endpoint = new URL(p.connection.endpoint);
      const integration = await this.request(user, 'POST', '/api/integration', {
        ...(p.integration || { name: `Twynix OPC UA · ${id} · ${attempt.slice(0, 8)}`, type: 'OPC_UA', routingKey: randomUUID(), secret: randomUUID(), remote: false }),
        additionalInfo: ownership, enabled: p.signals.length > 0, allowCreateDevicesOrAssets: false,
        defaultConverterId: converter.id, downlinkConverterId: null,
        configuration: !p.signals.length ? p.integration.configuration : { clientConfiguration: { host: endpoint.hostname, port: Number(endpoint.port), endpoint: endpoint.pathname.replace(/^\//, ''),
          scanPeriodInSeconds: 10, timeoutInMillis: 5000, security: 'None', identity: { type: 'anonymous' },
          keystore: { location: '', type: 'PKCS12', fileContent: '', password: '', alias: '', keyPassword: '' }, mapping: p.compiled.mapping } }
      });
      if (!integration.id?.id) throw new Error('Integration save outcome is unknown');
      Object.assign(resources, { integrationId: integration.id.id, integrationHash: hash(integration), signals: p.signals });
      this.store.update(attempt, 'applying', 'Checking saved configuration', resources);
      const savedIntegration = await this.request(user, 'GET', `/api/integration/${integration.id.id}`);
      const savedConverter = await this.request(user, 'GET', `/api/converter/${converter.id.id}`);
      this.assertOwned(savedIntegration, user, id); this.assertOwned(savedConverter, user, id);
      if (hash(savedIntegration) !== resources.integrationHash || hash(savedConverter) !== resources.converterHash
        || savedIntegration.allowCreateDevicesOrAssets !== false || savedIntegration.downlinkConverterId
        || savedIntegration.defaultConverterId?.id !== converter.id.id) throw new Error('Configuration readback did not match');
      this.store.update(attempt, 'applied', 'Configuration saved; telemetry not yet verified', resources);
      return this.get(user, id);
    } catch {
      this.store.update(attempt, 'attention', 'Partial or uncertain save. Inspect ThingsBoard before retrying; automatic retries are blocked.', resources);
      fail(409, 'Deployment needs attention. Saved resources may already be active. No automatic rollback or retry was attempted.');
    }
  }
  async verify(user, id) {
    this.connection(user, id);
    const deployment = this.store.deployments(user.tenantId, id).find(d => d.state === 'applied');
    if (!deployment) fail(400, 'No successful deployment to verify');
    const results = [];
    const signals = deployment.resources.signals || [];
    for (const deviceId of new Set(signals.map(s => s.deviceId))) {
      const keys = signals.filter(s => s.deviceId === deviceId).map(s => s.key);
      const values = await this.request(user, 'GET', `/api/plugins/telemetry/DEVICE/${deviceId}/values/timeseries?keys=${encodeURIComponent(keys.join(','))}`);
      for (const s of signals.filter(s => s.deviceId === deviceId)) {
        const point = values[s.key]?.[0];
        results.push({ id: s.id, key: s.key, device: s.device, timestamp: point?.ts || null,
          value: point ? String(point.value).slice(0, 256) : null, receivedSinceDeployment: !!point && Number(point.ts) > deployment.updatedAt });
      }
    }
    return { deploymentId: deployment.id, checkedAt: this.now(), signals: results };
  }
}
module.exports = { MappingService, hash };
