require('dotenv').config();

const express = require('express');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = rateLimit;
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const helmet = require('helmet'); // ← MUST-DO: security headers
const { createTwynixOplogRouter, createOplogEmitter } = require('./src/twynix-oplog');
const { createCameraAssetsRouter } = require('./src/camera-assets');
const { createTelemetryWriteGuard } = require('./src/telemetry-write-policy');
const { createTrendQueryHandler } = require('./src/iotdb-trend-query');
const { createIotdbSchemaHandler } = require('./src/iotdb-schema');
const { readEnvSecret } = require('./src/config-secrets');
const { validateConfig } = require('./src/config-validation');
const { validateProxyBodySize } = require('./src/request-size-policy');
const { buildRpcPolicy, validateRpcBody } = require('./src/rpc-policy');
const {
  clampText,
  createProxyRoutePolicy,
  getBearerTokenFromHeaders,
  isLocalRoute,
  isReadOnlyIotdbQuery,
  scrubInboundHeaders
} = require('./src/security-policy');

// ✅ NEW: better-sqlite3 shelving store
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const app = express();
const startedAt = Date.now();
const serviceState = {
  lastTbAdminLoginAt: null,
  lastTbAdminLoginError: null,
  lastThingsBoardError: null,
  lastIotdbError: null,
  lastShelvingError: null,
  lastAuditError: null,
  securityEvents: {},
  http: {
    requestsTotal: 0,
    byStatusClass: {},
    byMethod: {}
  },
  configWarnings: []
};

function logSecurityEvent(type, fields = {}) {
  serviceState.securityEvents[type] = (serviceState.securityEvents[type] || 0) + 1;
  console.log(JSON.stringify({
    event: 'twynix_security',
    type,
    ts: new Date().toISOString(),
    ...fields
  }));
}

/* -----------------------------
   Config (now from environment)
------------------------------ */
const config = {
  NODE_ENV: process.env.NODE_ENV || '',
  PORT: parseInt(process.env.PORT || '8787', 10),
  THINGSBOARD_URL: process.env.THINGSBOARD_URL,
  THINGSBOARD_WS_URL: process.env.THINGSBOARD_WS_URL,
  TB_ADMIN_USERNAME: process.env.TB_ADMIN_USERNAME,
  TB_ADMIN_PASSWORD: readEnvSecret('TB_ADMIN_PASSWORD'),
  IOTDB_URL: process.env.IOTDB_URL,
  IOTDB_AUTH: readEnvSecret('IOTDB_AUTH'),
  ACL_TTL_MS: parseInt(process.env.ACL_TTL_MS || '60000', 10),
  MAX_CACHE_ENTRIES: parseInt(process.env.MAX_CACHE_ENTRIES || '5000', 10),
  AXIOS_TIMEOUT_MS: parseInt(process.env.AXIOS_TIMEOUT_MS || '15000', 10),
  LOCAL_JSON_LIMIT: process.env.LOCAL_JSON_LIMIT || '128kb',
  TRUST_PROXY_HOPS: process.env.TRUST_PROXY_HOPS ? parseInt(process.env.TRUST_PROXY_HOPS, 10) : 0,
  CORS_ORIGINS: process.env.CORS_ORIGINS || 'http://localhost:4200',
  EXTRA_PROXY_ALLOW_RULES: process.env.EXTRA_PROXY_ALLOW_RULES || '',
  PROXY_READ_RATE_WINDOW_MS: parseInt(process.env.PROXY_READ_RATE_WINDOW_MS || '1000', 10),
  PROXY_READ_RATE_MAX: parseInt(process.env.PROXY_READ_RATE_MAX || '300', 10),
  PROXY_WRITE_RATE_WINDOW_MS: parseInt(process.env.PROXY_WRITE_RATE_WINDOW_MS || '1000', 10),
  PROXY_WRITE_RATE_MAX: parseInt(process.env.PROXY_WRITE_RATE_MAX || '20', 10),
  PROXY_MAX_BODY_BYTES: parseInt(process.env.PROXY_MAX_BODY_BYTES || String(1024 * 1024), 10),

  // roles allowed to perform management writes (comma-separated)
  MGMT_ALLOWED_ROLES: (process.env.MGMT_ALLOWED_ROLES || 'TENANT_ADMIN')
    .split(',').map(s => s.trim()).filter(Boolean),

  // ✅ NEW: Shelving DB + cleanup
  SHELVING_DB_PATH: process.env.SHELVING_DB_PATH || './data/twynix-shelving.db',
  SHELVING_SWEEP_MS: parseInt(process.env.SHELVING_SWEEP_MS || '30000', 10), // every 30s

  // ✅ NEW: RPC hardening
  RPC_ALLOWED_METHODS: (process.env.RPC_ALLOWED_METHODS || 'writeTag')
    .split(',').map(s => s.trim()).filter(Boolean),
  RPC_ALLOWED_TAGS: process.env.RPC_ALLOWED_TAGS || '',
  RPC_METHOD_PARAM_RULES: process.env.RPC_METHOD_PARAM_RULES || '',
  RPC_TIMEOUT_MAX_MS: parseInt(process.env.RPC_TIMEOUT_MAX_MS || '30000', 10),
  RPC_JSON_LIMIT: process.env.RPC_JSON_LIMIT || '16kb',
  RPC_MAX_BODY_BYTES: parseInt(process.env.RPC_MAX_BODY_BYTES || String(16 * 1024), 10),
  RPC_REQUIRE_AUDIT: String(process.env.RPC_REQUIRE_AUDIT || 'false').toLowerCase() === 'true',

  // ✅ NEW: per-user+device RPC rate limiting (in-memory)
  RPC_RATE_WINDOW_MS: parseInt(process.env.RPC_RATE_WINDOW_MS || '1000', 10), // 1s
  RPC_RATE_MAX: parseInt(process.env.RPC_RATE_MAX || '5', 10),               // 5 req / window

  // ✅ NEW: allow quick rollback to "pure forward"
  RPC_ACL_ENABLED: String(process.env.RPC_ACL_ENABLED || 'true').toLowerCase() !== 'false',
  IOTDB_QUERY_ENABLED: String(process.env.IOTDB_QUERY_ENABLED || 'false').toLowerCase() === 'true',
  IOTDB_TREND_MAX_WINDOW_MS: parseInt(process.env.IOTDB_TREND_MAX_WINDOW_MS || String(7 * 24 * 60 * 60 * 1000), 10),
  IOTDB_TREND_ESTIMATED_SAMPLE_MS: parseInt(process.env.IOTDB_TREND_ESTIMATED_SAMPLE_MS || '1000', 10),
  IOTDB_TREND_DEBUG: String(process.env.IOTDB_TREND_DEBUG || 'false').toLowerCase() === 'true',
  IOTDB_REST_QUERY_FIELD: process.env.IOTDB_REST_QUERY_FIELD || 'sql',
  IOTDB_SCHEMA_CACHE_TTL_MS: parseInt(process.env.IOTDB_SCHEMA_CACHE_TTL_MS || '60000', 10),
  IOTDB_SCHEMA_ROW_LIMIT: parseInt(process.env.IOTDB_SCHEMA_ROW_LIMIT || '10000', 10),
  INTERNAL_PROXY_SECRET: readEnvSecret('INTERNAL_PROXY_SECRET'),
  AUDIT_HMAC_SECRET: readEnvSecret('AUDIT_HMAC_SECRET') || '',
  OPLOG_MAX_WINDOW_MS: parseInt(process.env.OPLOG_MAX_WINDOW_MS || String(7 * 24 * 60 * 60 * 1000), 10),
};

function thingsboardWsUrl() {
  const explicit = String(config.THINGSBOARD_WS_URL || '').replace(/\/+$/, '');
  if (explicit) return explicit;

  const base = String(config.THINGSBOARD_URL || '').replace(/\/+$/, '');
  if (base.startsWith('https://')) return `wss://${base.slice('https://'.length)}`;
  if (base.startsWith('http://')) return `ws://${base.slice('http://'.length)}`;
  return base;
}

const configValidation = validateConfig(config);
serviceState.configWarnings = configValidation.warnings;
for (const warning of configValidation.warnings) {
  console.warn(`Config warning: ${warning}`);
}
if (configValidation.errors.length > 0) {
  for (const error of configValidation.errors) console.error(error);
  process.exit(1);
}

const proxyRoutePolicy = createProxyRoutePolicy(config.EXTRA_PROXY_ALLOW_RULES);
const rpcPolicy = buildRpcPolicy(config);
if (Number.isFinite(config.TRUST_PROXY_HOPS) && config.TRUST_PROXY_HOPS > 0) {
  app.set('trust proxy', config.TRUST_PROXY_HOPS);
}

/* -----------------------------------------
   HTTP keep-alive & axios instance + timeout
------------------------------------------ */
http.globalAgent.keepAlive = true;
https.globalAgent.keepAlive = true;

const ax = axios.create({
  httpAgent: new http.Agent({ keepAlive: true, maxSockets: 256 }),
  httpsAgent: new https.Agent({ keepAlive: true, maxSockets: 256 }),
  timeout: config.AXIOS_TIMEOUT_MS,
  maxRedirects: 0,
  maxBodyLength: 256 * 1024,
  maxContentLength: 2 * 1024 * 1024,
});

/* -------------------------------------------
   base64url-safe JWT helpers
-------------------------------------------- */
function b64urlDecode(str) {
  const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : str.length % 4 === 1 ? '===' : '';
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString();
}
function parseJwtPayload(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Bad JWT');
  return JSON.parse(b64urlDecode(parts[1]));
}
function getUserAuthoritiesFromToken(token) {
  try {
    const p = parseJwtPayload(token);
    const raw = p.authorities || p.scope || p.scopes || p.authority;
    if (Array.isArray(raw)) return raw.map(String);
    if (typeof raw === 'string') return raw.split(/[,\s]+/).filter(Boolean);
    return [];
  } catch { return []; }
}

// ✅ NEW: tenant id extraction for shelving keys
function getTenantIdFromToken(userToken) {
  try {
    const payload = parseJwtPayload(userToken);
    return payload.tenantId || payload.tenant_id || null;
  } catch {
    return null;
  }
}

function getCustomerIdFromToken(userToken) {
  try {
    const payload = parseJwtPayload(userToken);
    return payload.customerId || payload.customer_id || null;
  } catch {
    return null;
  }
}

/* -------------------------------------------
   Admin token cache and refresh logic
-------------------------------------------- */
let adminToken = null;
let adminTokenExpiry = 0;

function formatUpstreamAuthError(e) {
  const status = e?.response?.status;
  const message = e?.response?.data?.message || e?.message || String(e);
  return status ? `HTTP ${status}: ${message}` : message;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildOpcUaRpcError(e, operation) {
  const status = e?.response?.status || 502;
  const upstream = e?.response?.data;
  const upstreamMessage =
    upstream?.message ||
    upstream?.error ||
    (typeof upstream === 'string' ? upstream : '') ||
    e?.message ||
    String(e);
  const conflict = status === 409;
  const timeout = status === 504;
  return {
    httpStatus: status,
    body: {
      ok: false,
      code: conflict ? 'TB_RPC_CONFLICT' : timeout ? 'TB_RPC_TIMEOUT' : 'TB_RPC_FAILED',
      operation,
      error: conflict
        ? 'ThingsBoard could not deliver the OPC UA RPC request to the selected gateway device.'
        : timeout
          ? 'Timed out waiting for the OPC UA gateway to answer the ThingsBoard RPC request.'
        : formatUpstreamAuthError(e),
      upstreamStatus: status,
      upstreamMessage,
      hint: conflict
        ? 'Verify the selected device is the online OPC UA gateway, the gateway process was restarted after adding opcuaBrowse/opcuaDiscoverVariables support, the gateway access token matches this ThingsBoard device, and no previous server-side RPC is still pending.'
        : timeout
          ? 'Check whether the gateway logged an RPC request for this operation. If yes, OPC UA browse/discovery is too slow or the OPC UA channel is reconnecting. If no, ThingsBoard did not deliver the RPC to the gateway device.'
        : 'Verify ThingsBoard connectivity and proxy admin credentials.'
    }
  };
}

async function postThingsBoardDeviceRpc(gatewayDeviceId, method, params, adminTok) {
  const retryDelays = [0, 750, 2000, 4000];
  let lastError;

  for (let attempt = 0; attempt < retryDelays.length; attempt += 1) {
    if (retryDelays[attempt] > 0) await sleep(retryDelays[attempt]);

    try {
      return await ax.post(
        `${config.THINGSBOARD_URL}/api/rpc/twoway/${gatewayDeviceId}`,
        { method, params, timeout: params.timeoutMs },
        {
          headers: {
            'X-Authorization': `Bearer ${adminTok}`,
            'Content-Type': 'application/json'
          },
          __tbAdmin: true,
          timeout: params.timeoutMs + 2000
        }
      );
    } catch (e) {
      lastError = e;
      const status = e?.response?.status;
      if (status !== 409) throw e;
    }
  }

  throw lastError;
}

async function loginAdmin() {
  try {
    const resp = await ax.post(
      `${config.THINGSBOARD_URL}/api/auth/login`,
      { username: config.TB_ADMIN_USERNAME, password: config.TB_ADMIN_PASSWORD },
      { headers: { 'Content-Type': 'application/json' } }
    );
    adminToken = resp.data.token;
    serviceState.lastTbAdminLoginAt = Date.now();
    serviceState.lastTbAdminLoginError = null;
  } catch (e) {
    const sanitized = formatUpstreamAuthError(e);
    serviceState.lastTbAdminLoginError = sanitized;
    throw new Error(`ThingsBoard admin login failed: ${sanitized}`);
  }

  try {
    const payload = parseJwtPayload(adminToken);
    adminTokenExpiry = payload.exp * 1000;
  } catch {
    adminTokenExpiry = Date.now() + 10 * 60 * 1000; // fallback 10m
  }

  console.log('Admin logged in, token expires at:', new Date(adminTokenExpiry));
}

async function getAdminToken() {
  if (!adminToken || Date.now() > adminTokenExpiry - 60000) {
    await loginAdmin();
  }
  return adminToken;
}

/* -------------------------------------------
   axios interceptor to auto-refresh admin token
-------------------------------------------- */
ax.interceptors.response.use(
  (r) => r,
  async (error) => {
    const cfg = error.config || {};
    if (error.response && error.response.status === 401 && cfg.__tbAdmin && !cfg.__retried) {
      cfg.__retried = true;
      await loginAdmin();
      cfg.headers = { ...(cfg.headers || {}), 'X-Authorization': `Bearer ${adminToken}` };
      return ax(cfg);
    }
    throw error;
  }
);

/* ---------------------------------------------------------
   Token validation by TB (/api/auth/user) with small cache
---------------------------------------------------------- */
const tokenValidityCache = new Map(); // token -> expiresAt(ms)
const MAX_CACHE_ENTRIES = config.MAX_CACHE_ENTRIES;

function setBounded(map, key, val) {
  if (map.size >= MAX_CACHE_ENTRIES) {
    const firstKey = map.keys().next().value;
    map.delete(firstKey);
  }
  map.set(key, val);
}

async function assertTokenValid(userToken) {
  const cachedExp = tokenValidityCache.get(userToken);
  if (cachedExp && Date.now() < cachedExp) return;

  await ax.get(`${config.THINGSBOARD_URL}/api/auth/user`, {
    headers: { 'X-Authorization': `Bearer ${userToken}` }
  });

  let exp = Date.now() + 60000; // default 60s
  try {
    const payload = parseJwtPayload(userToken);
    if (payload?.exp) exp = Math.min(payload.exp * 1000, Date.now() + 60000);
  } catch { /* ignore */ }

  setBounded(tokenValidityCache, userToken, exp);
}

function getUserIdFromToken(userToken) {
  try {
    const payload = parseJwtPayload(userToken);
    return payload.userId || payload.sub || null;
  } catch {
    return null;
  }
}

/* -------------------------------------------
   ACL cache for SERVER attributes (bounded)
-------------------------------------------- */
const aclCache = new Map(); // key -> { data, expiryMs }

async function fetchServerAttributesArrayCached(entityType, entityId) {
  const key = `${entityType}:${entityId}`;
  const cached = aclCache.get(key);
  if (cached && Date.now() < cached.expiryMs) return cached.data;

  const adminTok = await getAdminToken();
  const resp = await ax.get(
    `${config.THINGSBOARD_URL}/api/plugins/telemetry/${entityType}/${entityId}/values/attributes/SERVER_SCOPE?keys=security`,
    {
      headers: { 'X-Authorization': `Bearer ${adminTok}` },
      __tbAdmin: true,
    }
  );

  const entry = { data: resp.data, expiryMs: Date.now() + config.ACL_TTL_MS };
  setBounded(aclCache, key, entry);
  return resp.data;
}

/* -------------------------------------------
   Canonical oplog emitter
-------------------------------------------- */
const emitOplogEvent = createOplogEmitter({
  config,
  ax,
  getAdminToken,
  logger: (obj) => console.log(JSON.stringify(obj))
});

async function emitAuditEvent(req, ev) {
  const tenantId = String(
    ev?.tenantId ||
    req?.__twynixAuth?.tenantId ||
    ''
  );
  const userId = String(
    ev?.userId !== undefined ? ev.userId : (req?.__twynixAuth?.userId || '')
  );

  try {
    const result = await emitOplogEvent({
      ...ev,
      tenantId,
      userId,
      corr: String(ev?.corr || req?.twynixRequestId || ''),
      targetType: String(ev?.targetType || ev?.entityType || ''),
      targetId: String(ev?.targetId || ev?.entityId || '')
    });
    if (!result?.ok) {
      serviceState.lastAuditError = result?.error || result?.reason || 'audit_not_written';
    }
    return result;
  } catch (e) {
    serviceState.lastAuditError = e.message || String(e);
    throw e;
  }
}

/* -------------------------------------------
   Helmet + hide x-powered-by
-------------------------------------------- */
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));

app.use((req, res, next) => {
  const incoming = req.headers['x-request-id'];
  const requestId = (typeof incoming === 'string' && incoming.trim()) ? incoming.trim() : crypto.randomUUID();
  req.twynixRequestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  next();
});

app.use((req, res, next) => {
  scrubInboundHeaders(req.headers);
  return next();
});

app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => {
    serviceState.http.requestsTotal += 1;
    serviceState.http.byMethod[req.method] = (serviceState.http.byMethod[req.method] || 0) + 1;
    const statusClass = `${Math.floor(res.statusCode / 100)}xx`;
    serviceState.http.byStatusClass[statusClass] = (serviceState.http.byStatusClass[statusClass] || 0) + 1;
    if (res.statusCode >= 500) {
      logSecurityEvent('http_5xx', {
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        durationMs: Date.now() - started,
        requestId: req.twynixRequestId || ''
      });
    }
  });
  next();
});

/* -------------------------------------------
   CORS
-------------------------------------------- */
const allowedOrigins = config.CORS_ORIGINS.split(',').map(s => s.trim()).filter(Boolean);
const corsOptions = {
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'X-Authorization', 'Authorization', 'X-Requested-With', 'X-Request-Id'],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  maxAge: 600
};
app.use(cors(corsOptions));

// ✅ NEW: Handle preflight OPTIONS (fixes 405 Method Not Allowed for shelving calls)
app.options('*', cors(corsOptions));

/* -------------------------------------------
   Rate limiting
-------------------------------------------- */
function proxyRateLimitKey(req) {
  const token = getBearerTokenFromHeaders(req.headers);
  return token ? `tok:${crypto.createHash('sha256').update(token).digest('base64url')}` : ipKeyGenerator(req.ip);
}

app.use(rateLimit({
  windowMs: config.PROXY_READ_RATE_WINDOW_MS,
  max: config.PROXY_READ_RATE_MAX,
  skip: (req) => !['GET', 'HEAD'].includes(req.method),
  keyGenerator: proxyRateLimitKey,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use(rateLimit({
  windowMs: config.PROXY_WRITE_RATE_WINDOW_MS,
  max: config.PROXY_WRITE_RATE_MAX,
  skip: (req) => ['GET', 'HEAD'].includes(req.method),
  keyGenerator: (req) => {
    if (req.path === '/api/auth/login') return ipKeyGenerator(req.ip);
    return proxyRateLimitKey(req);
  },
  standardHeaders: true,
  legacyHeaders: false,
}));

/* -------------------------------------------
   Login-specific limiter
-------------------------------------------- */
app.use('/api/auth/login', rateLimit({
  windowMs: 60_000,
  max: 10,
  keyGenerator: (req) => ipKeyGenerator(req.ip),
  standardHeaders: true,
  legacyHeaders: false,
}));

/* -------------------------------------------
   Request logger with redaction
-------------------------------------------- */
app.use((req, res, next) => {
  const headers = { ...req.headers };
  if (headers.authorization) headers.authorization = '[redacted]';
  if (headers['x-authorization']) headers['x-authorization'] = '[redacted]';
  if (headers['x-twynix-internal-admin']) delete headers['x-twynix-internal-admin'];
  console.log(`[${new Date().toISOString()}] ${req.ip} ${req.method} ${req.path} ${JSON.stringify(headers)}`);
  next();
});

/* -------------------------------------------
   Health endpoint
-------------------------------------------- */
app.get('/health', async (req, res) => {
  try {
    await getAdminToken();
    return res.json({ status: 'ok', tbAdmin: true });
  } catch {
    return res.status(500).json({ status: 'error', tbAdmin: false });
  }
});

/* ------------------------------------------------------------------
   Access check route (unchanged logic)
------------------------------------------------------------------- */
app.get('/api/access/check/:entityType/:entityId', async (req, res) => {
  const { entityType, entityId } = req.params;

  if (!['ASSET', 'DEVICE'].includes(entityType.toUpperCase())) {
    return res.status(400).send('Invalid entityType');
  }

  const userToken = getBearerTokenFromHeaders(req.headers);
  if (!userToken) {
    return res.status(401).send('Missing or invalid X-Authorization header');
  }

  let userId;
  try {
    await assertTokenValid(userToken);
    userId = getUserIdFromToken(userToken);
  } catch {
    return res.status(401).send('Invalid JWT token');
  }
  if (!userId) {
    return res.status(401).send('User ID not found in token');
  }

  try {
    const attrsArray = await fetchServerAttributesArrayCached(entityType, entityId);
    const securityAttr = getSecurityAttribute(attrsArray);

    if (!securityAttr) {
      return res.status(403).json({ access: false, reason: 'No security attribute found' });
    }

    let permissionsObj;
    try {
      permissionsObj = parseSecurityAttribute(securityAttr);
    } catch {
      return res.status(500).json({ access: false, reason: 'Failed to parse security attribute JSON' });
    }

    if (!hasPermission(permissionsObj, 'control', userId)) {
      return res.status(403).json({ access: false, reason: 'No control access' });
    }

    return res.json({ access: true });
  } catch (e) {
    console.error('Access check error:', e.message);
    return res.status(500).json({ access: false, reason: 'Internal server error' });
  }
});

/* -------------------------------------------
   IoTDB local routes (unchanged)
-------------------------------------------- */
app.post('/telemetry/:deviceId', express.json({ limit: config.LOCAL_JSON_LIMIT }), async (req, res) => {
  const auth = await requireValidUser(req, res);
  if (!auth) return;

  try {
    const access = await assertEntityPermission('DEVICE', req.params.deviceId, auth.userId, 'control');
    if (!access.ok) {
      await emitAuditEvent(req, {
        type: 'iotdb_telemetry_write', outcome: 'denied', reason: access.reason,
        userId: auth.userId, entityType: 'DEVICE', entityId: req.params.deviceId,
        method: 'POST', path: req.path
      });
      return res.status(access.status).send(access.reason);
    }

    const payload = { device: req.params.deviceId, measurements: req.body.data };
    if (!payload.measurements || typeof payload.measurements !== 'object') {
      return res.status(400).json({ error: 'data object is required' });
    }
    const resp = await ax.post(`${config.IOTDB_URL}/v2/write`, payload, {
      headers: {
        Authorization: `Basic ${config.IOTDB_AUTH}`,
        'Content-Type': 'application/json',
      },
    });
    res.status(resp.status).send('Data written successfully');
  } catch (e) {
    console.error('IoTDB write error:', e.message);
    serviceState.lastIotdbError = e.message || String(e);
    res.status(500).send('Failed to write data to IoTDB');
  }
});

app.post('/query', express.json({ limit: config.LOCAL_JSON_LIMIT }), async (req, res) => {
  if (!config.IOTDB_QUERY_ENABLED) {
    return res.status(404).json({ error: 'IoTDB query endpoint is disabled' });
  }

  const auth = await requireValidUser(req, res);
  if (!auth) return;

  const authorities = getUserAuthoritiesFromToken(auth.userToken);
  if (!hasAllowedRole(authorities)) {
    await emitAuditEvent(req, {
      type: 'iotdb_query', outcome: 'denied', reason: 'Insufficient role',
      userId: auth.userId, method: 'POST', path: req.path
    });
    return res.status(403).send('Forbidden: insufficient role');
  }

  if (!isReadOnlyIotdbQuery(req.body)) {
    await emitAuditEvent(req, {
      type: 'iotdb_query', outcome: 'denied', reason: 'Query is not allowlisted as read-only',
      userId: auth.userId, method: 'POST', path: req.path
    });
    return res.status(400).json({ error: 'Only a single read-only SELECT/SHOW/COUNT query is allowed' });
  }

  try {
    const resp = await ax.post(`${config.IOTDB_URL}/rest/v2/query`, req.body, {
      headers: {
        Authorization: `Basic ${config.IOTDB_AUTH}`,
        'Content-Type': 'application/json',
      },
    });
    res.status(resp.status).json(resp.data);
  } catch (e) {
    console.error('IoTDB query error:', e.message);
    serviceState.lastIotdbError = e.message || String(e);
    res.status(500).send('Failed to query data from IoTDB');
  }
});

app.post('/api/iotdb/trend/query', express.json({ limit: config.LOCAL_JSON_LIMIT }), createTrendQueryHandler({
  config,
  ax,
  requireValidUser,
  serviceState,
  logger: (msg) => console.log(msg)
}));

app.get('/api/iotdb/schema', createIotdbSchemaHandler({
  config,
  ax,
  requireValidUser,
  serviceState,
  logger: (msg) => console.log(msg)
}));

/* -------------------------------------------
   OPC UA service-layer routes
   - TwynIX frontend calls these endpoints.
   - Discovery goes through ThingsBoard server-side RPC to the gateway.
   - Configuration applies ONLY through ThingsBoard shared attributes.
-------------------------------------------- */
function sanitizeDiscoverRequest(body = {}) {
  return {
    rootNodeId: clampText(body.rootNodeId || body.nodeId || 'RootFolder', 512) || 'RootFolder',
    endpointId: clampText(body.endpointId || 'default', 128) || 'default',
    maxDepth: Math.max(0, Math.min(20, Number(body.maxDepth ?? 6))),
    maxNodes: Math.max(1, Math.min(10000, Number(body.maxNodes ?? 1000))),
    timeoutMs: Math.max(1000, Math.min(config.RPC_TIMEOUT_MAX_MS, Number(body.timeoutMs ?? 30000)))
  };
}

function extractAttributeValue(attrsArray, key) {
  const item = Array.isArray(attrsArray) ? attrsArray.find((attr) => attr.key === key) : null;
  return item ? item.value : null;
}

function buildDesiredConfigPayload(body = {}) {
  const desiredConfig = body.edge?.desiredConfig || body.desiredConfig || body.config || (() => {
    const {
      desiredConfigVersion,
      version,
      edge,
      ...configPatch
    } = body;
    return configPatch;
  })();
  const desiredVersion = clampText(
    body.edge?.desiredConfigVersion ||
      body.desiredConfigVersion ||
      body.version ||
      `opcua-config-${new Date().toISOString()}`,
    160
  );

  if (!desiredConfig || typeof desiredConfig !== 'object' || Array.isArray(desiredConfig)) {
    throw new Error('desiredConfig must be an object');
  }

  return {
    'edge.desiredConfigVersion': desiredVersion,
    'edge.desiredConfig': desiredConfig
  };
}

async function requireGatewayControl(req, res, gatewayDeviceId, operation) {
  const auth = await requireValidUser(req, res);
  if (!auth) return null;

  const access = await assertEntityPermission('DEVICE', gatewayDeviceId, auth.userId, 'control');
  if (!access.ok) {
    await emitAuditEvent(req, {
      type: `opcua_${operation}`,
      outcome: 'denied',
      reason: access.reason,
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });
    res.status(access.status).send(access.reason);
    return null;
  }

  return auth;
}

async function requireGatewayRead(req, res, gatewayDeviceId, operation) {
  const auth = await requireValidUser(req, res);
  if (!auth) return null;

  const access = await assertEntityAnyPermission('DEVICE', gatewayDeviceId, auth.userId, ['view', 'read', 'control']);
  if (!access.ok) {
    await emitAuditEvent(req, {
      type: `opcua_${operation}`,
      outcome: 'denied',
      reason: access.reason,
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });
    res.status(access.status).send(access.reason);
    return null;
  }

  return auth;
}

async function handleOpcUaDiscover(req, res) {
  const gatewayDeviceId = String(req.params.gatewayDeviceId || '');
  const auth = await requireGatewayControl(req, res, gatewayDeviceId, 'discover');
  if (!auth) return;

  const params = sanitizeDiscoverRequest(req.body || {});
  const adminTok = await getAdminToken();

  try {
    const resp = await postThingsBoardDeviceRpc(gatewayDeviceId, 'opcuaDiscoverVariables', params, adminTok);

    await emitAuditEvent(req, {
      type: 'opcua_discover',
      outcome: 'allowed',
      reason: 'device_acl',
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });

    return res.status(resp.status).json(resp.data);
  } catch (e) {
    const rpcError = buildOpcUaRpcError(e, 'opcua_discover');
    const message = rpcError.body.upstreamMessage || rpcError.body.error;
    serviceState.lastThingsBoardError = message;
    await emitAuditEvent(req, {
      type: 'opcua_discover',
      outcome: 'error',
      reason: message,
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });
    return res.status(rpcError.httpStatus).json(rpcError.body);
  }
}

async function handleTwynixOpcUaDiscoverVariables(req, res) {
  const gatewayDeviceId = String(req.body?.gatewayDeviceId || req.query?.gatewayDeviceId || '');
  if (!gatewayDeviceId) return res.status(400).json({ error: 'gatewayDeviceId is required' });
  req.params.gatewayDeviceId = gatewayDeviceId;

  const originalJson = res.json.bind(res);
  res.json = (payload) => {
    if (payload && Array.isArray(payload.variables)) return originalJson(payload.variables);
    return originalJson(payload);
  };
  return handleOpcUaDiscover(req, res);
}

async function handleTwynixOpcUaBrowse(req, res) {
  const gatewayDeviceId = String(req.body?.gatewayDeviceId || req.query?.gatewayDeviceId || '');
  if (!gatewayDeviceId) return res.status(400).json({ error: 'gatewayDeviceId is required' });

  const auth = await requireGatewayControl(req, res, gatewayDeviceId, 'browse');
  if (!auth) return;

  const params = {
    endpointId: clampText(req.body?.endpointId || req.query?.endpointId || 'default', 128) || 'default',
    nodeId: clampText(req.body?.nodeId || req.query?.nodeId || 'RootFolder', 512) || 'RootFolder',
    timeoutMs: Math.max(1000, Math.min(config.RPC_TIMEOUT_MAX_MS, Number(req.body?.timeoutMs ?? req.query?.timeoutMs ?? 30000)))
  };
  const adminTok = await getAdminToken();

  try {
    const resp = await postThingsBoardDeviceRpc(gatewayDeviceId, 'opcuaBrowse', params, adminTok);

    await emitAuditEvent(req, {
      type: 'opcua_browse',
      outcome: 'allowed',
      reason: 'device_acl',
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });

    return res.status(resp.status).json(Array.isArray(resp.data?.nodes) ? resp.data.nodes : resp.data);
  } catch (e) {
    const rpcError = buildOpcUaRpcError(e, 'opcua_browse');
    const message = rpcError.body.upstreamMessage || rpcError.body.error;
    serviceState.lastThingsBoardError = message;
    await emitAuditEvent(req, {
      type: 'opcua_browse',
      outcome: 'error',
      reason: message,
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });
    return res.status(rpcError.httpStatus).json(rpcError.body);
  }
}

async function handleOpcUaConfigApply(req, res) {
  const gatewayDeviceId = String(req.params.gatewayDeviceId || '');
  const auth = await requireGatewayControl(req, res, gatewayDeviceId, 'config_apply');
  if (!auth) return;

  let payload;
  try {
    payload = buildDesiredConfigPayload(req.body || {});
  } catch (e) {
    return res.status(400).json({ error: e.message || String(e) });
  }

  const adminTok = await getAdminToken();
  try {
    const resp = await ax.post(
      `${config.THINGSBOARD_URL}/api/plugins/telemetry/DEVICE/${gatewayDeviceId}/SHARED_SCOPE`,
      payload,
      {
        headers: {
          'X-Authorization': `Bearer ${adminTok}`,
          'Content-Type': 'application/json'
        },
        __tbAdmin: true
      }
    );

    await emitAuditEvent(req, {
      type: 'opcua_config_apply',
      outcome: 'allowed',
      reason: 'shared_attributes',
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });

    return res.status(resp.status).json({
      ok: true,
      desiredVersion: payload['edge.desiredConfigVersion']
    });
  } catch (e) {
    const message = formatUpstreamAuthError(e);
    serviceState.lastThingsBoardError = message;
    await emitAuditEvent(req, {
      type: 'opcua_config_apply',
      outcome: 'error',
      reason: message,
      userId: auth.userId,
      entityType: 'DEVICE',
      entityId: gatewayDeviceId,
      method: req.method,
      path: req.path
    });
    return res.status(e?.response?.status || 502).json({ ok: false, error: message });
  }
}

async function handleOpcUaConfigStatus(req, res) {
  const gatewayDeviceId = String(req.params.gatewayDeviceId || '');
  const auth = await requireGatewayRead(req, res, gatewayDeviceId, 'config_status');
  if (!auth) return;

  const adminTok = await getAdminToken();
  try {
    const resp = await ax.get(
      `${config.THINGSBOARD_URL}/api/plugins/telemetry/DEVICE/${gatewayDeviceId}/values/attributes/CLIENT_SCOPE?keys=${encodeURIComponent('edge.configStatus')}`,
      {
        headers: { 'X-Authorization': `Bearer ${adminTok}` },
        __tbAdmin: true
      }
    );
    return res.json({
      ok: true,
      configStatus: extractAttributeValue(resp.data, 'edge.configStatus')
    });
  } catch (e) {
    const message = formatUpstreamAuthError(e);
    serviceState.lastThingsBoardError = message;
    return res.status(e?.response?.status || 502).json({ ok: false, error: message });
  }
}

app.post('/api/opcua/gateways/:gatewayDeviceId/discover', express.json({ limit: config.RPC_JSON_LIMIT }), handleOpcUaDiscover);
app.post('/opcua/gateways/:gatewayDeviceId/discover', express.json({ limit: config.RPC_JSON_LIMIT }), handleOpcUaDiscover);
app.post('/api/twynix/opcua/discover-variables', express.json({ limit: config.RPC_JSON_LIMIT }), handleTwynixOpcUaDiscoverVariables);
app.post('/api/twynix/opcua/browse', express.json({ limit: config.RPC_JSON_LIMIT }), handleTwynixOpcUaBrowse);
app.put('/api/opcua/gateways/:gatewayDeviceId/config', express.json({ limit: config.LOCAL_JSON_LIMIT }), handleOpcUaConfigApply);
app.put('/opcua/gateways/:gatewayDeviceId/config', express.json({ limit: config.LOCAL_JSON_LIMIT }), handleOpcUaConfigApply);
app.get('/api/opcua/gateways/:gatewayDeviceId/config-status', handleOpcUaConfigStatus);
app.get('/opcua/gateways/:gatewayDeviceId/config-status', handleOpcUaConfigStatus);

/* -------------------------------------------
   Helper to read 'security' attribute (same)
-------------------------------------------- */
function getSecurityAttribute(attrsArray) {
  const securityAttr = attrsArray.find(attr => attr.key === 'security');
  return securityAttr ? securityAttr.value : null;
}

function parseSecurityAttribute(securityAttr) {
  if (!securityAttr) return null;
  return typeof securityAttr === 'string' ? JSON.parse(securityAttr) : securityAttr;
}

function hasPermission(permissionsObj, permissionName, userId) {
  const users = permissionsObj?.permissions?.[permissionName] || [];
  return Array.isArray(users) && users.includes(userId);
}

async function assertEntityPermission(entityType, entityId, userId, permissionName) {
  const attrsArray = await fetchServerAttributesArrayCached(entityType, entityId);
  const securityAttr = getSecurityAttribute(attrsArray);
  if (!securityAttr) return { ok: false, status: 403, reason: 'No security attribute found' };

  let permissionsObj;
  try {
    permissionsObj = parseSecurityAttribute(securityAttr);
  } catch {
    return { ok: false, status: 500, reason: 'Failed to parse security attribute JSON' };
  }

  if (!hasPermission(permissionsObj, permissionName, userId)) {
    return { ok: false, status: 403, reason: `No ${permissionName} access` };
  }

  return { ok: true };
}

async function assertEntityAnyPermission(entityType, entityId, userId, permissionNames) {
  const attrsArray = await fetchServerAttributesArrayCached(entityType, entityId);
  const securityAttr = getSecurityAttribute(attrsArray);
  if (!securityAttr) return { ok: false, status: 403, reason: 'No security attribute found' };

  let permissionsObj;
  try {
    permissionsObj = parseSecurityAttribute(securityAttr);
  } catch {
    return { ok: false, status: 500, reason: 'Failed to parse security attribute JSON' };
  }

  if (!permissionNames.some((name) => hasPermission(permissionsObj, name, userId))) {
    return { ok: false, status: 403, reason: `No ${permissionNames.join('/')} access` };
  }

  return { ok: true };
}

/* -----------------------------------------------------------------
   SHARED_SCOPE ACL middleware (unchanged logic; uses req.path)
------------------------------------------------------------------ */
async function permissionCheckMiddleware(req, res, next) {
  if (req.headers['x-twynix-internal-admin'] === config.INTERNAL_PROXY_SECRET) {
    return next();
  }
  const sharedScopeRegex = /^\/api\/plugins\/telemetry\/(ASSET|DEVICE)\/([a-zA-Z0-9\-]+)\/SHARED_SCOPE\/?$/;
  if ((req.method === 'POST' || req.method === 'PUT') && sharedScopeRegex.test(req.path)) {
    const matches = req.path.match(sharedScopeRegex);
    const entityType = matches[1];
    const entityId = matches[2];

    const userToken = getBearerTokenFromHeaders(req.headers);
    if (!userToken) {
      await emitAuditEvent(req, {
        type: 'shared_write', outcome: 'denied', reason: 'Missing or invalid X-Authorization header',
        userId: '', entityType, entityId, method: req.method, path: req.path
      });
      return res.status(401).send('Missing or invalid X-Authorization header');
    }

    let userId;
    const tenantId = getTenantIdFromToken(userToken) || '';
    try {
      await assertTokenValid(userToken);
      userId = getUserIdFromToken(userToken);
    } catch {
      await emitAuditEvent(req, {
        type: 'shared_write', outcome: 'denied', reason: 'Invalid JWT token',
        userId: '', entityType, entityId, method: req.method, path: req.path
      });
      return res.status(401).send('Invalid JWT token');
    }
    if (!userId) {
      await emitAuditEvent(req, {
        type: 'shared_write', outcome: 'denied', reason: 'User ID not found in token',
        userId: '', entityType, entityId, method: req.method, path: req.path
      });
      return res.status(401).send('User ID not found in token');
    }
    req.__twynixAuth = { tenantId, userId };

    try {
      const attrsArray = await fetchServerAttributesArrayCached(entityType, entityId);
      const securityAttr = getSecurityAttribute(attrsArray);
      if (!securityAttr) {
        await emitAuditEvent(req, {
          type: 'shared_write', outcome: 'denied', reason: 'No security attribute found',
          userId, entityType, entityId, method: req.method, path: req.path
        });
        return res.status(403).send('Forbidden: No security attribute found');
      }

      let permissionsObj;
      try {
        permissionsObj = parseSecurityAttribute(securityAttr);
      } catch {
        await emitAuditEvent(req, {
          type: 'shared_write', outcome: 'error', reason: 'Failed to parse security attribute JSON',
          userId, entityType, entityId, method: req.method, path: req.path
        });
        return res.status(500).send('Failed to parse security attribute JSON');
      }

      if (!hasPermission(permissionsObj, 'control', userId)) {
        await emitAuditEvent(req, {
          type: 'shared_write', outcome: 'denied', reason: 'No control access',
          userId, entityType, entityId, method: req.method, path: req.path
        });
        return res.status(403).send('Forbidden: No control access');
      }

      await emitAuditEvent(req, {
        type: 'shared_write', outcome: 'allowed',
        userId, entityType, entityId, method: req.method, path: req.path
      });

      next();
    } catch (e) {
      console.error('Permission check error:', e.message);
      await emitAuditEvent(req, {
        type: 'shared_write', outcome: 'error', reason: 'Failed to verify permissions',
        userId: userId || '', entityType, entityId, method: req.method, path: req.path
      });
      return res.status(500).send('Failed to verify permissions');
    }
  } else {
    next();
  }
}

const rpcRateBuckets = new Map();

function checkRpcRateLimit(userId, deviceId) {
  const now = Date.now();
  const key = `${userId}:${deviceId}`;
  const bucket = rpcRateBuckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    rpcRateBuckets.set(key, { resetAt: now + config.RPC_RATE_WINDOW_MS, count: 1 });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= config.RPC_RATE_MAX;
}

/* ==================================================================
   RPC ACL middleware
   - Guards /api/plugins/rpc/oneway/:deviceId and /api/plugins/rpc/twoway/:deviceId
   - Uses admin token to read DEVICE SERVER_SCOPE 'security' for the DEVICE
   - Allows if userId is in permissions.control
   - Validates JSON body before proxying and re-streams it with fixRequestBody
================================================================== */
async function rpcPermissionMiddleware(req, res, next) {
  if (req.method.toUpperCase() !== 'POST') return next();

  const rpcRx = /^\/api\/plugins\/rpc\/(oneway|twoway)\/([a-zA-Z0-9\-]+)\/?$/i;
  if (!rpcRx.test(req.path)) return next();

  const m = req.path.match(rpcRx);
  const mode = (m && m[1]) ? String(m[1]).toLowerCase() : 'unknown';
  const deviceId = (m && m[2]) ? String(m[2]) : '';

  const rpcMethod = typeof req.body?.method === 'string' ? req.body.method.trim() : '';
  const bodyError = validateRpcBody(req.body, mode, rpcPolicy);
  if (bodyError) {
    logSecurityEvent('rpc_denied', {
      reason: bodyError,
      mode,
      deviceId,
      rpcMethod,
      requestId: req.twynixRequestId || ''
    });
    const auditResult = await emitAuditEvent(req, {
      type: `rpc_${mode}`, outcome: 'denied', reason: bodyError,
      userId: '', entityType: 'DEVICE', entityId: deviceId,
      method: req.method, path: req.path
    });
    if (config.RPC_REQUIRE_AUDIT && !auditResult?.ok) return res.status(503).send('Audit log unavailable');
    return res.status(400).send(bodyError);
  }

  const userToken = getBearerTokenFromHeaders(req.headers);
  if (!userToken) {
    logSecurityEvent('rpc_denied', {
      reason: 'missing_token',
      mode,
      deviceId,
      rpcMethod,
      requestId: req.twynixRequestId || ''
    });
    await emitAuditEvent(req, {
      type: `rpc_${mode}`, outcome: 'denied', reason: 'Missing or invalid X-Authorization header',
      userId: '', entityType: 'DEVICE', entityId: deviceId,
      method: req.method, path: req.path
    });
    return res.status(401).send('Missing or invalid X-Authorization header');
  }

  let userId;
  const tenantId = getTenantIdFromToken(userToken) || '';
  try {
    await assertTokenValid(userToken);
    userId = getUserIdFromToken(userToken);
  } catch {
    logSecurityEvent('rpc_denied', {
      reason: 'invalid_token',
      mode,
      deviceId,
      rpcMethod,
      requestId: req.twynixRequestId || ''
    });
    await emitAuditEvent(req, {
      type: `rpc_${mode}`, outcome: 'denied', reason: 'Invalid JWT token',
      userId: '', entityType: 'DEVICE', entityId: deviceId,
      method: req.method, path: req.path
    });
    return res.status(401).send('Invalid JWT token');
  }

  if (!userId) {
    logSecurityEvent('rpc_denied', {
      reason: 'missing_user_id',
      mode,
      deviceId,
      rpcMethod,
      requestId: req.twynixRequestId || ''
    });
    await emitAuditEvent(req, {
      type: `rpc_${mode}`, outcome: 'denied', reason: 'User ID not found in token',
      userId: '', entityType: 'DEVICE', entityId: deviceId,
      method: req.method, path: req.path
    });
    return res.status(401).send('User ID not found in token');
  }
  req.__twynixAuth = { tenantId, userId };

  try {
    const attrsArray = await fetchServerAttributesArrayCached('DEVICE', deviceId);
    const securityAttr = getSecurityAttribute(attrsArray);

    if (!securityAttr) {
      logSecurityEvent('rpc_denied', {
        reason: 'missing_security_attribute',
        mode,
        deviceId,
        rpcMethod,
        userId,
        requestId: req.twynixRequestId || ''
      });
      await emitAuditEvent(req, {
        type: `rpc_${mode}`, outcome: 'denied', reason: 'No security attribute found',
        userId, entityType: 'DEVICE', entityId: deviceId,
        method: req.method, path: req.path
      });
      return res.status(403).send('Forbidden: No security attribute found');
    }

    let permissionsObj;
    try {
      permissionsObj = parseSecurityAttribute(securityAttr);
    } catch {
      logSecurityEvent('rpc_error', {
        reason: 'security_attribute_parse_failed',
        mode,
        deviceId,
        rpcMethod,
        userId,
        requestId: req.twynixRequestId || ''
      });
      await emitAuditEvent(req, {
        type: `rpc_${mode}`, outcome: 'error', reason: 'Failed to parse security attribute JSON',
        userId, entityType: 'DEVICE', entityId: deviceId,
        method: req.method, path: req.path
      });
      return res.status(500).send('Failed to parse security attribute JSON');
    }

    if (!hasPermission(permissionsObj, 'control', userId)) {
      logSecurityEvent('rpc_denied', {
        reason: 'no_control_access',
        mode,
        deviceId,
        rpcMethod,
        userId,
        requestId: req.twynixRequestId || ''
      });
      await emitAuditEvent(req, {
        type: `rpc_${mode}`, outcome: 'denied', reason: 'No control access',
        userId, entityType: 'DEVICE', entityId: deviceId,
        method: req.method, path: req.path
      });
      return res.status(403).send('Forbidden: No control access');
    }

    if (!checkRpcRateLimit(userId, deviceId)) {
      logSecurityEvent('rpc_denied', {
        reason: 'rate_limited',
        mode,
        deviceId,
        rpcMethod,
        userId,
        requestId: req.twynixRequestId || ''
      });
      await emitAuditEvent(req, {
        type: `rpc_${mode}`, outcome: 'denied', reason: 'RPC rate limit exceeded',
        userId, entityType: 'DEVICE', entityId: deviceId,
        method: req.method, path: req.path
      });
      return res.status(429).send('RPC rate limit exceeded');
    }

    logSecurityEvent('rpc_allowed', {
      mode,
      deviceId,
      rpcMethod,
      userId,
      requestId: req.twynixRequestId || ''
    });

    const auditResult = await emitAuditEvent(req, {
      type: `rpc_${mode}`, outcome: 'allowed', reason: 'device_acl',
      userId, entityType: 'DEVICE', entityId: deviceId,
      method: req.method, path: req.path
    });
    if (config.RPC_REQUIRE_AUDIT && !auditResult?.ok) return res.status(503).send('Audit log unavailable');

    return next();
  } catch (e) {
    console.error('rpcPermissionMiddleware error:', e.message);
    logSecurityEvent('rpc_error', {
      reason: 'permission_check_failed',
      mode,
      deviceId,
      rpcMethod,
      userId,
      requestId: req.twynixRequestId || ''
    });
    await emitAuditEvent(req, {
      type: `rpc_${mode}`, outcome: 'error', reason: 'Failed to verify permissions',
      userId, entityType: 'DEVICE', entityId: deviceId,
      method: req.method, path: req.path
    });
    return res.status(500).send('Failed to verify RPC permissions');
  }
}

/* -----------------------------------------------------------------
   Management write allowlist (incl. SERVER_SCOPE for admins)
------------------------------------------------------------------ */
const UUID_RX = '[0-9a-fA-F-]{36}';
const MGMT_POLICIES = [
  // Create Asset
  { rx: new RegExp(`^/api/asset/?$`, 'i'), methods: ['POST'] },
  // Update/Delete Asset by ID
  { rx: new RegExp(`^/api/asset/${UUID_RX}/?$`, 'i'), methods: ['PUT', 'DELETE'] },
  // Allow SERVER_SCOPE writes for ASSET/DEVICE (admins)
  { rx: new RegExp(`^/api/plugins/telemetry/(ASSET|DEVICE)/${UUID_RX}/SERVER_SCOPE/?$`, 'i'), methods: ['POST', 'PUT'] },
  // AAS submodel graph relation writes.
  { rx: /^\/api\/relation\/?$/i, methods: ['POST', 'DELETE'] },
  { rx: /^\/api\/relations\/?$/i, methods: ['POST'] },
  { rx: /^\/api\/relation\/delete\/?$/i, methods: ['POST'] },
];

function pathMethodMatchesPolicy(path_, method) {
  method = method.toUpperCase();
  return MGMT_POLICIES.find(p => p.methods.includes(method) && p.rx.test(path_));
}
function hasAllowedRole(authorities) {
  return authorities.some(a => config.MGMT_ALLOWED_ROLES.includes(a));
}
async function writePolicyMiddleware(req, res, next) {
  const policy = pathMethodMatchesPolicy(req.path, req.method);
  if (!policy) return next();

  const userToken = getBearerTokenFromHeaders(req.headers);
  if (!userToken) {
    await emitAuditEvent(req, {
      type: 'mgmt_write', outcome: 'denied', reason: 'Missing or invalid X-Authorization header',
      method: req.method, path: req.path
    });
    return res.status(401).send('Missing or invalid X-Authorization header');
  }

  try {
    await assertTokenValid(userToken);
    req.__twynixAuth = {
      tenantId: getTenantIdFromToken(userToken) || '',
      userId: getUserIdFromToken(userToken) || ''
    };
    const authorities = getUserAuthoritiesFromToken(userToken);

    if (!hasAllowedRole(authorities)) {
      await emitAuditEvent(req, {
        type: 'mgmt_write', outcome: 'denied', reason: 'Insufficient role',
        method: req.method, path: req.path
      });
      return res.status(403).send('Forbidden: insufficient role');
    }

    req.__allowedMgmtWrite = true;

    await emitAuditEvent(req, {
      type: 'mgmt_write', outcome: 'allowed',
      method: req.method, path: req.path
    });

    return next();
  } catch (e) {
    console.error('writePolicyMiddleware error:', e.message);
    await emitAuditEvent(req, {
      type: 'mgmt_write', outcome: 'error', reason: 'Validation failed',
      method: req.method, path: req.path
    });
    return res.status(500).send('Failed to validate management write');
  }
}
app.use(writePolicyMiddleware);

/* -----------------------------------------------------------------
   Narrow deny-by-default: ONLY guard TELEMETRY plugin writes.
   Everything else (non-telemetry) passes through to TB.
------------------------------------------------------------------ */
app.use(createTelemetryWriteGuard({
  emitOplogEvent,
  internalSecret: config.INTERNAL_PROXY_SECRET
}));

/* =========================================================================================
   ✅ NEW: Global Alarm Shelving (SCADA-style) using better-sqlite3
   - Shelve by DEFINITION: (tenantId, originatorId, alarmType)
   - Persisted, shared across clients, with expiry cleanup
========================================================================================= */

function ensureDirForFile(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

ensureDirForFile(config.SHELVING_DB_PATH);
const db = new Database(config.SHELVING_DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS alarm_shelving (
  tenant_id      TEXT NOT NULL,
  originator_id  TEXT NOT NULL,
  alarm_type     TEXT NOT NULL,
  shelved_until  INTEGER NOT NULL,
  shelved_at     INTEGER NOT NULL,
  shelved_by     TEXT NOT NULL,
  reason_code    TEXT,
  comment        TEXT,
  PRIMARY KEY (tenant_id, originator_id, alarm_type)
);

CREATE INDEX IF NOT EXISTS idx_alarm_shelving_until
ON alarm_shelving (tenant_id, shelved_until);
`);

const stmtUpsertShelve = db.prepare(`
INSERT INTO alarm_shelving
(tenant_id, originator_id, alarm_type, shelved_until, shelved_at, shelved_by, reason_code, comment)
VALUES (@tenant_id, @originator_id, @alarm_type, @shelved_until, @shelved_at, @shelved_by, @reason_code, @comment)
ON CONFLICT(tenant_id, originator_id, alarm_type)
DO UPDATE SET
  shelved_until=excluded.shelved_until,
  shelved_at=excluded.shelved_at,
  shelved_by=excluded.shelved_by,
  reason_code=excluded.reason_code,
  comment=excluded.comment
`);

const stmtUnshelve = db.prepare(`
DELETE FROM alarm_shelving
WHERE tenant_id = ? AND originator_id = ? AND alarm_type = ?
`);

const stmtLookupMany = db.prepare(`
SELECT tenant_id, originator_id, alarm_type, shelved_until, shelved_at, shelved_by, reason_code, comment
FROM alarm_shelving
WHERE tenant_id = ? AND originator_id = ? AND alarm_type = ? AND shelved_until > ?
`);

const stmtDeleteExpired = db.prepare(`
DELETE FROM alarm_shelving
WHERE shelved_until <= ?
`);

function requireUserToken(req) {
  return getBearerTokenFromHeaders(req.headers);
}

async function requireValidUser(req, res) {
  const userToken = requireUserToken(req);
  if (!userToken) {
    res.status(401).send('Missing or invalid X-Authorization header');
    return null;
  }

  try {
    await assertTokenValid(userToken);
  } catch {
    res.status(401).send('Invalid JWT token');
    return null;
  }

  const userId = getUserIdFromToken(userToken);
  if (!userId) {
    res.status(401).send('User ID not found in token');
    return null;
  }

  const tenantId = getTenantIdFromToken(userToken) || 'unknown';
  req.__twynixAuth = { tenantId, userId };
  return { userToken, userId, tenantId };
}

app.use(createTwynixOplogRouter({
  config,
  ax,
  getAdminToken,
  requireValidUser,
  logger: (obj) => console.log(JSON.stringify(obj))
}));

app.use('/api/cameras', createCameraAssetsRouter({
  express,
  ax,
  config,
  getAdminToken,
  requireValidUser,
  getUserAuthoritiesFromToken,
  getCustomerIdFromToken,
  hasAllowedRole,
  emitAuditEvent
}));

app.get('/twynix/status', async (req, res) => {
  const auth = await requireValidUser(req, res);
  if (!auth) return;

  if (!hasAllowedRole(getUserAuthoritiesFromToken(auth.userToken))) {
    return res.status(403).json({ error: 'Forbidden: insufficient role' });
  }

  let tbAdminOk = false;
  try {
    await getAdminToken();
    tbAdminOk = true;
  } catch (e) {
    serviceState.lastThingsBoardError = e.message || String(e);
  }

  let shelvingDbOk = false;
  try {
    db.prepare('SELECT 1 AS ok').get();
    shelvingDbOk = true;
  } catch (e) {
    serviceState.lastShelvingError = e.message || String(e);
  }

  return res.json({
    status: tbAdminOk && shelvingDbOk ? 'ok' : 'degraded',
    uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
    thingsBoard: {
      url: config.THINGSBOARD_URL,
      adminLogin: tbAdminOk,
      lastAdminLoginAt: serviceState.lastTbAdminLoginAt,
      lastAdminLoginError: serviceState.lastTbAdminLoginError,
      lastError: serviceState.lastThingsBoardError
    },
    iotdb: {
      url: config.IOTDB_URL,
      queryEnabled: config.IOTDB_QUERY_ENABLED,
      lastError: serviceState.lastIotdbError
    },
    rpc: {
      aclEnabled: config.RPC_ACL_ENABLED,
      allowedMethods: config.RPC_ALLOWED_METHODS,
      allowedTagsConfigured: Boolean(config.RPC_ALLOWED_TAGS),
      requireAudit: config.RPC_REQUIRE_AUDIT,
      rateWindowMs: config.RPC_RATE_WINDOW_MS,
      rateMax: config.RPC_RATE_MAX
    },
    audit: {
      hmacEnabled: Boolean(config.AUDIT_HMAC_SECRET),
      lastError: serviceState.lastAuditError
    },
    shelving: {
      dbPath: path.resolve(config.SHELVING_DB_PATH),
      dbOk: shelvingDbOk,
      lastError: serviceState.lastShelvingError
    },
    http: serviceState.http,
    configWarnings: serviceState.configWarnings,
    securityEvents: serviceState.securityEvents
  });
});

app.get('/twynix/metrics', async (req, res) => {
  const auth = await requireValidUser(req, res);
  if (!auth) return;

  if (!hasAllowedRole(getUserAuthoritiesFromToken(auth.userToken))) {
    return res.status(403).send('Forbidden: insufficient role');
  }

  const lines = [
    '# HELP twynix_proxy_uptime_seconds Proxy uptime in seconds',
    '# TYPE twynix_proxy_uptime_seconds gauge',
    `twynix_proxy_uptime_seconds ${Math.floor((Date.now() - startedAt) / 1000)}`,
    '# HELP twynix_proxy_http_requests_total HTTP requests handled by proxy',
    '# TYPE twynix_proxy_http_requests_total counter',
    `twynix_proxy_http_requests_total ${serviceState.http.requestsTotal}`
  ];

  for (const [method, count] of Object.entries(serviceState.http.byMethod)) {
    lines.push(`twynix_proxy_http_requests_by_method_total{method="${method}"} ${count}`);
  }
  for (const [statusClass, count] of Object.entries(serviceState.http.byStatusClass)) {
    lines.push(`twynix_proxy_http_requests_by_status_class_total{status_class="${statusClass}"} ${count}`);
  }
  for (const [type, count] of Object.entries(serviceState.securityEvents)) {
    lines.push(`twynix_proxy_security_events_total{type="${type}"} ${count}`);
  }

  res.type('text/plain').send(`${lines.join('\n')}\n`);
});

function normalizeAlarmType(t) {
  return clampText(t, 128) || '';
}
function normalizeOriginatorId(id) {
  return clampText(id, 64) || '';
}

function sweepExpiredShelving() {
  try {
    const now = Date.now();
    const info = stmtDeleteExpired.run(now);
    if (info.changes > 0) {
      console.log(`[Shelving] expired records removed: ${info.changes}`);
    }
  } catch (e) {
    console.error('[Shelving] sweep error:', e.message);
  }
}

// Periodic cleanup
setInterval(sweepExpiredShelving, config.SHELVING_SWEEP_MS).unref();

// Routes for shelving
app.post('/twynix/alarms/shelve', express.json({ limit: config.LOCAL_JSON_LIMIT }), async (req, res) => {
  const auth = await requireValidUser(req, res);
  if (!auth) return;

  const originatorId = normalizeOriginatorId(req.body?.originatorId);
  const alarmType = normalizeAlarmType(req.body?.alarmType);
  const durationMs = Number(req.body?.durationMs || 0);

  if (!originatorId || !alarmType) {
    await emitAuditEvent(req, {
      type: 'alarm_shelve', outcome: 'denied', reason: 'Missing originatorId or alarmType',
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId || '',
      method: 'POST', path: '/twynix/alarms/shelve'
    });
    return res.status(400).json({ error: 'originatorId and alarmType are required' });
  }

  // Guard duration: 1 min .. 7 days (tweak as desired)
  const minMs = 60_000;
  const maxMs = 7 * 24 * 60 * 60_000;
  const dur = Math.max(minMs, Math.min(maxMs, isFinite(durationMs) ? durationMs : minMs));

  const now = Date.now();
  const shelvedUntil = now + dur;

  let access;
  try {
    access = await assertEntityPermission('DEVICE', originatorId, auth.userId, 'control');
  } catch (e) {
    console.error('[Shelving] ACL check error:', e.message);
    await emitAuditEvent(req, {
      type: 'alarm_shelve', outcome: 'error', reason: 'Failed to verify permissions',
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/shelve'
    });
    return res.status(500).send('Failed to verify permissions');
  }
  if (!access.ok) {
    await emitAuditEvent(req, {
      type: 'alarm_shelve', outcome: 'denied', reason: access.reason,
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/shelve'
    });
    return res.status(access.status).send(access.reason);
  }

  const reasonCode = clampText(req.body?.reasonCode, 64);
  const comment = clampText(req.body?.comment, 512);

  try {
    stmtUpsertShelve.run({
      tenant_id: auth.tenantId,
      originator_id: originatorId,
      alarm_type: alarmType,
      shelved_until: shelvedUntil,
      shelved_at: now,
      shelved_by: auth.userId,
      reason_code: reasonCode,
      comment
    });

    await emitAuditEvent(req, {
      type: 'alarm_shelve', outcome: 'allowed', reason: reasonCode || 'n/a',
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/shelve'
    });

    return res.json({
      tenantId: auth.tenantId,
      originatorId,
      alarmType,
      shelvedAt: now,
      shelvedUntil,
      shelvedBy: auth.userId,
      reasonCode,
      comment
    });
  } catch (e) {
    console.error('[Shelving] shelve error:', e.message);
    await emitAuditEvent(req, {
      type: 'alarm_shelve', outcome: 'error', reason: e.message,
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/shelve'
    });
    return res.status(500).json({ error: 'Failed to shelve alarm' });
  }
});

app.post('/twynix/alarms/unshelve', express.json({ limit: config.LOCAL_JSON_LIMIT }), async (req, res) => {
  const auth = await requireValidUser(req, res);
  if (!auth) return;

  const originatorId = normalizeOriginatorId(req.body?.originatorId);
  const alarmType = normalizeAlarmType(req.body?.alarmType);

  if (!originatorId || !alarmType) {
    await emitAuditEvent(req, {
      type: 'alarm_unshelve', outcome: 'denied', reason: 'Missing originatorId or alarmType',
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId || '',
      method: 'POST', path: '/twynix/alarms/unshelve'
    });
    return res.status(400).json({ error: 'originatorId and alarmType are required' });
  }

  let access;
  try {
    access = await assertEntityPermission('DEVICE', originatorId, auth.userId, 'control');
  } catch (e) {
    console.error('[Shelving] ACL check error:', e.message);
    await emitAuditEvent(req, {
      type: 'alarm_unshelve', outcome: 'error', reason: 'Failed to verify permissions',
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/unshelve'
    });
    return res.status(500).send('Failed to verify permissions');
  }
  if (!access.ok) {
    await emitAuditEvent(req, {
      type: 'alarm_unshelve', outcome: 'denied', reason: access.reason,
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/unshelve'
    });
    return res.status(access.status).send(access.reason);
  }

  try {
    const info = stmtUnshelve.run(auth.tenantId, originatorId, alarmType);

    await emitAuditEvent(req, {
      type: 'alarm_unshelve', outcome: 'allowed',
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/unshelve'
    });

    return res.json({
      tenantId: auth.tenantId,
      originatorId,
      alarmType,
      removed: info.changes
    });
  } catch (e) {
    console.error('[Shelving] unshelve error:', e.message);
    await emitAuditEvent(req, {
      type: 'alarm_unshelve', outcome: 'error', reason: e.message,
      userId: auth.userId, entityType: 'DEVICE', entityId: originatorId,
      method: 'POST', path: '/twynix/alarms/unshelve'
    });
    return res.status(500).json({ error: 'Failed to unshelve alarm' });
  }
});

app.post('/twynix/alarms/shelving/lookup', express.json({ limit: config.LOCAL_JSON_LIMIT }), async (req, res) => {
  const auth = await requireValidUser(req, res);
  if (!auth) return;

  const keys = Array.isArray(req.body?.keys) ? req.body.keys.slice(0, 500) : [];
  if (keys.length === 0) return res.json({ records: [] });

  const now = Date.now();
  const records = [];

  try {
    for (const k of keys) {
      const originatorId = normalizeOriginatorId(k?.originatorId);
      const alarmType = normalizeAlarmType(k?.alarmType);
      if (!originatorId || !alarmType) continue;

      const access = await assertEntityAnyPermission('DEVICE', originatorId, auth.userId, ['read', 'control']);
      if (!access.ok) continue;

      const row = stmtLookupMany.get(auth.tenantId, originatorId, alarmType, now);
      if (row) {
        records.push({
          originatorId: row.originator_id,
          alarmType: row.alarm_type,
          shelvedUntil: row.shelved_until,
          shelvedAt: row.shelved_at,
          shelvedBy: row.shelved_by,
          reasonCode: row.reason_code,
          comment: row.comment
        });
      }
    }
    return res.json({ records });
  } catch (e) {
    console.error('[Shelving] lookup error:', e.message);
    return res.status(500).json({ error: 'Failed to lookup shelving' });
  }
});

/* =========================================================================================
   ✅ END NEW Shelving
========================================================================================= */

const tbProxy = createProxyMiddleware({
  target: config.THINGSBOARD_URL,
  changeOrigin: true,
  xfwd: true,
  logLevel: 'debug',
  proxyTimeout: 30000,
  timeout: 35000,
  pathRewrite: (path_) => path_,
  onProxyReq: (proxyReq, req) => {
    console.log(`→ Proxying ${req.method} ${req.url}`);
    proxyReq.removeHeader('x-twynix-internal-admin');
    proxyReq.removeHeader('x-forwarded-user');
    proxyReq.removeHeader('x-forwarded-email');
    proxyReq.removeHeader('x-forwarded-roles');
    proxyReq.removeHeader('x-real-user');
    proxyReq.removeHeader('x-user-id');
    proxyReq.removeHeader('x-tenant-id');
    fixRequestBody(proxyReq, req);
  },
  onProxyRes: (proxyRes, req) => {
    // Helpful to debug 504 vs TB timeout
    console.log(`← TB ${req.method} ${req.url} -> ${proxyRes.statusCode}`);
  },
  onError: (err, req, res) => {
    console.error('Proxy error:', err.message);
    serviceState.lastThingsBoardError = err.message || String(err);
    if (!res.headersSent) res.status(502).send('Bad Gateway');
  },
});

const tbWsProxy = createProxyMiddleware({
  target: thingsboardWsUrl(),
  changeOrigin: true,
  xfwd: true,
  ws: true,
  logLevel: 'debug',
  pathRewrite: (path_) => path_,
  onProxyReqWs: (proxyReq, req) => {
    console.log(`-> WS proxying ${req.url}`);
    proxyReq.removeHeader('x-twynix-internal-admin');
    proxyReq.removeHeader('x-forwarded-user');
    proxyReq.removeHeader('x-forwarded-email');
    proxyReq.removeHeader('x-forwarded-roles');
    proxyReq.removeHeader('x-real-user');
    proxyReq.removeHeader('x-user-id');
    proxyReq.removeHeader('x-tenant-id');
  },
  onError: (err, req, socket) => {
    console.error('WebSocket proxy error:', err.message);
    serviceState.lastThingsBoardError = err.message || String(err);
    socket.destroy();
  },
});


/* -------------------------------------------
   Register permission check BEFORE proxy
-------------------------------------------- */
app.use(permissionCheckMiddleware);

/* -------------------------------------------
   RPC ACL is NOT registered unless enabled
-------------------------------------------- */
if (config.RPC_ACL_ENABLED) {
  console.log('[RPC] ACL middleware ENABLED');
  app.use('/api/plugins/rpc', express.json({ limit: config.RPC_JSON_LIMIT }));
  app.use(rpcPermissionMiddleware);
} else {
  console.log('[RPC] ACL middleware DISABLED (pure forward)');
}

/* -------------------------------------------
   Keep local routes unproxied; everything else → TB
-------------------------------------------- */
app.use((req, res, next) => {
  if (isLocalRoute(req.path)) {
    return next();
  }

  const policy = proxyRoutePolicy(req.method, req.path);
  if (!policy.allowed) {
    return res.status(403).json({ error: 'Proxy route is not allowlisted' });
  }

  const bodySizeError = validateProxyBodySize(req, config.PROXY_MAX_BODY_BYTES);
  if (bodySizeError) {
    logSecurityEvent('proxy_body_denied', {
      reason: bodySizeError.reason,
      method: req.method,
      path: req.path,
      requestId: req.twynixRequestId || ''
    });
    return res.status(bodySizeError.status).json({ error: bodySizeError.message });
  }

  if (!policy.public) {
    const userToken = getBearerTokenFromHeaders(req.headers);
    if (!userToken) {
      return res.status(401).send('Missing or invalid X-Authorization header');
    }
    return assertTokenValid(userToken)
      .then(() => {
        req.__twynixAuth = {
          tenantId: getTenantIdFromToken(userToken) || '',
          userId: getUserIdFromToken(userToken) || ''
        };
        if (!req.headers['x-authorization']) {
          req.headers['x-authorization'] = `Bearer ${userToken}`;
        }
        return tbProxy(req, res, next);
      })
      .catch(() => res.status(401).send('Invalid JWT token'));
  }

  return tbProxy(req, res, next);
});

app.use((err, req, res, next) => {
  if (!err) return next();
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'Malformed JSON body' });
  }
  console.error('Unhandled request error:', err.message);
  return res.status(500).json({ error: 'Internal server error' });
});

/* -------------------------------------------
   Startup: bind to localhost
-------------------------------------------- */
(async () => {
  try {
    await loginAdmin();
    const server = app.listen(config.PORT, '0.0.0.0', () => {
      console.log(`Proxy server started on http://0.0.0.0:${config.PORT}`);
      console.log(`[Shelving] DB: ${path.resolve(config.SHELVING_DB_PATH)}`);
    });
    server.on('upgrade', (req, socket, head) => {
      if (!req.url || !req.url.startsWith('/api/ws')) {
        socket.destroy();
        return;
      }

      tbWsProxy.upgrade(req, socket, head);
    });
  } catch (e) {
    console.error(e.message || String(e));
    process.exit(1);
  }
})();
