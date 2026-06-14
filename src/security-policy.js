const UUID_RX = '[0-9a-fA-F-]{36}';

const DEFAULT_PROXY_RULES = [
  { methods: ['POST'], rx: /^\/api\/auth\/login\/?$/i, public: true },
  { methods: ['GET', 'HEAD'], rx: /^\/api\/auth\/user\/?$/i },

  { methods: ['GET', 'HEAD'], rx: new RegExp(`^/api/(device|asset|alarm)/${UUID_RX}/?$`, 'i') },
  { methods: ['GET', 'HEAD'], rx: /^\/api\/tenant\/(devices|deviceInfos|assets|assetInfos|alarms|dashboards|dashboardInfos)\/?$/i },
  { methods: ['GET', 'HEAD'], rx: new RegExp(`^/api/customer/${UUID_RX}/(devices|deviceInfos|assets|assetInfos|alarms|dashboards|dashboardInfos)/?$`, 'i') },
  { methods: ['GET', 'HEAD'], rx: /^\/api\/(device|asset)\/types\/?$/i },
  { methods: ['GET', 'HEAD'], rx: /^\/api\/deviceProfileInfos\/?$/i },
  { methods: ['GET', 'HEAD'], rx: new RegExp(`^/api/deviceProfile/${UUID_RX}/?$`, 'i') },
  { methods: ['GET', 'HEAD'], rx: /^\/api\/relations\/info\/?$/i },
  { methods: ['GET', 'HEAD'], rx: /^\/api\/relations\/?$/i },
  { methods: ['GET', 'HEAD'], rx: /^\/api\/entities\/?$/i },

  {
    methods: ['GET', 'HEAD'],
    rx: new RegExp(`^/api/plugins/telemetry/(ASSET|DEVICE)/${UUID_RX}/values/attributes/(CLIENT_SCOPE|SHARED_SCOPE)/?$`, 'i')
  },
  {
    methods: ['GET', 'HEAD'],
    rx: new RegExp(`^/api/plugins/telemetry/(ASSET|DEVICE)/${UUID_RX}/values/timeseries/?$`, 'i')
  },

  { methods: ['POST', 'PUT'], rx: new RegExp(`^/api/plugins/telemetry/(ASSET|DEVICE)/${UUID_RX}/SHARED_SCOPE/?$`, 'i') },
  { methods: ['POST', 'PUT'], rx: new RegExp(`^/api/plugins/telemetry/(ASSET|DEVICE)/${UUID_RX}/SERVER_SCOPE/?$`, 'i') },
  { methods: ['POST'], rx: new RegExp(`^/api/plugins/rpc/(oneway|twoway)/${UUID_RX}/?$`, 'i') },

  { methods: ['POST'], rx: /^\/api\/asset\/?$/i },
  { methods: ['PUT', 'DELETE'], rx: new RegExp(`^/api/asset/${UUID_RX}/?$`, 'i') },
  { methods: ['POST'], rx: /^\/api\/relation\/?$/i },
  { methods: ['POST'], rx: /^\/api\/relations\/?$/i },
  { methods: ['DELETE'], rx: /^\/api\/relation\/?$/i },
  { methods: ['POST'], rx: /^\/api\/relation\/delete\/?$/i }
];

const LOCAL_PATH_PREFIXES = [
  '/telemetry',
  '/query',
  '/health',
  '/api/access/check',
  '/twynix/status',
  '/twynix/metrics',
  '/twynix/oplog',
  '/twynix/alarms/',
  '/api/opcua',
  '/opcua',
  '/api/twynix/opcua'
];

const STRIPPED_INBOUND_HEADERS = [
  'x-twynix-internal-admin',
  'x-forwarded-user',
  'x-forwarded-email',
  'x-forwarded-roles',
  'x-real-user',
  'x-user-id',
  'x-tenant-id'
];

const WRITE_SQL = /\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|GRANT|REVOKE|TRUNCATE|LOAD|MERGE|CALL)\b/i;

function normalizePath(pathname) {
  const path = typeof pathname === 'string' && pathname ? pathname : '/';
  return path.split('?')[0] || '/';
}

function getBearerTokenFromHeaders(headers = {}) {
  const raw = headers['x-authorization'] || headers.authorization;
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  return trimmed.toLowerCase().startsWith('bearer ') ? trimmed.slice(7).trim() : null;
}

function scrubInboundHeaders(headers = {}) {
  for (const name of STRIPPED_INBOUND_HEADERS) {
    delete headers[name];
  }
}

function isLocalRoute(pathname) {
  const path = normalizePath(pathname);
  return LOCAL_PATH_PREFIXES.some((prefix) => path === prefix || path.startsWith(prefix));
}

function parseExtraProxyRules(spec) {
  if (!spec) return [];
  const parsed = typeof spec === 'string' ? JSON.parse(spec) : spec;
  if (!Array.isArray(parsed)) throw new Error('EXTRA_PROXY_ALLOW_RULES must be a JSON array');

  return parsed.map((rule, idx) => {
    if (!rule || typeof rule !== 'object') throw new Error(`Invalid proxy rule at index ${idx}`);
    const methods = Array.isArray(rule.methods) ? rule.methods.map((m) => String(m).toUpperCase()) : [];
    if (methods.length === 0) throw new Error(`Proxy rule ${idx} has no methods`);
    if (typeof rule.pathRegex !== 'string' || !rule.pathRegex) {
      throw new Error(`Proxy rule ${idx} needs pathRegex`);
    }
    return {
      methods,
      rx: new RegExp(rule.pathRegex, rule.flags || 'i'),
      public: rule.public === true
    };
  });
}

function createProxyRoutePolicy(extraRulesSpec) {
  const rules = DEFAULT_PROXY_RULES.concat(parseExtraProxyRules(extraRulesSpec));

  return function proxyRoutePolicy(method, pathname) {
    const normalizedMethod = String(method || '').toUpperCase();
    const path = normalizePath(pathname);

    // Let ThingsBoard enforce permissions for ordinary read APIs. The proxy still
    // validates that the caller has a real user token before forwarding.
    if (normalizedMethod === 'GET' || normalizedMethod === 'HEAD') {
      return { allowed: true, public: false };
    }

    const match = rules.find((rule) => rule.methods.includes(normalizedMethod) && rule.rx.test(path));
    if (!match) return { allowed: false, public: false };
    return { allowed: true, public: match.public === true };
  };
}

function isReadOnlyIotdbQuery(body) {
  const query = body && typeof body === 'object'
    ? String(body.sql || body.query || body.statement || '').trim()
    : '';
  if (!query) return false;
  if (query.length > 10_000) return false;
  if (query.includes(';')) return false;
  if (WRITE_SQL.test(query)) return false;
  return /^(SELECT|SHOW|COUNT)\b/i.test(query);
}

function clampText(value, maxChars) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  if (!text) return null;
  return text.slice(0, maxChars);
}

module.exports = {
  DEFAULT_PROXY_RULES,
  STRIPPED_INBOUND_HEADERS,
  clampText,
  createProxyRoutePolicy,
  getBearerTokenFromHeaders,
  isLocalRoute,
  isReadOnlyIotdbQuery,
  normalizePath,
  scrubInboundHeaders
};
