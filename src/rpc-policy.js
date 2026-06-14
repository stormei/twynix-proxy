const DEFAULT_MAX_BODY_BYTES = 16 * 1024;
const IDENT_RX = /^[A-Za-z0-9_.:-]{1,128}$/;

function parseCsv(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseMethodParamRules(spec) {
  if (!spec) return {};
  const parsed = typeof spec === 'string' ? JSON.parse(spec) : spec;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('RPC_METHOD_PARAM_RULES must be a JSON object');
  }
  return parsed;
}

function buildRpcPolicy(config) {
  return {
    allowedMethods: new Set(config.RPC_ALLOWED_METHODS || []),
    allowedTags: new Set(parseCsv(config.RPC_ALLOWED_TAGS)),
    maxBodyBytes: Number(config.RPC_MAX_BODY_BYTES || DEFAULT_MAX_BODY_BYTES),
    maxTimeoutMs: Number(config.RPC_TIMEOUT_MAX_MS || 15000),
    methodParamRules: parseMethodParamRules(config.RPC_METHOD_PARAM_RULES || '')
  };
}

function validateScalar(value) {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value);
}

function validateParamRules(params, rules) {
  if (!rules || typeof rules !== 'object') return null;
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    return 'RPC params must be an object';
  }

  const required = Array.isArray(rules.required) ? rules.required : [];
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(params, key)) return `RPC param ${key} is required`;
  }

  const allowedKeys = Array.isArray(rules.allowedKeys) ? new Set(rules.allowedKeys) : null;
  if (allowedKeys) {
    for (const key of Object.keys(params)) {
      if (!allowedKeys.has(key)) return `RPC param ${key} is not allowed`;
    }
  }

  const types = rules.types && typeof rules.types === 'object' ? rules.types : {};
  for (const [key, expected] of Object.entries(types)) {
    if (!Object.prototype.hasOwnProperty.call(params, key)) continue;
    const actual = Array.isArray(params[key]) ? 'array' : typeof params[key];
    if (actual !== expected) return `RPC param ${key} must be ${expected}`;
  }

  const ranges = rules.ranges && typeof rules.ranges === 'object' ? rules.ranges : {};
  for (const [key, range] of Object.entries(ranges)) {
    if (!Object.prototype.hasOwnProperty.call(params, key)) continue;
    const value = Number(params[key]);
    if (!Number.isFinite(value)) return `RPC param ${key} must be numeric`;
    if (range.min !== undefined && value < Number(range.min)) return `RPC param ${key} is below minimum`;
    if (range.max !== undefined && value > Number(range.max)) return `RPC param ${key} is above maximum`;
  }

  return null;
}

function validateRpcBody(body, mode, policy) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'RPC body must be a JSON object';
  }

  const method = typeof body.method === 'string' ? body.method.trim() : '';
  if (!method || !policy.allowedMethods.has(method)) {
    return 'RPC method is not allowed';
  }

  if (!IDENT_RX.test(method)) return 'RPC method contains invalid characters';

  if (mode === 'twoway' && body.timeout !== undefined) {
    const timeout = Number(body.timeout);
    if (!Number.isFinite(timeout) || timeout < 1 || timeout > policy.maxTimeoutMs) {
      return `RPC timeout must be between 1 and ${policy.maxTimeoutMs} ms`;
    }
  }

  const params = body.params === undefined ? {} : body.params;
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    return 'RPC params must be an object';
  }

  for (const [key, value] of Object.entries(params)) {
    if (!IDENT_RX.test(key)) return `RPC param ${key} has invalid name`;
    if (!validateScalar(value)) return `RPC param ${key} must be a scalar value`;
  }

  if (policy.allowedTags.size > 0 && typeof params.tag === 'string' && !policy.allowedTags.has(params.tag)) {
    return 'RPC tag is not allowed';
  }

  const ruleError = validateParamRules(params, policy.methodParamRules[method]);
  if (ruleError) return ruleError;

  const size = Buffer.byteLength(JSON.stringify(body), 'utf8');
  if (size > policy.maxBodyBytes) return 'RPC body is too large';

  return null;
}

module.exports = {
  buildRpcPolicy,
  parseMethodParamRules,
  validateRpcBody
};
