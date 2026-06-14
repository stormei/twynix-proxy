function isPositiveInt(value) {
  return Number.isInteger(value) && value > 0;
}

function validateConfig(config) {
  const errors = [];
  const warnings = [];
  const production = String(config.NODE_ENV || '').toLowerCase() === 'production';

  for (const key of ['THINGSBOARD_URL', 'TB_ADMIN_USERNAME', 'TB_ADMIN_PASSWORD', 'IOTDB_URL', 'IOTDB_AUTH', 'INTERNAL_PROXY_SECRET']) {
    if (!config[key]) errors.push(`Missing required env var: ${key}`);
  }

  for (const key of ['THINGSBOARD_URL', 'IOTDB_URL']) {
    if (!config[key]) continue;
    try {
      const url = new URL(config[key]);
      if (!['http:', 'https:'].includes(url.protocol)) errors.push(`${key} must be http or https`);
    } catch {
      errors.push(`${key} must be a valid URL`);
    }
  }

  if (production && !config.AUDIT_HMAC_SECRET) {
    errors.push('Missing required env var in production: AUDIT_HMAC_SECRET');
  }

  if (production && config.RPC_ACL_ENABLED !== true) {
    errors.push('RPC_ACL_ENABLED cannot be disabled in production');
  }

  if (!Array.isArray(config.RPC_ALLOWED_METHODS) || config.RPC_ALLOWED_METHODS.length === 0) {
    errors.push('RPC_ALLOWED_METHODS must contain at least one method');
  }

  for (const [key, value] of [
    ['PORT', config.PORT],
    ['ACL_TTL_MS', config.ACL_TTL_MS],
    ['MAX_CACHE_ENTRIES', config.MAX_CACHE_ENTRIES],
    ['AXIOS_TIMEOUT_MS', config.AXIOS_TIMEOUT_MS],
    ['PROXY_MAX_BODY_BYTES', config.PROXY_MAX_BODY_BYTES],
    ['RPC_TIMEOUT_MAX_MS', config.RPC_TIMEOUT_MAX_MS],
    ['RPC_RATE_WINDOW_MS', config.RPC_RATE_WINDOW_MS],
    ['RPC_RATE_MAX', config.RPC_RATE_MAX],
    ['RPC_MAX_BODY_BYTES', config.RPC_MAX_BODY_BYTES],
    ['OPLOG_MAX_WINDOW_MS', config.OPLOG_MAX_WINDOW_MS],
    ['IOTDB_SCHEMA_ROW_LIMIT', config.IOTDB_SCHEMA_ROW_LIMIT]
  ]) {
    if (!isPositiveInt(value)) errors.push(`${key} must be a positive integer`);
  }

  if (!Number.isInteger(config.IOTDB_SCHEMA_CACHE_TTL_MS) || config.IOTDB_SCHEMA_CACHE_TTL_MS < 0) {
    errors.push('IOTDB_SCHEMA_CACHE_TTL_MS must be a non-negative integer');
  }

  if (production && !process.env.TB_ADMIN_PASSWORD_FILE) {
    warnings.push('Production should use TB_ADMIN_PASSWORD_FILE instead of TB_ADMIN_PASSWORD');
  }
  if (production && !process.env.INTERNAL_PROXY_SECRET_FILE) {
    warnings.push('Production should use INTERNAL_PROXY_SECRET_FILE instead of INTERNAL_PROXY_SECRET');
  }

  return { errors, warnings };
}

module.exports = {
  validateConfig
};
