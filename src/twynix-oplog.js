const express = require('express');
const crypto = require('crypto');

const JOURNAL_ASSET_NAME = 'TwynIX Operator Journal';
const JOURNAL_ASSET_TYPE = 'twynix_journal';
const JOURNAL_ASSET_ID_ATTR = 'twynix.journalAssetId';
const JOURNAL_KEY_PREFIX = 'twynix.oplog.';
const JOURNAL_TS_KEY = 'twynix.oplog';
const MAX_PARAMS_BYTES = 4 * 1024;
const MAX_RESULT_DETAIL_CHARS = 512;
const MAX_LIMIT = 1000;
const DEFAULT_READ_WINDOW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

const REDACT_KEYS = new Set(['password', 'token', 'secret', 'authorization', 'auth']);
let warnedMissingAuditSecret = false;

function cloneJsonSafe(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function redactParams(value) {
  if (Array.isArray(value)) return value.map(redactParams);
  if (!value || typeof value !== 'object') return value;

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (REDACT_KEYS.has(String(k).toLowerCase())) {
      out[k] = '[redacted]';
      continue;
    }
    out[k] = redactParams(v);
  }
  return out;
}

function sanitizeEntry(rawEntry) {
  const entry = cloneJsonSafe(rawEntry || {});
  const out = entry && typeof entry === 'object' ? entry : {};

  if (!out.action || typeof out.action !== 'object') out.action = {};
  const redactedParams = redactParams(out.action.params);
  let sanitizedParams = redactedParams;
  try {
    if (Buffer.byteLength(JSON.stringify(redactedParams), 'utf8') > MAX_PARAMS_BYTES) {
      sanitizedParams = { _truncated: true };
    }
  } catch {
    sanitizedParams = { _truncated: true };
  }
  out.action.params = sanitizedParams;

  if (out.result && typeof out.result === 'object' && typeof out.result.detail === 'string') {
    out.result.detail = out.result.detail.slice(0, MAX_RESULT_DETAIL_CHARS);
  }

  const ts = Number(out.ts);
  out.ts = Number.isFinite(ts) ? ts : Date.now();
  return out;
}

function makeRequestId(req) {
  if (typeof req?.twynixRequestId === 'string' && req.twynixRequestId) return req.twynixRequestId;
  const existing = req?.headers?.['x-request-id'];
  if (typeof existing === 'string' && existing.trim()) return existing.trim();
  return crypto.randomUUID();
}

function logOplog(logger, fields) {
  const line = {
    event: 'twynix_oplog',
    ts: new Date().toISOString(),
    ...fields
  };
  if (typeof logger === 'function') logger(line);
  else console.log(JSON.stringify(line));
}

function parseNum(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function parseLimit(value) {
  const n = parseNum(value);
  if (!n || n <= 0) return 100;
  return Math.min(Math.floor(n), MAX_LIMIT);
}

function parseTypeCsv(value) {
  if (!value || typeof value !== 'string') return null;
  const types = value.split(',').map((s) => s.trim()).filter(Boolean);
  return types.length ? new Set(types) : null;
}

function parseReadWindow(query, maxWindowMs) {
  const now = Date.now();
  const requestedTo = parseNum(query?.toTs);
  const requestedFrom = parseNum(query?.fromTs);

  let endTs = requestedTo !== undefined ? requestedTo : now;
  let startTs = requestedFrom !== undefined ? requestedFrom : (endTs - DEFAULT_READ_WINDOW_MS);

  if (startTs > endTs) {
    startTs = endTs;
  }

  const maxWindow = Number.isFinite(maxWindowMs) && maxWindowMs > 0 ? maxWindowMs : DEFAULT_MAX_WINDOW_MS;
  if (endTs - startTs > maxWindow) {
    startTs = endTs - maxWindow;
  }

  startTs = Math.max(0, Math.floor(startTs));
  endTs = Math.max(startTs, Math.floor(endTs));

  return { startTs, endTs };
}

function extractAssetId(tbAssetLike) {
  if (!tbAssetLike || typeof tbAssetLike !== 'object') return null;
  if (typeof tbAssetLike.id === 'string') return tbAssetLike.id;
  if (tbAssetLike.id && typeof tbAssetLike.id.id === 'string') return tbAssetLike.id.id;
  return null;
}

async function tbGet(deps, url) {
  const token = await deps.getAdminToken();
  return deps.ax.get(url, {
    headers: {
      'X-Authorization': `Bearer ${token}`,
      'x-twynix-internal-admin': deps.config.INTERNAL_PROXY_SECRET
    },
    __tbAdmin: true
  });
}

async function tbPost(deps, url, body) {
  const token = await deps.getAdminToken();
  return deps.ax.post(url, body, {
    headers: {
      'X-Authorization': `Bearer ${token}`,
      'x-twynix-internal-admin': deps.config.INTERNAL_PROXY_SECRET
    },
    __tbAdmin: true
  });
}

function formatHttpError(e) {
  if (!e || typeof e !== 'object') return String(e);
  const status = e.response && e.response.status ? e.response.status : '';
  const data = e.response && e.response.data !== undefined ? e.response.data : '';
  const detail = typeof data === 'string' ? data : JSON.stringify(data || {});
  return status ? `HTTP ${status} ${detail}` : (e.message || String(e));
}

function normalizeAssetId(value) {
  if (!value) return null;
  if (typeof value === 'string') {
    const v = value.trim();
    const m = v.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
    return m ? m[0] : null;
  }
  if (typeof value === 'object') {
    if (typeof value.id === 'string') return normalizeAssetId(value.id);
    if (value.id && typeof value.id.id === 'string') return normalizeAssetId(value.id.id);
    if (typeof value.value === 'string') return normalizeAssetId(value.value);
  }
  return null;
}

async function readTenantJournalAssetId(deps, tenantId) {
  const url = `${deps.config.THINGSBOARD_URL}/api/plugins/telemetry/TENANT/${tenantId}/values/attributes/SERVER_SCOPE?keys=${encodeURIComponent(JOURNAL_ASSET_ID_ATTR)}`;
  try {
    const resp = await tbGet(deps, url);
    const attrs = Array.isArray(resp.data) ? resp.data : [];
    const hit = attrs.find((a) => a && a.key === JOURNAL_ASSET_ID_ATTR);
    if (!hit || hit.value === undefined || hit.value === null) return null;
    return normalizeAssetId(hit.value);
  } catch (e) {
    if (e && e.response && (e.response.status === 404 || e.response.status === 403)) return null;
    throw e;
  }
}

async function persistTenantJournalAssetId(deps, tenantId, assetId) {
  const url = `${deps.config.THINGSBOARD_URL}/api/plugins/telemetry/TENANT/${tenantId}/SERVER_SCOPE`;
  try {
    await tbPost(deps, url, { [JOURNAL_ASSET_ID_ATTR]: assetId });
  } catch (e) {
    if (!(e && e.response && (e.response.status === 404 || e.response.status === 403))) throw e;
  }
}

async function findJournalAsset(deps, tenantId) {
  const listBaseCandidates = [
    `${deps.config.THINGSBOARD_URL}/api/tenant/${tenantId}/assets`,
    `${deps.config.THINGSBOARD_URL}/api/tenant/assets`
  ];

  for (const base of listBaseCandidates) {
    let baseUsable = false;
    let page = 0;
    while (true) {
      const qs = new URLSearchParams({
        pageSize: '100',
        page: String(page),
        type: JOURNAL_ASSET_TYPE,
        textSearch: JOURNAL_ASSET_NAME
      });
      const url = `${base}?${qs.toString()}`;
      let resp;
      try {
        resp = await tbGet(deps, url);
        baseUsable = true;
      } catch (e) {
        if (e && e.response && (e.response.status === 404 || e.response.status === 403)) break;
        throw e;
      }
      const data = resp.data && Array.isArray(resp.data.data) ? resp.data.data : [];
      const hit = data.find((a) => a && a.type === JOURNAL_ASSET_TYPE && a.name === JOURNAL_ASSET_NAME);
      if (hit) return extractAssetId(hit);
      if (!resp.data || resp.data.hasNext !== true) break;
      page += 1;
    }
    if (baseUsable) return null;
  }

  return null;
}

async function createJournalAsset(deps, tenantId) {
  const url = `${deps.config.THINGSBOARD_URL}/api/asset`;
  const body = {
    name: JOURNAL_ASSET_NAME,
    type: JOURNAL_ASSET_TYPE,
    tenantId: { entityType: 'TENANT', id: tenantId }
  };
  const resp = await tbPost(deps, url, body);
  const assetId = extractAssetId(resp.data);
  if (!assetId) throw new Error('Failed to create journal asset');
  return assetId;
}

async function resolveJournalAssetId(deps, tenantId) {
  const fromAttr = await readTenantJournalAssetId(deps, tenantId);
  if (fromAttr) {
    try {
      const url = `${deps.config.THINGSBOARD_URL}/api/asset/${fromAttr}`;
      await tbGet(deps, url);
      return fromAttr;
    } catch (e) {
      if (!(e && e.response && (e.response.status === 404 || e.response.status === 403))) throw e;
    }
  }

  const existing = await findJournalAsset(deps, tenantId);
  const assetId = existing || await createJournalAsset(deps, tenantId);
  await persistTenantJournalAssetId(deps, tenantId, assetId);
  return assetId;
}

function applyReadFilters(entry, query) {
  const fromTs = parseNum(query.fromTs);
  const toTs = parseNum(query.toTs);
  const targetType = typeof query.targetType === 'string' ? query.targetType : undefined;
  const targetId = typeof query.targetId === 'string' ? query.targetId : undefined;
  const userId = typeof query.userId === 'string' ? query.userId : undefined;
  const types = parseTypeCsv(query.typeCsv);

  const entryTargetType = extractEntryTargetType(entry);
  const entryTargetId = extractEntryTargetId(entry);
  const entryUserId = extractEntryUserId(entry);

  if (fromTs !== undefined && Number(entry.ts) < fromTs) return false;
  if (toTs !== undefined && Number(entry.ts) > toTs) return false;
  if (targetType !== undefined && String(entryTargetType) !== targetType) return false;
  if (targetId !== undefined && String(entryTargetId) !== targetId) return false;
  if (userId !== undefined && String(entryUserId) !== userId) return false;
  if (types && !types.has(String(entry.type || ''))) return false;
  return true;
}

function toSafeString(value) {
  if (value === undefined || value === null) return '';
  return String(value);
}

function extractEntryUserId(entry) {
  if (entry?.user && typeof entry.user === 'object' && entry.user !== null && entry.user.id !== undefined) {
    return toSafeString(entry.user.id);
  }
  return toSafeString(entry?.userId);
}

function extractEntryTargetType(entry) {
  if (entry?.target && typeof entry.target === 'object' && entry.target !== null && entry.target.entityType !== undefined) {
    return toSafeString(entry.target.entityType);
  }
  return toSafeString(entry?.targetType);
}

function extractEntryTargetId(entry) {
  if (entry?.target && typeof entry.target === 'object' && entry.target !== null && entry.target.id !== undefined) {
    return toSafeString(entry.target.id);
  }
  return toSafeString(entry?.targetId);
}

function deriveOutcome(entry) {
  const state = entry?.result?.state;
  return typeof state === 'string' ? state : '';
}

function base64urlEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function sha256Base64url(text) {
  return base64urlEncode(crypto.createHash('sha256').update(String(text || ''), 'utf8').digest());
}

function buildSignatureBase(entryWithoutSig) {
  const ts = toSafeString(Number(entryWithoutSig?.ts) || 0);
  const type = toSafeString(entryWithoutSig?.type);
  const userId = extractEntryUserId(entryWithoutSig);
  const targetType = extractEntryTargetType(entryWithoutSig);
  const targetId = extractEntryTargetId(entryWithoutSig);
  const corr = toSafeString(entryWithoutSig?.corr);
  const outcome = deriveOutcome(entryWithoutSig);

  const payload = { ...entryWithoutSig };
  delete payload.sig;
  delete payload.sigAlg;
  const payloadHash = sha256Base64url(JSON.stringify(payload));

  return `${ts}|${type}|${userId}|${targetType}|${targetId}|${corr}|${outcome}|${payloadHash}`;
}

function signEntry(entry, secret) {
  if (!secret) return entry;
  const canonical = buildSignatureBase(entry);
  const sig = base64urlEncode(crypto.createHmac('sha256', secret).update(canonical, 'utf8').digest());
  return {
    ...entry,
    sigAlg: 'hmac-sha256',
    sig
  };
}

function getAuditSecret(config, logger) {
  const secret = typeof config?.AUDIT_HMAC_SECRET === 'string' ? config.AUDIT_HMAC_SECRET : '';
  if (secret) return secret;
  if (!warnedMissingAuditSecret) {
    warnedMissingAuditSecret = true;
    const env = String(process.env.NODE_ENV || '').toLowerCase();
    const msg = env === 'production'
      ? 'AUDIT_HMAC_SECRET missing in production; oplog signatures disabled'
      : 'AUDIT_HMAC_SECRET missing; oplog signatures disabled';
    if (typeof logger === 'function') logger({ event: 'twynix_oplog_warn', message: msg });
    else console.warn(msg);
  }
  return '';
}

function buildCanonicalEntry(rawEntry, defaults = {}) {
  const out = sanitizeEntry(rawEntry || {});

  out.v = 2;
  out.type = toSafeString(out.type);

  const existingUserId = extractEntryUserId(out);
  out.userId = existingUserId || toSafeString(defaults.userId);

  const existingTargetType = extractEntryTargetType(out);
  const existingTargetId = extractEntryTargetId(out);
  out.targetType = existingTargetType || toSafeString(defaults.targetType);
  out.targetId = existingTargetId || toSafeString(defaults.targetId);

  const corr = toSafeString(out.corr || defaults.corr);
  out.corr = corr;

  if (!out.result || typeof out.result !== 'object') out.result = {};
  if (!out.action || typeof out.action !== 'object') out.action = {};

  if (defaults.method && !out.action.method) out.action.method = toSafeString(defaults.method);
  if (defaults.path && !out.action.path) out.action.path = toSafeString(defaults.path);

  if (defaults.outcome && typeof out.result.state !== 'string') out.result.state = toSafeString(defaults.outcome);
  if (defaults.reason && typeof out.result.detail !== 'string') out.result.detail = toSafeString(defaults.reason).slice(0, MAX_RESULT_DETAIL_CHARS);

  return out;
}

function buildTelemetryValues(entry) {
  return {
    [JOURNAL_TS_KEY]: JSON.stringify(entry),
    [`${JOURNAL_KEY_PREFIX}type`]: toSafeString(entry.type),
    [`${JOURNAL_KEY_PREFIX}userId`]: extractEntryUserId(entry),
    [`${JOURNAL_KEY_PREFIX}targetType`]: extractEntryTargetType(entry),
    [`${JOURNAL_KEY_PREFIX}targetId`]: extractEntryTargetId(entry),
    [`${JOURNAL_KEY_PREFIX}outcome`]: deriveOutcome(entry),
    [`${JOURNAL_KEY_PREFIX}corr`]: toSafeString(entry.corr)
  };
}

async function writeTenantJournalEntry(deps, tenantId, rawEntry, defaults = {}) {
  const entry = buildCanonicalEntry(rawEntry, defaults);
  const secret = getAuditSecret(deps.config, deps.logger);
  const signedEntry = signEntry(entry, secret);

  const assetId = await resolveJournalAssetId(deps, tenantId);
  const url = `${deps.config.THINGSBOARD_URL}/api/plugins/telemetry/ASSET/${assetId}/timeseries/ANY`;
  await tbPost(deps, url, {
    ts: signedEntry.ts,
    values: buildTelemetryValues(signedEntry)
  });

  return { assetId, entry: signedEntry };
}

function createTwynixOplogHandlers(deps) {
  async function writeHandler(req, res) {
    const requestId = makeRequestId(req);
    const auth = await deps.requireValidUser(req, res);
    if (!auth) return;
    if (!auth.tenantId || auth.tenantId === 'unknown') {
      logOplog(deps.logger, {
        requestId,
        tenantId: '',
        userId: auth.userId,
        outcome: 'denied',
        reason: 'missing_tenant'
      });
      return res.status(403).json({ error: 'Forbidden: tenant missing from token' });
    }

    const tenantFromBody = req.body && typeof req.body.tenantId === 'string' ? req.body.tenantId.trim() : '';
    if (tenantFromBody && tenantFromBody !== auth.tenantId) {
      logOplog(deps.logger, {
        requestId,
        tenantId: auth.tenantId,
        userId: auth.userId,
        outcome: 'denied',
        reason: 'tenant_mismatch'
      });
      return res.status(403).json({ error: 'Forbidden: tenant mismatch' });
    }

    try {
      const { assetId, entry } = await writeTenantJournalEntry(
        deps,
        auth.tenantId,
        req.body ? req.body.entry : null,
        {
          userId: auth.userId,
          corr: requestId
        }
      );

      logOplog(deps.logger, {
        requestId,
        tenantId: auth.tenantId,
        userId: auth.userId,
        assetId,
        telemetryKey: JOURNAL_TS_KEY,
        outcome: 'allowed'
      });
      return res.json({ ok: true, assetId, telemetryKey: JOURNAL_TS_KEY, ts: entry.ts });
    } catch (e) {
      logOplog(deps.logger, {
        requestId,
        tenantId: auth.tenantId,
        userId: auth.userId,
        outcome: 'error',
        reason: formatHttpError(e)
      });
      return res.status(500).json({ error: 'Failed to write oplog entry', detail: formatHttpError(e) });
    }
  }

  async function readHandler(req, res) {
    const requestId = makeRequestId(req);
    const auth = await deps.requireValidUser(req, res);
    if (!auth) return;
    if (!auth.tenantId || auth.tenantId === 'unknown') {
      logOplog(deps.logger, {
        requestId,
        tenantId: '',
        userId: auth.userId,
        outcome: 'denied',
        reason: 'missing_tenant'
      });
      return res.status(403).json({ error: 'Forbidden: tenant missing from token' });
    }

    try {
      const assetId = await resolveJournalAssetId(deps, auth.tenantId);
      const limit = parseLimit(req.query ? req.query.limit : undefined);
      const maxWindowMs = parseNum(deps.config?.OPLOG_MAX_WINDOW_MS) || DEFAULT_MAX_WINDOW_MS;
      const { startTs, endTs } = parseReadWindow(req.query || {}, maxWindowMs);
      const qs = new URLSearchParams({
        keys: JOURNAL_TS_KEY,
        startTs: String(startTs),
        endTs: String(endTs),
        limit: String(limit),
        agg: 'NONE',
        orderBy: 'DESC'
      });
      const url = `${deps.config.THINGSBOARD_URL}/api/plugins/telemetry/ASSET/${assetId}/values/timeseries?${qs.toString()}`;
      const resp = await tbGet(deps, url);
      const rows = resp?.data && Array.isArray(resp.data[JOURNAL_TS_KEY]) ? resp.data[JOURNAL_TS_KEY] : [];

      const entries = [];
      const boundedQuery = { ...(req.query || {}), fromTs: String(startTs), toTs: String(endTs) };
      for (const kv of rows) {
        if (!kv) continue;
        try {
          const parsed = typeof kv.value === 'string' ? JSON.parse(kv.value) : kv.value;
          if (!parsed || typeof parsed !== 'object') continue;
          const ts = Number(parsed.ts);
          const rowTs = Number(kv.ts);
          parsed.ts = Number.isFinite(ts) ? ts : (Number.isFinite(rowTs) ? rowTs : 0);
          if (!applyReadFilters(parsed, boundedQuery)) continue;
          entries.push(parsed);
        } catch {
          continue;
        }
      }

      entries.sort((a, b) => Number(b.ts) - Number(a.ts));
      const data = entries.slice(0, limit);

      logOplog(deps.logger, {
        requestId,
        tenantId: auth.tenantId,
        userId: auth.userId,
        assetId,
        outcome: 'allowed',
        count: data.length
      });

      return res.json({ data });
    } catch (e) {
      logOplog(deps.logger, {
        requestId,
        tenantId: auth.tenantId,
        userId: auth.userId,
        outcome: 'error',
        reason: formatHttpError(e)
      });
      return res.status(500).json({ error: 'Failed to read oplog entries', detail: formatHttpError(e) });
    }
  }

  return { writeHandler, readHandler };
}

function createOplogEmitter(deps) {
  return async function emitOplogEvent(event) {
    const tenantId = typeof event?.tenantId === 'string' ? event.tenantId.trim() : '';
    if (!tenantId || tenantId === 'unknown') return { ok: false, skipped: true, reason: 'missing_tenant' };

    const baseEntry = event?.entry && typeof event.entry === 'object'
      ? event.entry
      : {
          type: event?.type,
          userId: event?.userId,
          targetType: event?.targetType || event?.entityType,
          targetId: event?.targetId || event?.entityId,
          corr: event?.corr,
          action: {
            method: event?.method,
            path: event?.path,
            params: event?.params
          },
          result: {
            state: event?.outcome,
            detail: event?.reason
          }
        };

    try {
      const { assetId, entry } = await writeTenantJournalEntry(deps, tenantId, baseEntry, {
        userId: event?.userId,
        targetType: event?.targetType || event?.entityType,
        targetId: event?.targetId || event?.entityId,
        corr: event?.corr,
        method: event?.method,
        path: event?.path,
        outcome: event?.outcome,
        reason: event?.reason
      });
      return { ok: true, assetId, ts: entry.ts };
    } catch (e) {
      logOplog(deps.logger, {
        requestId: toSafeString(event?.corr),
        tenantId,
        userId: toSafeString(event?.userId),
        outcome: 'error',
        reason: formatHttpError(e)
      });
      return { ok: false, error: formatHttpError(e) };
    }
  };
}

function createTwynixOplogRouter(deps) {
  const router = express.Router();
  const handlers = createTwynixOplogHandlers(deps);

  router.post('/twynix/oplog/write', express.json({ limit: '128kb' }), handlers.writeHandler);
  router.get('/twynix/oplog', handlers.readHandler);

  return router;
}

module.exports = {
  JOURNAL_ASSET_NAME,
  JOURNAL_ASSET_TYPE,
  JOURNAL_ASSET_ID_ATTR,
  JOURNAL_KEY_PREFIX,
  JOURNAL_TS_KEY,
  sanitizeEntry,
  createTwynixOplogHandlers,
  createTwynixOplogRouter,
  createOplogEmitter
};
