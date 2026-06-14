const SAFE_PATH_PART_RX = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RESERVED_SQL_WORDS = new Set([
  'ALTER',
  'AND',
  'BY',
  'CALL',
  'CREATE',
  'DELETE',
  'DROP',
  'FROM',
  'GRANT',
  'GROUP',
  'INSERT',
  'INTO',
  'LOAD',
  'MERGE',
  'OR',
  'ORDER',
  'REVOKE',
  'SELECT',
  'TRUNCATE',
  'UPDATE',
  'WHERE'
]);
const MODE_VALUES = new Set(['raw', 'aggregated', 'auto']);
const AGGREGATION_VALUES = new Set(['avg', 'min', 'max', 'minmax', 'last', 'range']);
const DEFAULT_MAX_POINTS = 2000;
const MAX_POINTS_UPPER_BOUND = 10000;
const DEFAULT_ESTIMATED_SAMPLE_MS = 1000;
const DEBUG_MAX_CHARS = 4000;

function createTrendError(error, message, status = 400, details) {
  const err = new Error(message);
  err.trendError = { error, message, status, details };
  return err;
}

function validateIotdbPath(path) {
  if (typeof path !== 'string' || path.length > 512) {
    throw createTrendError('INVALID_PATH', 'Invalid IoTDB path');
  }
  if (/[;"'`\\]|--|\/\*|\*\//.test(path)) {
    throw createTrendError('INVALID_PATH', 'Invalid IoTDB path');
  }
  const parts = path.split('.');
  if (parts.length < 3 || parts[0] !== 'root') {
    throw createTrendError('INVALID_PATH', 'Invalid IoTDB path');
  }
  for (const part of parts) {
    if (!SAFE_PATH_PART_RX.test(part) || RESERVED_SQL_WORDS.has(part.toUpperCase())) {
      throw createTrendError('INVALID_PATH', 'Invalid IoTDB path');
    }
  }
  return {
    fullPath: path,
    devicePath: parts.slice(0, -1).join('.'),
    measurement: parts[parts.length - 1]
  };
}

function normalizeMaxPoints(value) {
  if (value === undefined || value === null) return DEFAULT_MAX_POINTS;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) {
    throw createTrendError('INVALID_MAX_POINTS', 'maxPoints must be a positive integer');
  }
  return Math.min(n, MAX_POINTS_UPPER_BOUND);
}

function validateTimeRange(body, maxWindowMs) {
  const startTs = Number(body?.startTs);
  const endTs = Number(body?.endTs);
  if (!Number.isInteger(startTs) || !Number.isInteger(endTs)) {
    throw createTrendError('INVALID_TIME_RANGE', 'startTs and endTs are required millisecond timestamps');
  }
  if (startTs < 0 || endTs < 0 || startTs >= endTs) {
    throw createTrendError('INVALID_TIME_RANGE', 'startTs must be less than endTs');
  }
  if (Number.isInteger(maxWindowMs) && maxWindowMs > 0 && endTs - startTs > maxWindowMs) {
    throw createTrendError('TIME_RANGE_TOO_LARGE', 'Requested time range exceeds maximum query window');
  }
  return { startTs, endTs };
}

function sanitizeText(value, maxChars) {
  if (value === undefined || value === null) return undefined;
  return String(value).slice(0, maxChars);
}

function validateSeries(series) {
  if (!Array.isArray(series) || series.length < 1) {
    throw createTrendError('INVALID_SERIES', 'series must contain at least one item');
  }
  if (series.length > 20) {
    throw createTrendError('INVALID_SERIES', 'series contains too many items');
  }
  return series.map((item, index) => {
    const parsed = validateIotdbPath(item?.path);
    const id = item?.id === undefined || item?.id === null ? parsed.fullPath : String(item.id);
    if (!id || id.length > 120) {
      throw createTrendError('INVALID_SERIES', 'series id is required');
    }
    return {
      id,
      path: parsed.fullPath,
      devicePath: parsed.devicePath,
      measurement: parsed.measurement,
      label: sanitizeText(item?.label, 160),
      unit: sanitizeText(item?.unit, 40),
      color: sanitizeText(item?.color, 40),
      index
    };
  });
}

function normalizeRequest(body, options = {}) {
  const { startTs, endTs } = validateTimeRange(body, options.maxWindowMs);
  const maxPoints = normalizeMaxPoints(body?.maxPoints);
  const mode = body?.mode === undefined || body?.mode === null ? 'auto' : String(body.mode).toLowerCase();
  if (!MODE_VALUES.has(mode)) {
    throw createTrendError('INVALID_MODE', 'Unsupported trend query mode');
  }
  const aggregation = body?.aggregation === undefined || body?.aggregation === null
    ? 'minmax'
    : String(body.aggregation).toLowerCase();
  if (!AGGREGATION_VALUES.has(aggregation)) {
    throw createTrendError('INVALID_AGGREGATION', 'Unsupported trend aggregation');
  }
  return {
    series: validateSeries(body?.series),
    startTs,
    endTs,
    mode,
    maxPoints,
    aggregation
  };
}

function chooseIntervalMs(startTs, endTs, maxPoints) {
  return Math.max(1, Math.ceil((endTs - startTs) / Math.max(1, maxPoints)));
}

function chooseDataMode(request, options = {}) {
  if (request.mode === 'raw') return { dataMode: 'RAW', intervalMs: null };
  const estimatedSampleMs = Number(options.estimatedSampleMs || DEFAULT_ESTIMATED_SAMPLE_MS);
  const estimatedRawPoints = Math.ceil((request.endTs - request.startTs) / Math.max(1, estimatedSampleMs));
  if (request.mode === 'aggregated' || estimatedRawPoints > request.maxPoints) {
    return {
      dataMode: request.mode === 'auto' ? 'DOWNSAMPLED' : 'AGGREGATED',
      intervalMs: chooseIntervalMs(request.startTs, request.endTs, request.maxPoints)
    };
  }
  return { dataMode: 'RAW', intervalMs: null };
}

function aggregationExpressions(measurement, aggregation) {
  switch (aggregation) {
    case 'avg':
      return [`avg(${measurement})`];
    case 'min':
      return [`min_value(${measurement})`];
    case 'max':
      return [`max_value(${measurement})`];
    case 'last':
      return [`last_value(${measurement})`];
    case 'range':
    case 'minmax':
    default:
      return [`min_value(${measurement})`, `max_value(${measurement})`, `avg(${measurement})`];
  }
}

function formatIotdbTimeLiteral(ts) {
  return new Date(ts).toISOString().replace('Z', '+00:00');
}

function buildSeriesSql(series, request, selected) {
  return buildGroupSql([series], request, selected);
}

function buildGroupSql(seriesGroup, request, selected) {
  const start = formatIotdbTimeLiteral(request.startTs);
  const end = formatIotdbTimeLiteral(request.endTs);
  const devicePath = seriesGroup[0].devicePath;
  if (selected.dataMode === 'RAW') {
    const measurements = seriesGroup.map((series) => series.measurement).join(', ');
    return `SELECT ${measurements} FROM ${devicePath} WHERE time >= ${start} AND time < ${end} LIMIT ${request.maxPoints + 1}`;
  }
  const expr = seriesGroup
    .flatMap((series) => aggregationExpressions(series.measurement, request.aggregation))
    .join(', ');
  return `SELECT ${expr} FROM ${devicePath} GROUP BY ([${start}, ${end}), ${selected.intervalMs}ms)`;
}

function buildLatestSeriesSql(series) {
  return `SELECT ${series.measurement} FROM ${series.devicePath} ORDER BY time DESC LIMIT 5`;
}

function buildShowTimeseriesSql(series) {
  return `SHOW TIMESERIES ${series.path}`;
}

function buildShowDeviceTimeseriesSql(series) {
  return `SHOW TIMESERIES ${series.devicePath}.**`;
}

function asNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function qualityFor(value) {
  return asNumber(value) === null ? 'BAD' : 'GOOD';
}

function truncateForDebug(value, maxChars = DEBUG_MAX_CHARS) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (!text) return text;
  return text.length > maxChars ? `${text.slice(0, maxChars)}... [truncated ${text.length - maxChars} chars]` : text;
}

function summarizeIotdbData(data) {
  if (!data || typeof data !== 'object') return { type: typeof data };
  return {
    keys: Object.keys(data),
    code: data.code,
    message: data.message,
    timestamps: Array.isArray(data.timestamps) ? data.timestamps.length : undefined,
    valuesColumns: Array.isArray(data.values) ? data.values.length : undefined,
    valueRowsOrSamples: Array.isArray(data.values?.[0]) ? data.values[0].length : undefined,
    columns: Array.isArray(data.columns) ? data.columns : undefined,
    column_names: Array.isArray(data.column_names) ? data.column_names : undefined,
    expressions: Array.isArray(data.expressions) ? data.expressions : undefined,
    dataKeys: data.data && typeof data.data === 'object' ? Object.keys(data.data) : undefined
  };
}

function debugTrend(deps, event, payload) {
  if (!deps.config?.IOTDB_TREND_DEBUG) return;
  const logger = deps.logger || console.log;
  logger(JSON.stringify({
    event: 'iotdb_trend_debug',
    stage: event,
    ...payload
  }));
}

function queryPayloadFields(config = {}) {
  const preferred = String(config.IOTDB_REST_QUERY_FIELD || 'sql').trim();
  const useFallbacks = String(config.IOTDB_REST_QUERY_FIELD_FALLBACKS || 'false').toLowerCase() === 'true';
  const fields = useFallbacks
    ? [preferred, 'sql', 'query', 'statement']
    : [preferred];
  return [...new Set(fields)];
}

function queryRowLimit(request, selected) {
  if (!request || !selected) return undefined;
  return request.maxPoints + 1;
}

async function postIotdbQuery(deps, sql, payloadField, options = {}) {
  const payload = { [payloadField]: sql };
  if (Number.isInteger(options.rowLimit) && options.rowLimit > 0) {
    payload.row_limit = options.rowLimit;
  }
  const request = () => deps.ax.post(`${deps.config.IOTDB_URL}/rest/v2/query`, payload, {
      headers: {
        Authorization: `Basic ${deps.config.IOTDB_AUTH}`,
        'Content-Type': 'application/json'
      }
    });

  try {
    return await request();
  } catch (e) {
    const message = e.message || '';
    const code = e.code || '';
    if (code === 'ECONNRESET' || /socket hang up/i.test(message)) {
      return request();
    }
    throw e;
  }
}

function iotdbBodyError(data) {
  return data && typeof data.code === 'number' && data.code >= 300
    ? new Error(data.message || `IoTDB returned code ${data.code}`)
    : null;
}

async function runDebugIotdbQuery(deps, item, stage, sql) {
  if (!deps.config?.IOTDB_TREND_DEBUG) return;
  for (const payloadField of queryPayloadFields(deps.config)) {
    try {
      const resp = await postIotdbQuery(deps, sql, payloadField);
      const bodyError = iotdbBodyError(resp.data);
      debugTrend(deps, stage, {
        id: item.id,
        path: item.path,
        sql,
        payloadField,
        status: resp.status,
        summary: summarizeIotdbData(resp.data),
        body: truncateForDebug(resp.data),
        ...(bodyError ? { bodyError: bodyError.message } : {})
      });
    } catch (e) {
      debugTrend(deps, `${stage}_error`, {
        id: item.id,
        path: item.path,
        sql,
        payloadField,
        message: e.message || String(e)
      });
    }
  }
}

async function queryAndNormalizeSeries(deps, item, request, selected, sql) {
  let lastError = null;
  let lastResult = null;

  for (const payloadField of queryPayloadFields(deps.config)) {
    debugTrend(deps, 'request', {
      id: item.id,
      path: item.path,
      dataMode: selected.dataMode,
      aggregation: request.aggregation,
      intervalMs: selected.intervalMs,
      payloadField,
      sql
    });

    try {
      const resp = await postIotdbQuery(deps, sql, payloadField, { rowLimit: queryRowLimit(request, selected) });
      debugTrend(deps, 'response', {
        id: item.id,
        path: item.path,
        payloadField,
        status: resp.status,
        summary: summarizeIotdbData(resp.data),
        body: truncateForDebug(resp.data)
      });
      const bodyError = iotdbBodyError(resp.data);
      if (bodyError) throw bodyError;

      const points = selected.dataMode === 'RAW'
        ? normalizeRawPoints(resp.data, selected.dataMode)
        : normalizeAggregatedPoints(resp.data, selected.dataMode, request.aggregation);
      lastResult = { points, payloadField };
      debugTrend(deps, 'normalized', {
        id: item.id,
        path: item.path,
        payloadField,
        points: points.length,
        firstPoint: points[0] || null,
        lastPoint: points.length > 0 ? points[points.length - 1] : null
      });
      if (points.length > 0 || payloadField === queryPayloadFields(deps.config).at(-1)) return lastResult;
    } catch (e) {
      lastError = e;
      debugTrend(deps, 'series_payload_error', {
        id: item.id,
        path: item.path,
        payloadField,
        message: e.message || String(e)
      });
    }
  }

  if (lastResult) return lastResult;
  throw lastError || new Error('IoTDB query failed');
}

function groupSeriesByDevice(series) {
  const groups = new Map();
  for (const item of series) {
    const group = groups.get(item.devicePath) || [];
    group.push(item);
    groups.set(item.devicePath, group);
  }
  return Array.from(groups.values());
}

function responseRows(data) {
  if (!data) return [];
  if (data.data && typeof data.data === 'object') return responseRows(data.data);
  if (Array.isArray(data.timestamps) && Array.isArray(data.values)) {
    return data.timestamps.map((ts, idx) => ({ ts, values: data.values.map((v) => Array.isArray(v) ? v[idx] : undefined) }));
  }
  const columns = data.columns || data.column_names || data.expressions;
  if (Array.isArray(data.values) && Array.isArray(columns)) {
    const timeIdx = columns.findIndex((c) => String(c).toLowerCase() === 'time');
    const normalizedTimeIdx = timeIdx >= 0 ? timeIdx : 0;
    const looksColumnOriented = data.values.length === columns.length
      && Array.isArray(data.values[normalizedTimeIdx])
      && data.values.every((col) => Array.isArray(col));
    if (looksColumnOriented) {
      const rowCount = data.values[normalizedTimeIdx].length;
      return Array.from({ length: rowCount }, (_, rowIdx) => ({
        row: data.values.map((col) => col[rowIdx]),
        timeIdx: normalizedTimeIdx,
        columns
      }));
    }
    return data.values.map((row) => ({ row, timeIdx: normalizedTimeIdx, columns }));
  }
  if (Array.isArray(data.rows)) {
    return data.rows.map((row) => ({ objectRow: row }));
  }
  return [];
}

function columnMatchesSeries(column, series) {
  const value = String(column || '').toLowerCase();
  const measurement = series.measurement.toLowerCase();
  const path = series.path.toLowerCase();
  return value === measurement
    || value === path
    || value.endsWith(`.${measurement}`)
    || value.includes(`(${measurement})`)
    || value.includes(`(${path})`);
}

function rawValueIndex(data, series, fallbackIndex) {
  const columns = data?.columns || data?.column_names || data?.expressions;
  if (!Array.isArray(columns)) return fallbackIndex;
  const timeIdx = columns.findIndex((c) => String(c).toLowerCase() === 'time');
  const idx = columns.findIndex((column, index) => index !== timeIdx && columnMatchesSeries(column, series));
  return idx >= 0 ? (timeIdx >= 0 && Array.isArray(data?.values?.[timeIdx]) ? idx : idx) : fallbackIndex;
}

function normalizeRawPointsForSeries(iotdbData, series, dataMode, fallbackIndex = 0) {
  if (iotdbData?.data && typeof iotdbData.data === 'object') {
    return normalizeRawPointsForSeries(iotdbData.data, series, dataMode, fallbackIndex);
  }
  if (Array.isArray(iotdbData?.timestamps) && Array.isArray(iotdbData?.values)) {
    const valueIdx = rawValueIndex(iotdbData, series, fallbackIndex);
    const values = Array.isArray(iotdbData.values[valueIdx]) ? iotdbData.values[valueIdx] : [];
    return iotdbData.timestamps.map((ts, idx) => {
      const value = asNumber(values[idx]);
      return { ts: Number(ts), value, quality: qualityFor(value), dataMode };
    }).filter((p) => Number.isFinite(p.ts) && p.value !== null);
  }

  const rows = responseRows(iotdbData);
  return rows.map((entry) => {
    if (entry.objectRow) {
      const ts = Number(entry.objectRow.Time ?? entry.objectRow.time ?? entry.objectRow.timestamp ?? entry.objectRow.ts);
      const valueKey = Object.keys(entry.objectRow).find((key) => columnMatchesSeries(key, series));
      const value = asNumber(valueKey ? entry.objectRow[valueKey] : null);
      return { ts, value, quality: qualityFor(value), dataMode };
    }
    if (entry.row) {
      const valueIdx = entry.columns.findIndex((column, idx) => idx !== entry.timeIdx && columnMatchesSeries(column, series));
      const fallbackValueIdx = entry.columns.findIndex((_, idx) => idx !== entry.timeIdx);
      const value = asNumber(entry.row[valueIdx >= 0 ? valueIdx : fallbackValueIdx]);
      return { ts: Number(entry.row[entry.timeIdx]), value, quality: qualityFor(value), dataMode };
    }
    const value = asNumber(entry.values[fallbackIndex]);
    return { ts: Number(entry.ts), value, quality: qualityFor(value), dataMode };
  }).filter((p) => Number.isFinite(p.ts) && p.value !== null);
}

function normalizeRawPoints(iotdbData, dataMode) {
  const rows = responseRows(iotdbData);
  return rows.map((entry) => {
    if (entry.objectRow) {
      const ts = Number(entry.objectRow.Time ?? entry.objectRow.time ?? entry.objectRow.timestamp ?? entry.objectRow.ts);
      const valueKey = Object.keys(entry.objectRow).find((key) => !['Time', 'time', 'timestamp', 'ts'].includes(key));
      const value = asNumber(valueKey ? entry.objectRow[valueKey] : null);
      return { ts, value, quality: qualityFor(value), dataMode };
    }
    if (entry.row) {
      const valueIdx = entry.columns.findIndex((_, idx) => idx !== entry.timeIdx);
      const value = asNumber(entry.row[valueIdx]);
      return { ts: Number(entry.row[entry.timeIdx]), value, quality: qualityFor(value), dataMode };
    }
    const value = asNumber(entry.values[0]);
    return { ts: Number(entry.ts), value, quality: qualityFor(value), dataMode };
  }).filter((p) => Number.isFinite(p.ts));
}

function valueByColumn(entry, names) {
  if (!entry.row) return null;
  const idx = entry.columns.findIndex((c) => {
    const col = String(c).toLowerCase();
    return names.some((name) => col.includes(name));
  });
  return idx >= 0 ? asNumber(entry.row[idx]) : null;
}

function valueByColumnForSeries(entry, series, names, fallbackOffset) {
  if (!entry.row) return null;
  const idx = entry.columns.findIndex((c) => {
    const col = String(c).toLowerCase();
    return columnMatchesSeries(c, series) && names.some((name) => col.includes(name));
  });
  if (idx >= 0) return asNumber(entry.row[idx]);
  return Number.isInteger(fallbackOffset) ? asNumber(entry.row[fallbackOffset]) : null;
}

function valueByObjectKey(row, names) {
  if (!row || typeof row !== 'object') return null;
  const key = Object.keys(row).find((k) => {
    const col = String(k).toLowerCase();
    return names.some((name) => col.includes(name));
  });
  return key ? asNumber(row[key]) : null;
}

function firstObjectMetricValue(row) {
  if (!row || typeof row !== 'object') return null;
  const key = Object.keys(row).find((k) => !['Time', 'time', 'timestamp', 'ts'].includes(k));
  return key ? asNumber(row[key]) : null;
}

function normalizeAggregatedPoints(iotdbData, dataMode, aggregation) {
  const rows = responseRows(iotdbData);
  return rows.map((entry) => {
    if (entry.objectRow) {
      const ts = Number(entry.objectRow.Time ?? entry.objectRow.time ?? entry.objectRow.timestamp ?? entry.objectRow.ts);
      const min = asNumber(entry.objectRow.min ?? entry.objectRow.min_value) ?? valueByObjectKey(entry.objectRow, ['min_value', 'min(']);
      const max = asNumber(entry.objectRow.max ?? entry.objectRow.max_value) ?? valueByObjectKey(entry.objectRow, ['max_value', 'max(']);
      const avg = asNumber(entry.objectRow.avg) ?? valueByObjectKey(entry.objectRow, ['avg(']);
      const range = min !== null && max !== null ? max - min : null;
      const value = aggregation === 'minmax'
        ? (avg ?? max ?? min)
        : aggregation === 'range'
          ? range
          : asNumber(entry.objectRow.value ?? avg ?? max ?? min) ?? firstObjectMetricValue(entry.objectRow);
      return aggregation === 'minmax' || aggregation === 'range'
        ? { ts, value, min, max, avg, quality: value === null ? 'BAD' : 'GOOD', dataMode }
        : { ts, value, quality: qualityFor(value), dataMode };
    }
    const ts = entry.row ? Number(entry.row[entry.timeIdx]) : Number(entry.ts);
    if (aggregation === 'minmax' || aggregation === 'range') {
      const min = entry.row ? valueByColumn(entry, ['min_value', 'min(']) : asNumber(entry.values[0]);
      const max = entry.row ? valueByColumn(entry, ['max_value', 'max(']) : asNumber(entry.values[1]);
      const avg = entry.row ? valueByColumn(entry, ['avg(']) : asNumber(entry.values[2]);
      const value = aggregation === 'range'
        ? (min !== null && max !== null ? max - min : null)
        : avg ?? max ?? min;
      return { ts, value, min, max, avg, quality: value === null ? 'BAD' : 'GOOD', dataMode };
    }
    const raw = entry.row
      ? entry.row[entry.columns.findIndex((_, idx) => idx !== entry.timeIdx)]
      : entry.values[0];
    const value = asNumber(raw);
    return { ts, value, quality: qualityFor(value), dataMode };
  }).filter((p) => Number.isFinite(p.ts));
}

function aggregationWidth(aggregation) {
  return aggregation === 'minmax' || aggregation === 'range' ? 3 : 1;
}

function normalizeAggregatedPointsForSeries(iotdbData, series, dataMode, aggregation, groupIndex = 0) {
  if (iotdbData?.data && typeof iotdbData.data === 'object') {
    return normalizeAggregatedPointsForSeries(iotdbData.data, series, dataMode, aggregation, groupIndex);
  }
  const rows = responseRows(iotdbData);
  const offset = groupIndex * aggregationWidth(aggregation);
  return rows.map((entry) => {
    if (entry.objectRow) {
      const ts = Number(entry.objectRow.Time ?? entry.objectRow.time ?? entry.objectRow.timestamp ?? entry.objectRow.ts);
      const min = valueByObjectKey(entry.objectRow, [`min_value(${series.measurement}`, `min_value(${series.path}`]);
      const max = valueByObjectKey(entry.objectRow, [`max_value(${series.measurement}`, `max_value(${series.path}`]);
      const avg = valueByObjectKey(entry.objectRow, [`avg(${series.measurement}`, `avg(${series.path}`]);
      const range = min !== null && max !== null ? max - min : null;
      const value = aggregation === 'minmax'
        ? (avg ?? max ?? min)
        : aggregation === 'range'
          ? range
          : valueByObjectKey(entry.objectRow, [`${aggregation}(${series.measurement}`, `${aggregation}(${series.path}`]) ?? avg ?? max ?? min;
      return aggregation === 'minmax' || aggregation === 'range'
        ? { ts, value, min, max, avg, quality: value === null ? 'BAD' : 'GOOD', dataMode }
        : { ts, value, quality: qualityFor(value), dataMode };
    }

    const ts = entry.row ? Number(entry.row[entry.timeIdx]) : Number(entry.ts);
    if (aggregation === 'minmax' || aggregation === 'range') {
      const min = entry.row ? valueByColumnForSeries(entry, series, ['min_value', 'min('], offset + 1) : asNumber(entry.values[offset]);
      const max = entry.row ? valueByColumnForSeries(entry, series, ['max_value', 'max('], offset + 2) : asNumber(entry.values[offset + 1]);
      const avg = entry.row ? valueByColumnForSeries(entry, series, ['avg('], offset + 3) : asNumber(entry.values[offset + 2]);
      const value = aggregation === 'range'
        ? (min !== null && max !== null ? max - min : null)
        : avg ?? max ?? min;
      return { ts, value, min, max, avg, quality: value === null ? 'BAD' : 'GOOD', dataMode };
    }
    const fallbackIdx = entry.row ? offset + 1 : offset;
    const value = entry.row
      ? valueByColumnForSeries(entry, series, [`${aggregation}(`, 'last_value', 'min_value', 'max_value', 'avg('], fallbackIdx)
      : asNumber(entry.values[offset]);
    return { ts, value, quality: qualityFor(value), dataMode };
  }).filter((p) => Number.isFinite(p.ts));
}

function normalizeGroupedSeries(iotdbData, seriesGroup, selected, aggregation) {
  return seriesGroup.map((item, index) => ({
    item,
    points: selected.dataMode === 'RAW'
      ? normalizeRawPointsForSeries(iotdbData, item, selected.dataMode, index)
      : normalizeAggregatedPointsForSeries(iotdbData, item, selected.dataMode, aggregation, index)
  }));
}

async function queryAndNormalizeGroup(deps, seriesGroup, request, selected, sql) {
  let lastError = null;
  let lastResult = null;

  for (const payloadField of queryPayloadFields(deps.config)) {
    debugTrend(deps, 'request_group', {
      ids: seriesGroup.map((item) => item.id),
      devicePath: seriesGroup[0].devicePath,
      dataMode: selected.dataMode,
      aggregation: request.aggregation,
      intervalMs: selected.intervalMs,
      payloadField,
      rowLimit: queryRowLimit(request, selected),
      sql
    });

    try {
      const resp = await postIotdbQuery(deps, sql, payloadField, { rowLimit: queryRowLimit(request, selected) });
      debugTrend(deps, 'response_group', {
        ids: seriesGroup.map((item) => item.id),
        payloadField,
        status: resp.status,
        summary: summarizeIotdbData(resp.data),
        body: truncateForDebug(resp.data)
      });
      const bodyError = iotdbBodyError(resp.data);
      if (bodyError) throw bodyError;

      const seriesResults = normalizeGroupedSeries(resp.data, seriesGroup, selected, request.aggregation);
      lastResult = { seriesResults, payloadField };
      const hasAnyPoints = seriesResults.some((result) => result.points.length > 0);
      if (hasAnyPoints || payloadField === queryPayloadFields(deps.config).at(-1)) return lastResult;
    } catch (e) {
      lastError = e;
      debugTrend(deps, 'group_payload_error', {
        ids: seriesGroup.map((item) => item.id),
        payloadField,
        message: e.message || String(e)
      });
    }
  }

  if (lastResult) return lastResult;
  throw lastError || new Error('IoTDB query failed');
}

async function executeTrendQuery(request, deps) {
  const selected = chooseDataMode(request, deps);
  const out = [];
  const errors = [];

  for (const seriesGroup of groupSeriesByDevice(request.series)) {
    const sql = buildGroupSql(seriesGroup, request, selected);
    try {
      const { seriesResults, payloadField } = await queryAndNormalizeGroup(deps, seriesGroup, request, selected, sql);
      for (const { item, points } of seriesResults) {
        if (points.length === 0) {
          await runDebugIotdbQuery(deps, item, 'empty_list_user', 'LIST USER');
          await runDebugIotdbQuery(deps, item, 'empty_show_databases', 'SHOW DATABASES');
          await runDebugIotdbQuery(deps, item, 'empty_count_all_timeseries', 'COUNT TIMESERIES root.**');
          await runDebugIotdbQuery(deps, item, 'empty_show_all_timeseries', 'SHOW TIMESERIES root.**');
          await runDebugIotdbQuery(deps, item, 'empty_show_timeseries', buildShowTimeseriesSql(item));
          await runDebugIotdbQuery(deps, item, 'empty_show_device_timeseries', buildShowDeviceTimeseriesSql(item));
          await runDebugIotdbQuery(deps, item, 'empty_latest_samples', buildLatestSeriesSql(item));
        }
        out.push({
          id: item.id,
          path: item.path,
          label: item.label,
          unit: item.unit,
          color: item.color,
          sourcePayloadField: payloadField,
          points
        });
      }
    } catch (e) {
      for (const item of seriesGroup) {
        debugTrend(deps, 'series_error', {
          id: item.id,
          path: item.path,
          message: e.message || String(e)
        });
        errors.push({ id: item.id, path: item.path, error: 'COMM_LOST', message: 'Failed to query series' });
      }
      if (deps.config?.IOTDB_TREND_DEBUG) {
        const item = seriesGroup[0];
        await runDebugIotdbQuery(deps, item, 'empty_list_user', 'LIST USER');
      }
    }
  }

  return {
    dataMode: errors.length > 0 && out.length > 0 ? 'PARTIAL' : selected.dataMode,
    startTs: request.startTs,
    endTs: request.endTs,
    series: out,
    ...(errors.length > 0 ? { errors } : {})
  };
}

function createTrendQueryHandler(deps) {
  return async function trendQueryHandler(req, res) {
    const auth = await deps.requireValidUser(req, res);
    if (!auth) return;

    let request;
    try {
      request = normalizeRequest(req.body, { maxWindowMs: deps.config.IOTDB_TREND_MAX_WINDOW_MS });
    } catch (e) {
      if (e.trendError) {
        return res.status(e.trendError.status).json({
          error: e.trendError.error,
          message: e.trendError.message,
          ...(e.trendError.details ? { details: e.trendError.details } : {})
        });
      }
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'Invalid trend query request' });
    }

    try {
      const result = await executeTrendQuery(request, {
        ax: deps.ax,
        config: deps.config,
        estimatedSampleMs: deps.config.IOTDB_TREND_ESTIMATED_SAMPLE_MS,
        logger: deps.logger
      });
      return res.json(result);
    } catch (e) {
      if (deps.serviceState) deps.serviceState.lastIotdbError = e.message || String(e);
      return res.status(500).json({ error: 'IOTDB_QUERY_FAILED', message: 'Failed to query trend data' });
    }
  };
}

module.exports = {
  aggregationExpressions,
  buildGroupSql,
  buildSeriesSql,
  buildLatestSeriesSql,
  buildShowDeviceTimeseriesSql,
  buildShowTimeseriesSql,
  chooseDataMode,
  chooseIntervalMs,
  createTrendQueryHandler,
  executeTrendQuery,
  normalizeAggregatedPoints,
  normalizeRawPoints,
  normalizeRequest,
  validateIotdbPath
};
