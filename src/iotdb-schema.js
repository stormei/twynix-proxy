function queryPayloadFields(config = {}) {
  const preferred = String(config.IOTDB_REST_QUERY_FIELD || 'sql').trim();
  const useFallbacks = String(config.IOTDB_REST_QUERY_FIELD_FALLBACKS || 'false').toLowerCase() === 'true';
  const fields = useFallbacks
    ? [preferred, 'sql', 'query', 'statement']
    : [preferred];
  return [...new Set(fields)];
}

async function postIotdbQuery(deps, sql, payloadField, options = {}) {
  const payload = { [payloadField]: sql };
  if (Number.isInteger(options.rowLimit) && options.rowLimit > 0) {
    payload.row_limit = options.rowLimit;
  }
  return deps.ax.post(`${deps.config.IOTDB_URL}/rest/v2/query`, payload, {
    headers: {
      Authorization: `Basic ${deps.config.IOTDB_AUTH}`,
      'Content-Type': 'application/json'
    }
  });
}

function iotdbBodyError(data) {
  return data && typeof data.code === 'number' && data.code >= 300
    ? new Error(data.message || `IoTDB returned code ${data.code}`)
    : null;
}

async function runIotdbQuery(deps, sql) {
  let lastError = null;
  for (const payloadField of queryPayloadFields(deps.config)) {
    try {
      const resp = await postIotdbQuery(deps, sql, payloadField, { rowLimit: deps.config?.IOTDB_SCHEMA_ROW_LIMIT });
      const bodyError = iotdbBodyError(resp.data);
      if (bodyError) throw bodyError;
      return resp.data;
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error('IoTDB schema query failed');
}

function columnValues(data, candidates) {
  if (!data) return [];
  if (data.data && typeof data.data === 'object') return columnValues(data.data, candidates);

  const columns = data.columns || data.column_names || data.expressions;
  const values = data.values || data.data || data.rows;
  if (!Array.isArray(columns) || !Array.isArray(values)) return [];

  const wanted = candidates.map((name) => String(name).toLowerCase());
  const index = columns.findIndex((column) => wanted.includes(String(column).toLowerCase()));
  if (index < 0) return [];

  if (values.length === columns.length && values.every((col) => Array.isArray(col))) {
    return values[index].map((value) => String(value ?? '')).filter(Boolean);
  }

  if (values.every((row) => Array.isArray(row))) {
    return values.map((row) => String(row[index] ?? '')).filter(Boolean);
  }

  if (values.every((row) => row && typeof row === 'object')) {
    const key = columns[index];
    return values.map((row) => String(row[key] ?? '')).filter(Boolean);
  }

  return [];
}

function metadataRows(data) {
  const paths = columnValues(data, ['Timeseries', 'TimeSeries', 'timeseries', 'path', 'Path']);
  const dataTypes = columnValues(data, ['DataType', 'datatype', 'Type', 'type']);
  const encodings = columnValues(data, ['Encoding', 'encoding']);
  const compressions = columnValues(data, ['Compression', 'compression']);
  const tags = columnValues(data, ['Tags', 'tags']);

  return paths.map((path, index) => ({
    path,
    dataType: dataTypes[index] || '',
    encoding: encodings[index] || '',
    compression: compressions[index] || '',
    tags: tags[index] || undefined
  }));
}

function rootFromPath(path) {
  return String(path || '').split('.').slice(0, 2).join('.');
}

function deviceFromPath(path) {
  const parts = String(path || '').split('.').filter(Boolean);
  return parts.length > 2 ? parts.slice(0, -1).join('.') : '';
}

async function collectSchema(deps) {
  const roots = new Set();
  const devices = new Set();
  const timeseries = new Map();

  for (const sql of ['SHOW DATABASES', 'SHOW STORAGE GROUP']) {
    try {
      const data = await runIotdbQuery(deps, sql);
      for (const root of columnValues(data, ['Database', 'Storage Group', 'StorageGroup', 'storage group', 'database'])) {
        if (root) roots.add(root);
      }
    } catch (e) {
      deps.logger?.(JSON.stringify({ event: 'iotdb_schema_debug', stage: 'root_query_error', sql, message: e.message || String(e) }));
    }
  }

  let rootList = Array.from(roots);
  const rootPatterns = rootList.length ? rootList.map((root) => `${root}.**`) : ['root.**'];

  for (const pattern of rootPatterns) {
    for (const sql of [`SHOW DEVICES ${pattern}`, `SHOW TIMESERIES ${pattern}`]) {
      try {
        const data = await runIotdbQuery(deps, sql);
        for (const device of columnValues(data, ['Device', 'Devices', 'device', 'devices'])) {
          if (device) {
            devices.add(device);
            const root = rootFromPath(device);
            if (root) roots.add(root);
          }
        }
        for (const row of metadataRows(data)) {
          if (!row.path) continue;
          timeseries.set(row.path, row);
          const device = deviceFromPath(row.path);
          if (device) devices.add(device);
          const root = rootFromPath(row.path);
          if (root) roots.add(root);
        }
      } catch (e) {
        deps.logger?.(JSON.stringify({ event: 'iotdb_schema_debug', stage: 'schema_query_error', sql, message: e.message || String(e) }));
      }
    }
  }

  rootList = Array.from(roots).sort();
  const deviceList = Array.from(devices).sort();
  const seriesList = Array.from(timeseries.values()).sort((a, b) => a.path.localeCompare(b.path));

  return {
    roots: rootList,
    devices: deviceList,
    timeseries: seriesList
  };
}

function createIotdbSchemaHandler(deps) {
  let cachedSchema = null;
  let cachedUntil = 0;
  let inFlight = null;

  return async function iotdbSchemaHandler(req, res) {
    const auth = await deps.requireValidUser(req, res);
    if (!auth) return;

    try {
      const ttlMs = Number(deps.config?.IOTDB_SCHEMA_CACHE_TTL_MS ?? 60_000);
      const now = Date.now();
      if (cachedSchema && ttlMs > 0 && now < cachedUntil) {
        return res.json(cachedSchema);
      }

      if (!inFlight) {
        inFlight = collectSchema(deps)
          .then((schema) => {
            cachedSchema = schema;
            cachedUntil = Date.now() + Math.max(0, ttlMs);
            return schema;
          })
          .finally(() => {
            inFlight = null;
          });
      }

      const schema = await inFlight;
      return res.json(schema);
    } catch (e) {
      if (deps.serviceState) deps.serviceState.lastIotdbError = e.message || String(e);
      return res.status(500).json({ error: 'IOTDB_SCHEMA_FAILED', message: 'Failed to load IoTDB schema' });
    }
  };
}

module.exports = {
  collectSchema,
  createIotdbSchemaHandler
};
