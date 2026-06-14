const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function parseContentLength(headers = {}) {
  const raw = headers['content-length'];
  if (raw === undefined) return null;
  const value = Array.isArray(raw) ? raw[0] : raw;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : NaN;
}

function hasChunkedTransferEncoding(headers = {}) {
  const raw = headers['transfer-encoding'];
  const value = Array.isArray(raw) ? raw.join(',') : String(raw || '');
  return value.split(',').map((part) => part.trim().toLowerCase()).includes('chunked');
}

function validateProxyBodySize(req, maxBodyBytes) {
  const method = String(req?.method || '').toUpperCase();
  if (!BODY_METHODS.has(method)) return null;

  const max = Number(maxBodyBytes);
  if (!Number.isInteger(max) || max <= 0) {
    return {
      status: 500,
      reason: 'invalid_proxy_body_limit',
      message: 'Proxy body limit is not configured correctly'
    };
  }

  const headers = req?.headers || {};
  const contentLength = parseContentLength(headers);
  if (Number.isNaN(contentLength)) {
    return {
      status: 400,
      reason: 'invalid_content_length',
      message: 'Invalid Content-Length header'
    };
  }

  if (contentLength !== null && contentLength > max) {
    return {
      status: 413,
      reason: 'content_length_too_large',
      message: 'Request body too large'
    };
  }

  if (contentLength === null && hasChunkedTransferEncoding(headers)) {
    return {
      status: 411,
      reason: 'missing_content_length',
      message: 'Content-Length is required for proxied write requests'
    };
  }

  return null;
}

module.exports = {
  validateProxyBodySize
};
