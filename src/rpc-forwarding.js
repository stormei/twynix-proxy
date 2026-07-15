'use strict';

const LEGACY_RPC_PATH_RX = /^\/api\/plugins\/rpc\/(oneway|twoway)(\/.*)?$/i;

function rewriteThingsBoardRpcPath(pathname) {
  if (typeof pathname !== 'string') return pathname;
  return pathname.replace(LEGACY_RPC_PATH_RX, (_match, mode, suffix = '') =>
    `/api/rpc/${String(mode).toLowerCase()}${suffix}`
  );
}

async function dispatchRpcAudit({ requireAudit, emitAudit, onError }, req, event) {
  if (requireAudit) return emitAudit(req, event);

  void Promise.resolve()
    .then(() => emitAudit(req, event))
    .catch((error) => {
      if (typeof onError === 'function') onError(error);
    });

  return { ok: true, deferred: true };
}

module.exports = {
  rewriteThingsBoardRpcPath,
  dispatchRpcAudit
};
