const WRITE = /^(POST|PUT|PATCH|DELETE)$/i;
const telemetryPrefix = /^\/api\/plugins\/telemetry\//i;
const sharedScopePath = /^\/api\/plugins\/telemetry\/(ASSET|DEVICE)\/[a-zA-Z0-9\-]+\/SHARED_SCOPE\/?$/i;
const serverScopePath = /^\/api\/plugins\/telemetry\/(ASSET|DEVICE)\/[a-zA-Z0-9\-]+\/SERVER_SCOPE\/?$/i;

function createTelemetryWriteGuard(deps) {
  const emitOplogEvent = deps.emitOplogEvent || deps.auditToThingsBoard || (async () => {});
  const internalSecret = deps.internalSecret;

  return async function telemetryWriteGuard(req, res, next) {
    if (internalSecret && req.headers['x-twynix-internal-admin'] === internalSecret) {
      return next();
    }
    if (!WRITE.test(req.method)) return next();
    if (!telemetryPrefix.test(req.path)) return next();
    if (sharedScopePath.test(req.path)) return next();
    if (serverScopePath.test(req.path) && req.__allowedMgmtWrite === true) return next();

    await emitOplogEvent({
      tenantId: req.__twynixAuth?.tenantId || '',
      userId: req.__twynixAuth?.userId || '',
      corr: req.twynixRequestId || '',
      type: 'write_blocked',
      outcome: 'denied',
      reason: 'Telemetry write not allowed',
      method: req.method,
      path: req.path
    });
    return res.status(403).send('Writes must use SHARED_SCOPE via proxy policy');
  };
}

module.exports = {
  createTelemetryWriteGuard
};
