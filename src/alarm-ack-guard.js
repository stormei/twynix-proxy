const ALARM_ACK_PATH_RX = /^\/api\/alarm\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/ack\/?$/i;

function entityId(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value.id === 'string') return value.id;
  return '';
}

function upstreamStatus(error) {
  const status = Number(error?.response?.status);
  return [401, 403, 404].includes(status) ? status : 502;
}

function createAlarmAckGuard({
  ax,
  thingsboardUrl,
  requireValidUser,
  emitAuditEvent = async () => {}
}) {
  if (!ax || typeof ax.get !== 'function') throw new Error('Alarm ACK guard requires an axios-compatible client');
  if (!thingsboardUrl) throw new Error('Alarm ACK guard requires ThingsBoard URL');
  if (typeof requireValidUser !== 'function') throw new Error('Alarm ACK guard requires user authentication');

  const baseUrl = String(thingsboardUrl).replace(/\/+$/, '');

  return async function alarmAckGuard(req, res, next) {
    if (String(req.method || '').toUpperCase() !== 'POST') return next();

    const match = String(req.path || '').match(ALARM_ACK_PATH_RX);
    if (!match) return next();

    const alarmId = match[1];
    const auth = await requireValidUser(req, res);
    if (!auth) return;

    const audit = (outcome, reason) => emitAuditEvent(req, {
      type: 'alarm_ack',
      outcome,
      reason,
      userId: auth.userId,
      entityType: 'ALARM',
      entityId: alarmId,
      method: 'POST',
      path: req.path
    });

    if (!auth.tenantId || auth.tenantId === 'unknown') {
      await audit('denied', 'Tenant missing from token');
      return res.status(403).json({ error: 'Forbidden: tenant missing from token' });
    }

    try {
      // Reading with the caller's token makes ThingsBoard enforce that this user
      // can access this exact alarm before the write is allowed through.
      const response = await ax.get(`${baseUrl}/api/alarm/${alarmId}`, {
        headers: { 'X-Authorization': `Bearer ${auth.userToken}` }
      });
      const alarmTenantId = entityId(response?.data?.tenantId);

      if (!alarmTenantId || alarmTenantId !== auth.tenantId) {
        await audit('denied', 'Alarm tenant mismatch');
        return res.status(403).json({ error: 'Forbidden: alarm tenant mismatch' });
      }

      req.__twynixProxyGuard = 'alarmAck';
      await audit('allowed', 'Alarm access and tenant verified');
      return next();
    } catch (error) {
      const status = upstreamStatus(error);
      await audit(status === 502 ? 'error' : 'denied', `Alarm access check failed (${status})`);
      return res.status(status).json({
        error: status === 502 ? 'Failed to verify alarm access' : 'Alarm access denied'
      });
    }
  };
}

module.exports = {
  ALARM_ACK_PATH_RX,
  createAlarmAckGuard,
  entityId,
  upstreamStatus
};
