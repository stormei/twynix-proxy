const express = require('express');
function createDiscoveryRouter({ sessions, mappings, authenticate, audit = () => {} }) {
  const router = express.Router();
  router.use(express.json({ limit: '256kb' }));
  router.use(async (req, res, next) => {
    try {
      req.discoveryUser = await authenticate(req);
      sessions.authorize(req.discoveryUser);
      res.setHeader('Cache-Control', 'no-store');
      next();
    } catch (error) { next(error); }
  });
  const route = (operation, fn) => async (req, res, next) => {
    const start = Date.now();
    try {
      const result = await fn(req);
      audit({ operation, tenantId: req.discoveryUser.tenantId, userId: req.discoveryUser.userId, outcome: 'success', durationMs: Date.now() - start });
      res.json(result);
    } catch (error) {
      audit({ operation, tenantId: req.discoveryUser.tenantId, userId: req.discoveryUser.userId, outcome: 'failure', durationMs: Date.now() - start });
      next(error);
    }
  };
  router.get('/connections', route('connections', req => sessions.list(req.discoveryUser)));
  if (mappings) {
    router.get('/devices', route('devices', req => mappings.devices(req.discoveryUser, req.query.search || '', Number(req.query.page || 0))));
    router.get('/mappings/:connection', route('read-mapping', req => mappings.get(req.discoveryUser, req.params.connection)));
    router.put('/mappings/:connection', route('save-mapping', req => mappings.save(req.discoveryUser, req.params.connection, req.body || {})));
    router.post('/mappings/:connection/restore', route('restore-mapping', req => mappings.restore(req.discoveryUser, req.params.connection, req.body || {})));
    router.post('/mappings/:connection/preview', route('preview-mapping', req => mappings.preview(req.discoveryUser, req.params.connection, req.body?.sessionId)));
    router.post('/mappings/:connection/deploy', route('deploy-mapping', req => mappings.deploy(req.discoveryUser, req.params.connection, req.body?.token)));
    router.get('/mappings/:connection/verify', route('verify-mapping', req => mappings.verify(req.discoveryUser, req.params.connection)));
  }
  router.post('/sessions', route('open', req => sessions.open(req.discoveryUser, req.body?.connectionId, req.body?.revision)));
  router.post('/sessions/:id/browse', route('browse', req => sessions.browse(req.discoveryUser, req.params.id, req.body || {})));
  router.post('/sessions/:id/inspect', route('inspect', req => sessions.inspect(req.discoveryUser, req.params.id, req.body || {})));
  router.delete('/sessions/:id', route('close', async req => { await sessions.close(req.discoveryUser, req.params.id); return { closed: true }; }));
  router.use((req, res) => res.status(404).json({ message: 'Unknown discovery operation' }));
  router.use((error, req, res, next) => {
    const status = error.status || error.response?.status;
    const safe = [400,401,403,404,409,410,413,429,504].includes(status);
    res.status(safe ? status : 502).json({ message: safe && error.status ? error.message : 'OPC UA discovery unavailable; check proxy configuration and server access' });
  });
  return router;
}
module.exports = { createDiscoveryRouter };
