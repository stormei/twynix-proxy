const express = require('express');
const { fail } = require('./screen-store');
const { TYPE } = require('./faceplate-store');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function createFaceplateRouter({ store, authenticate, readLegacy }) {
  const router = express.Router();
  const route = fn => (req,res,next) => Promise.resolve().then(() => fn(req,res)).catch(next);
  router.use(async (req,res,next) => {
    try {
      req.templateUser = await authenticate(req);
      if (!req.templateUser?.tenantId || !req.templateUser?.userId) fail(401,'Valid tenant user required');
      res.setHeader('Cache-Control','no-store');
      next();
    } catch (error) { next(error); }
  });
  router.use(express.json({ limit: '6mb' }));
  function admin(req) { if (req.templateUser.authority !== 'TENANT_ADMIN') fail(403,'Tenant administrator required for template authoring'); }
  function id(req) { if (!UUID.test(req.params.id)) fail(400,'Invalid template ID'); return req.params.id; }
  function expected(req) {
    if (!/^"?\d+"?$/.test(req.headers['if-match'] || '')) fail(428,'If-Match revision is required');
    return Number(req.headers['if-match'].replace(/"/g,''));
  }
  async function readable(user,row) {
    if (user.authority === 'TENANT_ADMIN') return true;
    if (row.deleted) return false;
    if (row.sourceAssetId) {
      try { await readLegacy(user,row.sourceAssetId,true); }
      catch (error) { if ([403,404].includes(error.status || error.response?.status)) return false; throw error; }
    }
    return true;
  }
  async function load(req) {
    const row = store.get(req.templateUser.tenantId,id(req));
    if (!row) fail(404,'Template not found');
    if (!await readable(req.templateUser,row)) fail(403,'Template unavailable to this user');
    if (row.deleted) fail(410,'Template deleted; history retained');
    return row;
  }
  function send(res,row,status=200) { res.setHeader('ETag',`"${row.revision}"`); res.status(status).json(row); }
  router.get('/',route(async (req,res) => {
    const rows = store.list(req.templateUser.tenantId), data = [];
    for (const row of rows) if (!row.deleted && await readable(req.templateUser,row)) data.push(row);
    res.json({ data, shadowIds: rows.map(row => row.asset.id.id) });
  }));
  router.post('/',route((req,res) => {
    admin(req);
    send(res,store.create(req.templateUser.tenantId,req.templateUser.userId,req.body?.template),201);
  }));
  router.post('/migrate/:id',route(async (req,res) => {
    admin(req);
    const key = id(req), user = req.templateUser, existing = store.get(user.tenantId,key);
    if (existing) return send(res,existing);
    const {asset,attrs} = await readLegacy(user,key);
    if (asset.type !== TYPE || asset.tenantId?.id !== user.tenantId) fail(403,'Only same-tenant faceplate templates can be migrated');
    send(res,store.create(user.tenantId,user.userId,attrs.faceplateTemplate,key,key),201);
  }));
  router.get('/:id',route(async (req,res) => send(res,await load(req))));
  router.patch('/:id',route(async (req,res) => {
    admin(req); await load(req);
    send(res,store.update(req.templateUser.tenantId,req.templateUser.userId,id(req),expected(req),req.body?.attrs?.faceplateTemplate));
  }));
  router.delete('/:id',route(async (req,res) => {
    admin(req); await load(req);
    send(res,store.update(req.templateUser.tenantId,req.templateUser.userId,id(req),expected(req),null,true));
  }));
  router.use((error,req,res,next) => {
    if (res.headersSent) return next(error);
    const status = error.status || error.response?.status || 500;
    res.status(status >= 400 && status < 600 ? status : 500).json({message: status < 500 ? error.message : 'Template storage unavailable; no fallback write attempted'});
  });
  return router;
}
module.exports = { createFaceplateRouter };
