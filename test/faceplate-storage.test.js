const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openScreenStore } = require('../src/screen-store');
const { openFaceplateStore, TYPE } = require('../src/faceplate-store');
const { createFaceplateRouter } = require('../src/faceplate-router');
const template = { templateId:'motor', name:'Motor', version:1, assetType:'motor', sections:[] };

test('faceplates: tenant isolation, validation, revisions, tombstones, screen backup recovery', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'twynix-faceplates-'));
  const source = path.join(dir,'screens.sqlite'), backup = path.join(dir,'backup.sqlite');
  const screens = openScreenStore(source), store = openFaceplateStore(source);
  t.after(() => { store.close(); screens.close(); fs.rmSync(dir,{recursive:true}); });
  const row = store.create('tenant','admin',template), id = row.asset.id.id;
  assert.equal(store.get('other',id),undefined);
  assert.throws(() => store.create('tenant','admin',{}),{status:400});
  store.update('tenant','admin',id,1,{...template,name:'Updated'});
  assert.throws(() => store.update('tenant','admin',id,1,template),{status:409});
  await screens.backup(backup);
  const restored = openFaceplateStore(backup);
  assert.equal(restored.get('tenant',id).attrs.faceplateTemplate.name,'Updated');
  assert.equal(restored.get('tenant',id).revision,2);
  restored.close();
  store.update('tenant','admin',id,2,null,true);
  assert.equal(store.get('tenant',id).deleted,true);
  assert.equal(store.list('tenant').length,1);
});

test('faceplate API: authorization, safe copy, CAS, denied reads and no original resurrection', async t => {
  const store = openFaceplateStore(':memory:');
  const legacyId = '11111111-1111-4111-8111-111111111111';
  let sourceAllowed = true;
  const app = express();
  app.use(createFaceplateRouter({store,
    authenticate: async req => {
      if (!req.headers['x-role']) throw Object.assign(new Error('Unauthorized'),{status:401});
      return {tenantId:req.headers['x-tenant'] || 'tenant',userId:'user',authority:req.headers['x-role']};
    },
    readLegacy: async user => {
      if (!sourceAllowed && user.authority !== 'TENANT_ADMIN') throw Object.assign(new Error('Denied'),{status:403});
      return {asset:{type:TYPE,tenantId:{id:'tenant'}},attrs:{faceplateTemplate:template}};
    }
  }));
  const server = app.listen(0,'127.0.0.1');
  await new Promise(resolve => server.once('listening',resolve));
  t.after(() => { server.close(); store.close(); });
  const request = (url,method='GET',body,headers={}) => fetch(`http://127.0.0.1:${server.address().port}${url}`, {
    method,headers:{'Content-Type':'application/json','x-role':'TENANT_ADMIN',...headers},
    ...(body === undefined ? {} : {body:JSON.stringify(body)})
  });
  assert.equal((await request('/','GET',undefined,{'x-role':''})).status,401);
  assert.equal((await request('/','POST',{template},{'x-role':'CUSTOMER_USER'})).status,403);
  const created = await request('/','POST',{template});
  assert.equal(created.status,201);
  const id = (await created.json()).asset.id.id;
  assert.equal((await request(`/${id}`,'GET',undefined,{'x-role':'CUSTOMER_USER'})).status,200);
  assert.equal((await request(`/${id}`,'GET',undefined,{'x-tenant':'other'})).status,404);
  assert.equal((await request(`/${id}`,'PATCH',{attrs:{faceplateTemplate:template}})).status,428);
  assert.equal((await request(`/${id}`,'PATCH',{attrs:{faceplateTemplate:template}},{'If-Match':'1'})).status,200);
  assert.equal((await request(`/${id}`,'PATCH',{attrs:{faceplateTemplate:template}},{'If-Match':'1'})).status,409);
  assert.equal((await request(`/migrate/${legacyId}`,'POST',{})).status,201);
  sourceAllowed = false;
  assert.equal((await request(`/${legacyId}`,'GET',undefined,{'x-role':'CUSTOMER_USER'})).status,403);
  assert.equal((await request(`/${legacyId}`,'DELETE',undefined,{'If-Match':'1'})).status,200);
  assert.equal((await request(`/${legacyId}`)).status,410);
  const again = await (await request(`/migrate/${legacyId}`,'POST',{})).json();
  assert.equal(again.deleted,true);
  const listing = await (await request('/')).json();
  assert.ok(listing.shadowIds.includes(legacyId));
  assert.equal(listing.data.length,1);
});
