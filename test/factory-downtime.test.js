const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const {
  createDowntimeRouter,
  annotation,
  validateEvents,
} = require("../src/factory-downtime");
const uuid = "00000000-0000-0000-0000-000000000001";
const event = {
  id: "event",
  start: 100,
  end: 1000,
  state: "STOPPED",
  seconds: 0.9,
};
const user = { id: { id: uuid }, email: "operator", authority: "TENANT_ADMIN" };
const input = {
  eventId: "event",
  expectedRevision: 0,
  reasonId: "BREAKDOWN",
  note: "  test  ",
  requestId: uuid,
};
const report = {
  schemaVersion: 1,
  reportRevision: 1,
  scheduledSeconds: 0.9,
  uptimeSeconds: 0,
  downtimeSeconds: 0.9,
  unknownSeconds: 0,
  stateSeconds: { RUNNING: 0, IDLE: 0, STOPPED: 0.9, SETUP: 0, FAULT: 0 },
  calculatedAt: 302000,
  periodId: "2026-09-30",
  periodStart: 0,
  periodEnd: 2000,
  finalizedAt: 302000,
  finalized: true,
  finalizerVersion: 1,
  pendingSeconds: 0,
  calculationVersion: 2,
  maxSampleAgeSeconds: 300,
};
const fingerprint = require("node:crypto")
  .createHash("sha256")
  .update(JSON.stringify(report))
  .digest("hex");
const period = () => ({
  periodId: "2026-09-30",
  reportFingerprint: fingerprint,
  status: "READY",
  events: [event],
  history: [],
});
test("Reason revisions use trusted user and timestamp, trim notes, refuse spoofed fields", () => {
  assert.deepEqual(annotation(input, period(), user, 123), {
    eventId: "event",
    revision: 1,
    reasonId: "BREAKDOWN",
    note: "test",
    requestId: uuid,
    actorId: uuid,
    actorLabel: "operator",
    at: 123,
  });
  for (const field of ["actorId", "at", "revision"])
    assert.throws(() =>
      annotation({ ...input, [field]: "spoof" }, period(), user, 123),
    );
});
test("Reject stale revisions, missing events, unknown reasons and oversized notes", () => {
  const p = period();
  p.history.push(annotation(input, p, user, 123));
  assert.throws(
    () => annotation(input, p, user, 124),
    (e) => e.status === 409,
  );
  for (const change of [
    { eventId: "missing" },
    { reasonId: "FAKE" },
    { note: "x".repeat(501) },
    { expectedRevision: -1 },
  ])
    assert.throws(() =>
      annotation({ ...input, ...change }, period(), user, 123),
    );
});
test("Clearing a reason appends a revision without deleting history", () => {
  const p = period();
  p.history.push(annotation(input, p, user, 123));
  const next = annotation(
    { ...input, reasonId: null, expectedRevision: 1 },
    p,
    user,
    124,
  );
  assert.equal(next.revision, 2);
  assert.equal(next.reasonId, null);
  assert.equal(p.history.length, 1);
});
test("Boundary validation rejects overlap, unknown states and mismatched totals", () => {
  const report = {
    periodId: "2026-09-30",
    reportRevision: 1,
    periodStart: 0,
    periodEnd: 2000,
    stateSeconds: { IDLE: 0, STOPPED: 0.9, SETUP: 0, FAULT: 0 },
  };
  const events = validateEvents([event], report);
  assert.equal(events[0].seconds, 0.9);
  assert.equal(events[0].id.length, 64);
  for (const rows of [
    [{ ...event, state: "RUNNING" }],
    [event, event],
    [{ ...event, end: 3000 }],
    [{ ...event, end: 900 }],
  ])
    assert.throws(() => validateEvents(rows, report));
});
async function harness(
  t,
  { auth = true, authority = "TENANT_ADMIN", block = false, initialJournal } = {},
) {
  let journal = initialJournal || { schemaVersion: 1, revision: 0, periods: [period()] };
  let posts = 0;
  let release;
  const gate = new Promise((r) => (release = r));
  const ax = {
    get: async (url) => {
      if (url.includes("availabilityDailyReport"))
        return {
          data: { availabilityDailyReport: [{ ts: 1999, value: report }] },
        };
      if (url.endsWith("/api/auth/user"))
        return { data: { ...user, authority } };
      if (url.includes("/api/assets?assetIds="))
        return { data: [{ type: "MACHINE" }] };
      return {
        data: [{ key: "downtimeReview", value: structuredClone(journal) }],
      };
    },
    post: async (url, body) => {
      posts++;
      if (block) await gate;
      journal = structuredClone(body.downtimeReview);
      return { data: null };
    },
  };
  const app = express();
  app.use(
    createDowntimeRouter({
      express,
      ax,
      base: "http://tb",
      requireValidUser: async (req, res) => {
        if (!auth) {
          res.status(401).end();
          return null;
        }
        return { userToken: "test" };
      },
    }),
  );
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  t.after(() => {
    release();
    server.close();
  });
  const path = `http://127.0.0.1:${server.address().port}/api/factory/machines/${uuid}/downtime`;
  const save = (body) =>
    fetch(path + "/2026-09-30/reason", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  return { path, save, release, posts: () => posts, journal: () => journal };
}
test("Endpoint enforces authentication and tenant administrator role", async (t) => {
  for (const options of [{ auth: false }, { authority: "CUSTOMER_USER" }]) {
    const h = await harness(t, options);
    assert.equal(
      (await h.save(input)).status,
      options.auth === false ? 401 : 403,
    );
    assert.equal(h.posts(), 0);
  }
});
test("Endpoint preserves history, retries idempotently and rejects conflicting edits", async (t) => {
  const h = await harness(t);
  assert.equal((await h.save(input)).status, 200);
  assert.equal((await h.save(input)).status, 200);
  assert.equal(h.posts(), 1);
  assert.equal(
    (
      await h.save({
        ...input,
        requestId: "00000000-0000-0000-0000-000000000002",
      })
    ).status,
    409,
  );
  assert.equal(h.journal().periods[0].history.length, 1);
});
test("Concurrent conflicts cannot release another operation lock", async (t) => {
  const h = await harness(t, { block: true });
  const first = h.save(input);
  while (h.posts() === 0) await new Promise((r) => setTimeout(r, 5));
  assert.equal((await h.save(input)).status, 409);
  assert.equal((await h.save(input)).status, 409);
  h.release();
  assert.equal((await first).status, 200);
  assert.equal(h.posts(), 1);
});

 test("Large legacy journal migrates on a reason append, and readback preserves every record", async t => {
 const p=period();
 p.events.push(...Array.from({length:1700},(_,i)=>({...event,id:String(i).padStart(64,"0"),start:2000+i*2000,end:3000+i*2000})));
 const initialJournal={schemaVersion:1,revision:4,periods:[p]};
 assert.ok(Buffer.byteLength(JSON.stringify(initialJournal)) > 180000);
 const h=await harness(t,{initialJournal});
 const response=await h.save(input);
 assert.equal(response.status,200);
 const decoded=await response.json();
 assert.equal(decoded.periods[0].events.length,1701);
 assert.equal(decoded.periods[0].history.length,1);
 assert.equal(h.journal().encoding,"gzip-base64");
 assert.equal((await h.save(input)).status,200);
 assert.equal(h.posts(),1);
 const loaded=await (await fetch(h.path)).json();
 assert.deepEqual(loaded,decoded);
 });
 test("Expanded storage guard retains the existing journal and makes no native write",async t=>{
 const initialJournal={schemaVersion:1,revision:4,periods:[period()],extra:"x".repeat(2*1024*1024)};
 const h=await harness(t,{initialJournal});
 assert.equal((await h.save(input)).status,409);
 assert.equal(h.posts(),0);
 assert.deepEqual(h.journal(),initialJournal);
 });

test('Preparation can finish a new day beside a large saved journal and retries without duplicating stops',async t=>{
 const old=period();old.periodId='2026-09-29';
 old.events.push(...Array.from({length:1700},(_,i)=>({...event,id:String(i).padStart(64,'0'),start:2000+i*2000,end:3000+i*2000})));
 let stored={schemaVersion:1,revision:5,periods:[old]};const original=structuredClone(old);let saves=0;let calculations=0;
 const calendar={schemaVersion:1,revisions:[{id:'r1',effectiveFrom:'2026-01-01',timezone:'UTC',shifts:[],exceptions:[]}]};
 const ax={get:async url=>{
  if(url.endsWith('/api/auth/user'))return {data:user};
  if(url.includes('/api/assets?'))return {data:[{type:'MACHINE'}]};
  if(url.includes('availabilityDailyReport'))return {data:{availabilityDailyReport:[{ts:1999,value:report}]}};
  if(url.includes('keys=productionCalendar'))return {data:[{key:'productionCalendar',value:calendar}]};
  if(url.includes('keys=machineState'))return {data:{machineState:[]}};
  return {data:[{key:'downtimeReview',value:structuredClone(stored)}]};
 },post:async(url,body)=>{
  if(url.endsWith('/api/calculatedField/testScript')){
   calculations++;
   const result=calculations%2===1 ? {msgType:'FACTORY_AVAILABILITY_QUERY',msg:{periodId:report.periodId,periodStart:0,periodEnd:2000,plannedMs:900},metadata:{fromTs:'0',toTs:'2000'}} : {msg:{values:{availabilityDailyCheckpoint:{},availabilityDailyReport:{...report,downtimeEvents:[{start:100,end:1000,state:'STOPPED'}]}}}};
   return {data:{output:JSON.stringify(result)}};
  }
  saves++;stored=structuredClone(body.downtimeReview);return {data:null};
 }};
 const app=express();app.use(createDowntimeRouter({express,ax,base:'http://tb',requireValidUser:async()=>({userToken:'test'})}));
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));t.after(()=>server.close());
 const path=`http://127.0.0.1:${server.address().port}/api/factory/machines/${uuid}/downtime/2026-09-30/prepare`;
 const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
 assert.equal(response.status,200);const result=await response.json();
 assert.equal(stored.encoding,'gzip-base64');assert.deepEqual(result.periods[0],original);
 assert.equal(result.periods[1].status,'READY');assert.equal(result.periods[1].events.length,1);
 assert.equal((await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).status,200);
 assert.equal(saves,1);assert.equal(calculations,2);
});
