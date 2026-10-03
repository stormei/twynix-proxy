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
  { auth = true, authority = "TENANT_ADMIN", block = false } = {},
) {
  let journal = { schemaVersion: 1, revision: 0, periods: [period()] };
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
