const test = require("node:test");
const assert = require("node:assert/strict");
const { applyNote } = require("../src/factory-notes");
const user = {
  id: { id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
  email: "operator@example.test",
};
const empty = () => ({
  schemaVersion: 1,
  revision: 0,
  notes: [],
  requests: [],
});
const body = {
  requestId: "11111111-1111-1111-1111-111111111111",
  expectedRevision: 0,
  text: "Check coolant",
  kind: "HANDOVER",
  actorId: "spoofed",
  at: 1,
};
test("trusted authorship, idempotent retry, conflict and immutable note content", () => {
  const initial = empty();
  const saved = applyNote(initial, body, user, 1000);
  assert.equal(saved.notes[0].actorId, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
  assert.equal(saved.notes[0].at, 1000);
  assert.equal(initial.notes.length, 0);
  assert.equal(applyNote(saved, body, user), saved);
  assert.throws(
    () => applyNote(saved, { ...body, text: "changed" }, user),
    /Retry differs/,
  );
  assert.throws(
    () =>
      applyNote(
        saved,
        { ...body, requestId: "22222222-2222-2222-2222-222222222222" },
        user,
      ),
    /Notes changed/,
  );
});
test("handover resolution preserves author and text", () => {
  const saved = applyNote(empty(), body, user, 1000);
  const resolved = applyNote(
    saved,
    {
      requestId: "22222222-2222-2222-2222-222222222222",
      expectedRevision: 1,
      resolveId: body.requestId,
    },
    user,
    2000,
  );
  assert.equal(resolved.notes[0].resolvedAt, 2000);
  assert.equal(resolved.notes[0].text, "Check coolant");
  assert.equal(saved.notes[0].resolvedAt, undefined);
});
const express = require("express");
const { createNotesRouter } = require("../src/factory-notes");
async function harness(
  t,
  {
    auth = true,
    authority = "TENANT_ADMIN",
    type = "MACHINE",
    mismatch = false,
  } = {},
) {
  let journal = empty(),
    writes = 0;
  const headers = [];
  const ax = {
    get: async (url, options) => {
      headers.push(options.headers["X-Authorization"]);
      if (url.endsWith("/api/auth/user"))
        return { data: { ...user, authority } };
      if (url.includes("/api/assets?")) return { data: [{ type }] };
      return {
        data: [{ key: "machineNotes", value: structuredClone(journal) }],
      };
    },
    post: async (url, body, options) => {
      headers.push(options.headers["X-Authorization"]);
      writes++;
      if (!mismatch) journal = structuredClone(body.machineNotes);
      return { data: null };
    },
  };
  const app = express();
  app.use(
    createNotesRouter({
      express,
      ax,
      base: "http://tb",
      requireValidUser: async (req, res) => {
        if (!auth) {
          res.status(401).end();
          return null;
        }
        return { userToken: "caller-token" };
      },
    }),
  );
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  t.after(() => server.close());
  const path = `http://127.0.0.1:${server.address().port}/api/factory/machines/${body.requestId}/notes`;
  return {
    path,
    writes: () => writes,
    headers,
    save: (data) =>
      fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
  };
}
test("Notes routes enforce caller authority and machine type without service-token fallback", async (t) => {
  for (const options of [
    { auth: false },
    { authority: "CUSTOMER_USER" },
    { type: "OTHER" },
  ]) {
    const h = await harness(t, options);
    const result = await h.save(body);
    assert.equal(
      result.status,
      options.auth === false ? 401 : options.type ? 404 : 403,
    );
    assert.equal(h.writes(), 0);
    assert.ok(h.headers.every((v) => v === "Bearer caller-token"));
  }
  const read = await harness(t, { authority: "CUSTOMER_USER" });
  const result = await fetch(read.path);
  assert.equal(result.status, 200);
  assert.equal((await result.json()).canWrite, false);
});
test("Notes HTTP saves are verified, retry safely, and reject concurrent revision changes", async (t) => {
  const h = await harness(t);
  let result = await h.save(body);
  assert.equal(result.status, 200);
  assert.equal((await result.json()).notes[0].actorId, user.id.id);
  assert.equal((await h.save(body)).status, 200);
  assert.equal(h.writes(), 1);
  assert.equal(
    (
      await h.save({
        ...body,
        requestId: "22222222-2222-2222-2222-222222222222",
      })
    ).status,
    409,
  );
  assert.equal(h.writes(), 1);
  const bad = await harness(t, { mismatch: true });
  assert.equal((await bad.save(body)).status, 409);
});
test("Notes reject malformed journals and storage exhaustion instead of deleting history", () => {
  assert.throws(() =>
    applyNote({ ...empty(), notes: [{ id: "invalid" }] }, body, user),
  );
  const full = {
    ...empty(),
    requests: Array.from({ length: 400 }, (_, i) => ({ id: String(i) })),
  };
  assert.throws(() => applyNote(full, body, user), /storage is full/);
});
test("Generic attribute writes cannot replace audit journals, even in mixed payloads", () => {
  const { containsFactoryJournal } = require("../src/factory-attribute-policy");
  for (const value of [
    { machineNotes: {} },
    { downtimeReview: {} },
    { identity: {}, machineNotes: null },
  ])
    assert.equal(containsFactoryJournal(value), true);
  assert.equal(
    containsFactoryJournal({ identity: {}, presentation: {} }),
    false,
  );
});
