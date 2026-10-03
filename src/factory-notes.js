const crypto = require("node:crypto");
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
function fail(message, status = 400) {
  const e = new Error(message);
  e.status = status;
  throw e;
}
function applyNote(journal, body, user, now = Date.now()) {
  if (
    !body ||
    !UUID.test(body.requestId) ||
    !Number.isSafeInteger(body.expectedRevision) ||
    body.expectedRevision < 0
  )
    fail("Invalid note request.");
  if (
    journal.schemaVersion !== 1 ||
    !Number.isSafeInteger(journal.revision) ||
    journal.revision < 0 ||
    !Array.isArray(journal.notes)
  )
    fail("Notes need administrator review.", 409);
  if (
    journal.notes.length > 200 ||
    (journal.requests != null && !Array.isArray(journal.requests)) ||
    journal.notes.some(
      (n) =>
        !UUID.test(n.id) ||
        !["NOTE", "HANDOVER"].includes(n.kind) ||
        typeof n.text !== "string" ||
        !n.text.trim() ||
        n.text.length > 2000 ||
        !UUID.test(n.actorId) ||
        !Number.isSafeInteger(n.at),
    )
  )
    fail("Notes need administrator review.", 409);
  const prior = (journal.requests || []).find((r) => r.id === body.requestId);
  const fingerprint = crypto
    .createHash("sha256")
    .update(
      JSON.stringify({
        text: body.text,
        kind: body.kind,
        resolveId: body.resolveId,
      }),
    )
    .digest("hex");
  if (prior) {
    if (prior.fingerprint !== fingerprint || prior.actorId !== user.id.id)
      fail("Retry differs from saved request.", 409);
    return journal;
  }
  if (body.expectedRevision !== journal.revision)
    fail("Notes changed. Refresh before saving; your draft is retained.", 409);
  const next = structuredClone(journal);
  if (body.resolveId) {
    const note = next.notes.find((n) => n.id === body.resolveId);
    if (!note || note.kind !== "HANDOVER") fail("Select an existing handover.");
    if (note.resolvedAt) fail("Handover is already resolved.", 409);
    note.resolvedAt = now;
    note.resolvedActorId = user.id.id;
    note.resolvedBy = user.email || user.id.id;
  } else {
    if (
      typeof body.text !== "string" ||
      !body.text.trim() ||
      body.text.trim().length > 2000 ||
      !["NOTE", "HANDOVER"].includes(body.kind)
    )
      fail("Enter a note of up to 2000 characters.");
    if (next.notes.length >= 200)
      fail("Notes storage is full. Archive before adding more notes.", 409);
    next.notes.push({
      id: body.requestId,
      text: body.text.trim(),
      kind: body.kind,
      actorId: user.id.id,
      actorLabel: user.email || user.id.id,
      at: now,
    });
  }
  next.requests ||= [];
  if (next.requests.length >= 400)
    fail("Notes audit storage is full. Archive before continuing.", 409);
  next.requests.push({
    id: body.requestId,
    fingerprint,
    actorId: user.id.id,
    at: now,
  });
  next.revision++;
  if (Buffer.byteLength(JSON.stringify(next)) > 180000)
    fail("Notes storage is full.", 409);
  return next;
}
function createNotesRouter({ express, ax, base, requireValidUser }) {
  const router = express.Router(),
    locks = new Set();
  const path = "/api/factory/machines/:machineId/notes";
  async function context(req, res) {
    const auth = await requireValidUser(req, res);
    if (!auth) return null;
    const id = req.params.machineId;
    if (!UUID.test(id)) fail("Invalid machine ID.");
    const headers = { "X-Authorization": `Bearer ${auth.userToken}` };
    const get = async (p) => (await ax.get(base + p, { headers })).data;
    const [user, assets] = await Promise.all([
      get("/api/auth/user"),
      get("/api/assets?assetIds=" + id),
    ]);
    if (
      !Array.isArray(assets) ||
      assets.length !== 1 ||
      assets[0].type !== "MACHINE"
    )
      fail("Machine is unavailable.", 404);
    return {
      id,
      user,
      get,
      post: async (p, b) => (await ax.post(base + p, b, { headers })).data,
      path: `/api/plugins/telemetry/ASSET/${id}`,
    };
  }
  async function load(c) {
    const attrs = await c.get(
      c.path + "/values/attributes/SERVER_SCOPE?keys=machineNotes",
    );
    const raw = attrs.find((a) => a.key === "machineNotes")?.value;
    return raw === undefined
      ? { schemaVersion: 1, revision: 0, notes: [], requests: [] }
      : typeof raw === "string"
        ? JSON.parse(raw)
        : raw;
  }
  function handle(action) {
    return async (req, res) => {
      try {
        const c = await context(req, res);
        if (c) await action(c, req, res);
      } catch (e) {
        res
          .status(
            e.status ||
              (e.response && [401, 403, 404].includes(e.response.status)
                ? e.response.status
                : 502),
          )
          .json({
            error: e.status ? e.message : "Could not access machine notes.",
          });
      }
    };
  }
  router.get(
    path,
    handle(async (c, req, res) =>
      res.json({
        journal: await load(c),
        canWrite: c.user.authority === "TENANT_ADMIN",
      }),
    ),
  );
  router.post(
    path,
    express.json({ limit: "16kb" }),
    handle(async (c, req, res) => {
      if (c.user.authority !== "TENANT_ADMIN")
        fail("Notes writes currently require a tenant administrator.", 403);
      if (locks.has(c.id)) fail("Another note is saving. Try again.", 409);
      locks.add(c.id);
      try {
        const original = await load(c);
        const next = applyNote(original, req.body, c.user);
        if (next !== original)
          await c.post(c.path + "/SERVER_SCOPE", { machineNotes: next });
        const saved = await load(c);
        if (JSON.stringify(saved) !== JSON.stringify(next))
          fail("Save could not be confirmed. Retry the same request.", 409);
        res.json(saved);
      } finally {
        locks.delete(c.id);
      }
    }),
  );
  return router;
}
module.exports = { createNotesRouter, applyNote };
