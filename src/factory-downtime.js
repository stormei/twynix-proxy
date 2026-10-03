"use strict";
const { createHash, randomUUID } = require("node:crypto");
const spec = require("./factory-downtime-spec.json");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const REASONS = ["MAINTENANCE", "MATERIAL", "SETUP", "BREAKDOWN", "OTHER"];
const hash = (x) =>
  createHash("sha256").update(JSON.stringify(x)).digest("hex");
function fail(message, status = 400) {
  throw Object.assign(new Error(message), { status });
}
function decode(x) {
  return typeof x === "string" ? JSON.parse(x) : x;
}
function annotation(body, period, user, now) {
  if (
    !body ||
    Object.keys(body).some(
      (k) =>
        ![
          "eventId",
          "expectedRevision",
          "reasonId",
          "note",
          "requestId",
        ].includes(k),
    )
  )
    fail("Invalid reason request.");
  if (
    !UUID.test(body.requestId || "") ||
    !Number.isInteger(body.expectedRevision) ||
    body.expectedRevision < 0
  )
    fail("Invalid revision.");
  const event = period.events.find((e) => e.id === body.eventId);
  if (!event) fail("Downtime event was not found.", 404);
  if (body.reasonId !== null && !REASONS.includes(body.reasonId))
    fail("Choose a valid downtime reason.");
  if (
    typeof body.note !== "string" ||
    body.note.length > 500 ||
    /[\x00-\x08\x0b-\x1f]/.test(body.note)
  )
    fail("Note must be at most 500 characters.");
  const prior = period.history.filter((r) => r.eventId === event.id);
  if (prior.length !== body.expectedRevision)
    fail("This reason changed. Refresh before saving.", 409);
  return {
    eventId: event.id,
    revision: prior.length + 1,
    reasonId: body.reasonId,
    note: body.note.trim(),
    requestId: body.requestId,
    actorId: user.id.id,
    actorLabel: user.email || user.firstName || user.id.id,
    at: now,
  };
}
function validateEvents(events, report) {
  if (
    !Array.isArray(events) ||
    events.length > 2000 ||
    ["IDLE", "STOPPED", "SETUP", "FAULT"].some(
      (s) => !Number.isFinite(report.stateSeconds?.[s]),
    )
  )
    fail("Invalid downtime result.", 502);
  let last = report.periodStart;
  const states = { IDLE: 0, STOPPED: 0, SETUP: 0, FAULT: 0 };
  for (const e of events) {
    if (
      !Object.hasOwn(states, e.state) ||
      !Number.isSafeInteger(e.start) ||
      !Number.isSafeInteger(e.end) ||
      e.start < last ||
      e.end <= e.start ||
      e.end > report.periodEnd
    )
      fail("Invalid downtime event boundaries.", 502);
    states[e.state] += (e.end - e.start) / 1000;
    last = e.end;
  }
  for (const s of Object.keys(states))
    if (Math.abs(states[s] - report.stateSeconds[s]) > 0.01)
      fail(
        "Recorded history no longer matches the finalized report. No downtime detail was saved.",
        409,
      );
  return events.map((e) => ({
    ...e,
    id: hash([report.periodId, report.reportRevision, e.start, e.end, e.state]),
    seconds: (e.end - e.start) / 1000,
  }));
}
function createDowntimeRouter({ express, ax, base, requireValidUser }) {
  const router = express.Router();
  const locks = new Set();
  const prefix = "/api/factory/machines/:machineId/downtime";
  async function context(req, res) {
    const auth = await requireValidUser(req, res);
    if (!auth) return null;
    const id = String(req.params.machineId).toLowerCase();
    if (!UUID.test(id)) fail("Invalid machine ID.");
    const headers = { "X-Authorization": `Bearer ${auth.userToken}` };
    const get = async (path) => (await ax.get(base + path, { headers })).data;
    const post = async (path, body) =>
      (await ax.post(base + path, body, { headers })).data;
    const [user, asset] = await Promise.all([
      get("/api/auth/user"),
      get("/api/assets?assetIds=" + id),
    ]);
    if (
      !Array.isArray(asset) ||
      asset.length !== 1 ||
      asset[0].type !== "MACHINE"
    )
      fail("Select a MACHINE asset.");
    if (user.authority !== "TENANT_ADMIN")
      fail("Downtime review currently requires a tenant administrator.", 403);
    return { id, user, get, post, path: `/api/plugins/telemetry/ASSET/${id}` };
  }
  async function load(c) {
    const attrs = await c.get(
      c.path + "/values/attributes/SERVER_SCOPE?keys=downtimeReview",
    );
    const value = attrs.find((a) => a.key === "downtimeReview")?.value;
    const journal =
      value == null
        ? { schemaVersion: 1, revision: 0, periods: [] }
        : decode(value);
    if (
      journal.schemaVersion !== 1 ||
      !Number.isInteger(journal.revision) ||
      !Array.isArray(journal.periods)
    )
      fail("Downtime review storage needs administrator review.", 409);
    return journal;
  }
  async function save(c, j) {
    j.revision++;
    if (Buffer.byteLength(JSON.stringify(j)) > 180000)
      fail(
        "Downtime review storage is full. Archive it before adding more records.",
        409,
      );
    await c.post(c.path + "/SERVER_SCOPE", { downtimeReview: j });
    if (hash(await load(c)) !== hash(j))
      fail("Save could not be confirmed. Refresh before retrying.", 409);
  }
  async function execute(c, expression, msg, metadata) {
    const now = Date.now();
    const r = await c.post("/api/calculatedField/testScript", {
      expression:
        'var msg=JSON.parse(body);var metadata=JSON.parse(meta);var msgType="TEST";\n' +
        expression,
      arguments: {
        body: { type: "SINGLE_VALUE", ts: now, value: JSON.stringify(msg) },
        meta: {
          type: "SINGLE_VALUE",
          ts: now,
          value: JSON.stringify(metadata),
        },
      },
    });
    if (r.error)
      fail(
        "ThingsBoard downtime calculation failed: " +
          String(r.error).slice(0, 300),
        502,
      );
    return decode(r.output);
  }
  async function finalized(c, date) {
    const midnight = Date.parse(date + "T00:00:00Z");
    if (
      !Number.isFinite(midnight) ||
      new Date(midnight).toISOString().slice(0, 10) !== date
    )
      fail("Invalid report date.");
    const raw = await c.get(
      c.path +
        `/values/timeseries?keys=availabilityDailyReport&startTs=${midnight - 86400000}&endTs=${midnight + 172800000}&agg=NONE&orderBy=DESC&limit=4`,
    );
    const reports = (raw.availabilityDailyReport || [])
      .map((p) => ({ r: decode(p.value), ts: p.ts }))
      .filter((p) => p.r.periodId === date);
    if (reports.length !== 1)
      fail("One finalized daily report is required.", 409);
    const { r, ts } = reports[0];
    const states = ["RUNNING", "IDLE", "STOPPED", "SETUP", "FAULT"];
    if (
      r.schemaVersion !== 1 ||
      !Number.isInteger(r.reportRevision) ||
      r.reportRevision < 1 ||
      !Number.isSafeInteger(r.periodStart) ||
      !Number.isSafeInteger(r.periodEnd) ||
      r.periodEnd <= r.periodStart ||
      !Number.isFinite(r.finalizedAt) ||
      r.finalizedAt !== r.calculatedAt ||
      r.finalizedAt < r.periodEnd + 300000 ||
      [
        "scheduledSeconds",
        "uptimeSeconds",
        "downtimeSeconds",
        "unknownSeconds",
      ].some((k) => !Number.isFinite(r[k]) || r[k] < 0) ||
      states.some(
        (k) => !Number.isFinite(r.stateSeconds?.[k]) || r.stateSeconds[k] < 0,
      ) ||
      Math.abs(
        r.scheduledSeconds -
          r.uptimeSeconds -
          r.downtimeSeconds -
          r.unknownSeconds,
      ) > 0.01 ||
      Math.abs(r.stateSeconds.RUNNING - r.uptimeSeconds) > 0.01 ||
      Math.abs(
        states.slice(1).reduce((n, k) => n + r.stateSeconds[k], 0) -
          r.downtimeSeconds,
      ) > 0.01
    )
      fail("The finalized report failed validation.", 409);

    if (
      r.finalized !== true ||
      r.finalizerVersion !== 1 ||
      r.pendingSeconds !== 0 ||
      r.checkpoint ||
      ts !== r.periodEnd - 1 ||
      !Number.isFinite(r.maxSampleAgeSeconds) ||
      r.calculationVersion !== 2
    )
      fail("The finalized report is incompatible with downtime review.", 409);
    return r;
  }
  const view = (j) => ({
    schemaVersion: 1,
    revision: j.revision,
    periods: j.periods.map(({ progress, completedEvents, ...p }) => ({
      ...p,
      processedThrough: progress?.checkpoint?.cursorTs,
    })),
  });
  const handle = (write, fn) => async (req, res) => {
    let key;
    try {
      const c = await context(req, res);
      if (!c) return;
      if (write) {
        if (locks.has(c.id))
          fail("Another review operation is in progress. Try again.", 409);
        key = c.id;
        locks.add(key);
      }
      const j = await load(c);
      await fn(req, c, j);
      res.json(view(j));
    } catch (e) {
      res.status(e.status || e.response?.status || 502).json({
        error: e.status
          ? e.message
          : "ThingsBoard could not complete downtime review.",
      });
    } finally {
      if (key) locks.delete(key);
    }
  };
  router.get(
    prefix,
    handle(false, async () => {}),
  );
  router.post(
    prefix + "/:periodId/prepare",
    express.json({ limit: "2kb" }),
    handle(true, async (req, c, j) => {
      if (!DAY.test(req.params.periodId)) fail("Invalid report date.");
      const date = req.params.periodId;
      const r = await finalized(c, date);
      const fingerprint = hash(r);
      let period = j.periods.find((p) => p.periodId === date);
      if (period && period.reportFingerprint !== fingerprint)
        fail(
          "The report revision changed. Existing reason records were preserved for review.",
          409,
        );
      if (period?.status === "READY") return;
      const attrs = await c.get(
        c.path + "/values/attributes/SERVER_SCOPE?keys=productionCalendar",
      );
      const calendar = attrs.find((a) => a.key === "productionCalendar")?.value;
      if (!calendar) fail("A saved production calendar is required.", 409);
      const encoded = JSON.stringify(decode(calendar));
      if (period && period.calendarFingerprint !== hash(decode(calendar)))
        fail(
          "The calendar changed during processing. Restart review after administrator inspection.",
          409,
        );
      // Transport only completed server-produced intervals outside the TBEL checkpoint.
      // Carry its last interval so TBEL can merge a continuation across batches.
      if (period?.progress?.checkpoint?.events?.length > 1) {
        const emitted = period.progress.checkpoint.events;
        period.completedEvents = (period.completedEvents || []).concat(
          emitted.slice(0, -1),
        );
        period.progress.checkpoint.events = emitted.slice(-1);
      }
      const previous = period?.progress || {
        finalizerVersion: 1,
        finalized: false,
        periodId: date,
      };
      const p = await execute(
        c,
        spec.prepare,
        { runTs: r.finalizedAt, maxSampleAgeSeconds: r.maxSampleAgeSeconds },
        {
          ss_productionCalendar: encoded,
          availabilityDailyCheckpoint: JSON.stringify(previous),
        },
      );
      if (
        p.msgType !== "FACTORY_AVAILABILITY_QUERY" ||
        p.msg.periodId !== date ||
        p.msg.periodStart !== r.periodStart ||
        p.msg.periodEnd !== r.periodEnd ||
        p.msg.calendarRevision !== r.calendarRevision ||
        Math.abs(p.msg.plannedMs / 1000 - r.scheduledSeconds) > 0.01
      )
        fail("The saved calendar no longer matches this finalized day.", 409);
      const history = await c.get(
        c.path +
          `/values/timeseries?keys=machineState&startTs=${p.metadata.fromTs}&endTs=${p.metadata.toTs}&agg=NONE&orderBy=ASC&limit=1000`,
      );
      p.metadata.machineState = JSON.stringify(history.machineState || []);
      const result = await execute(c, spec.integrate, p.msg, p.metadata);
      const values = result.msg?.values;
      if (!values?.availabilityDailyCheckpoint)
        fail("ThingsBoard returned an invalid downtime calculation.", 502);
      if (!period) {
        if (j.periods.length >= 62)
          fail(
            "Downtime review storage is full. Archive it before adding more days.",
            409,
          );
        period = {
          periodId: date,
          reportFingerprint: fingerprint,
          calendarFingerprint: hash(decode(calendar)),
          reportRevision: r.reportRevision,
          calendarRevision: r.calendarRevision,
          timezone: r.timezone,
          periodStart: r.periodStart,
          periodEnd: r.periodEnd,
          downtimeSeconds: r.downtimeSeconds,
          status: "PROCESSING",
          events: [],
          history: [],
          preparedBy: c.user.id.id,
          preparedAt: Date.now(),
        };
        j.periods.push(period);
      }
      if (values.availabilityDailyReport) {
        const computed = values.availabilityDailyReport;
        for (const k of [
          "scheduledSeconds",
          "uptimeSeconds",
          "downtimeSeconds",
          "unknownSeconds",
        ])
          if (Math.abs(computed[k] - r[k]) > 0.01)
            fail(
              "Recorded history no longer matches the finalized report. No downtime detail was saved.",
              409,
            );
        period.events = validateEvents(
          (period.completedEvents || []).concat(computed.downtimeEvents),
          r,
        );
        period.status = "READY";
        delete period.progress;
        delete period.completedEvents;
      } else {
        period.progress = values.availabilityDailyCheckpoint;
        const emitted = period.progress.checkpoint.events || [];
        period.completedEvents = (period.completedEvents || []).concat(
          emitted.slice(0, -1),
        );
        period.progress.checkpoint.events = emitted.slice(-1);
        if (period.completedEvents.length + emitted.slice(-1).length > 2000)
          fail("Downtime event limit reached.", 409);
      }
      await save(c, j);
    }),
  );
  router.post(
    prefix + "/:periodId/reason",
    express.json({ limit: "4kb" }),
    handle(true, async (req, c, j) => {
      const p = j.periods.find((p) => p.periodId === req.params.periodId);
      if (!p || p.status !== "READY")
        fail("Prepare finalized downtime detail first.", 409);
      if (hash(await finalized(c, p.periodId)) !== p.reportFingerprint)
        fail(
          "The finalized report changed. Existing annotations were preserved.",
          409,
        );
      const duplicate = p.history.find(
        (r) => r.requestId === req.body?.requestId,
      );
      if (duplicate) {
        if (
          duplicate.eventId !== req.body.eventId ||
          duplicate.reasonId !== req.body.reasonId ||
          duplicate.note !== req.body.note?.trim()
        )
          fail("Request ID already used.", 409);
        return;
      }
      p.history.push(annotation(req.body, p, c.user, Date.now()));
      await save(c, j);
    }),
  );
  return router;
}
module.exports = { createDowntimeRouter, annotation, validateEvents, REASONS };
