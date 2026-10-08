"use strict";
const { gzipSync, gunzipSync } = require("node:zlib");
const STORED_LIMIT = 180000;
const EXPANDED_LIMIT = 2 * 1024 * 1024;
function storageError(message) {
  throw Object.assign(new Error(message), { status: 409 });
}
function decodeJournal(value) {
  const raw = typeof value === "string" ? JSON.parse(value) : value;
  if (raw?.schemaVersion !== 2) return raw;
  if (raw.encoding !== "gzip-base64" || typeof raw.data !== "string" ||
      Buffer.byteLength(JSON.stringify(raw)) > STORED_LIMIT ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(raw.data))
    storageError("Downtime review storage is invalid. Saved records were retained.");
  try {
    const expanded = gunzipSync(Buffer.from(raw.data, "base64"), { maxOutputLength: EXPANDED_LIMIT });
    const journal = JSON.parse(expanded.toString("utf8"));
    if (journal?.schemaVersion !== 1) throw new Error("Invalid journal version.");
    return journal;
  } catch {
    storageError("Downtime review storage could not be decoded. Saved records were retained.");
  }
}
function encodeJournal(journal) {
  const json = JSON.stringify(journal);
  if (Buffer.byteLength(json) > EXPANDED_LIMIT)
    storageError("Downtime review storage is full (expanded journal limit). Saved records were retained.");
  // Keep small legacy journals readable; migrate losslessly only when necessary.
  if (Buffer.byteLength(json) <= STORED_LIMIT) return journal;
  const encoded = { schemaVersion: 2, encoding: "gzip-base64", data: gzipSync(json).toString("base64") };
  if (Buffer.byteLength(JSON.stringify(encoded)) > STORED_LIMIT)
    storageError("Downtime review storage is full (compressed journal limit). Saved records were retained.");
  return encoded;
}
module.exports = { decodeJournal, encodeJournal, STORED_LIMIT, EXPANDED_LIMIT };
