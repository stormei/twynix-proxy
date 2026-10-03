// Audit journals may only be written through caller-verified append-only endpoints.
function containsFactoryJournal(body) {
  return (
    !!body &&
    typeof body === "object" &&
    ["downtimeReview", "machineNotes"].some((key) =>
      Object.prototype.hasOwnProperty.call(body, key),
    )
  );
}
module.exports = { containsFactoryJournal };
