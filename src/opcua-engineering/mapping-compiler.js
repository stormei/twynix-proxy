const { fail } = require('./session-manager');
// Java regex quoting, not user-supplied regex. Only exact parent Node IDs match.
function literal(value) { return '\\Q' + value.replace(/\\E/g, '\\E\\\\E\\Q') + '\\E'; }
function compileMappings(mappings, devices) {
  const groups = new Map();
  const targets = new Map();
  for (const m of mappings.filter(m => m.enabled)) {
    if (!m.deviceId || !m.key) fail(400, `${m.displayName}: choose a device and telemetry key`);
    const match = /^ns=(\d+);[is]=(.+)$/.exec(m.parentNodeId);
    const browseName = m.subscriptionPath || m.browseName.replace(/^\d+:/, '');
    if (!match || !browseName || /[/*]/.test(browseName)) fail(400, `${m.displayName}: this browse path is not supported by the ThingsBoard adapter`);
    const device = devices.get(m.deviceId);
    if (!device?.name) fail(400, 'Target device is unavailable');
    const key = 'twx_' + m.id.replace(/-/g, '');
    if (!groups.has(m.parentNodeId)) groups.set(m.parentNodeId, { mappingType: 'ID', namespace: Number(match[1]), deviceNodePattern: literal(match[2]), subscriptionTags: [] });
    groups.get(m.parentNodeId).subscriptionTags.push({ key, path: browseName, required: false });
    if (!targets.has(m.deviceId)) targets.set(m.deviceId, { name: device.name, type: device.type || 'default', signals: [] });
    targets.get(m.deviceId).signals.push({ source: key, key: m.key });
  }
  if (!groups.size) fail(400, 'Enable at least one mapping');
  // No user script interpolation. Missing values are omitted, never defaulted.
  const decoder = `var encoded = '';\nfor (var b = 0; b < payload.length; b++) encoded += '%' + ('0' + (payload[b] & 255).toString(16)).slice(-2);\nvar data = JSON.parse(decodeURIComponent(encoded));\nvar targets = ${JSON.stringify([...targets.values()])};\nvar result = [];\nfor (var i = 0; i < targets.length; i++) {\n  var target = targets[i];\n  var values = {};\n  var count = 0;\n  for (var j = 0; j < target.signals.length; j++) {\n    var signal = target.signals[j];\n    if (Object.prototype.hasOwnProperty.call(data, signal.source) && data[signal.source] != null) {\n      values[signal.key] = data[signal.source]; count++;\n    }\n  }\n  if (count) result.push({deviceName: target.name, deviceType: target.type, attributes: {}, telemetry: values});\n}\nreturn result;`;
  return { mapping: [...groups.values()], decoder };
}
module.exports = { compileMappings };
