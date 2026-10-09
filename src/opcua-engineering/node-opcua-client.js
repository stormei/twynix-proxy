const { OPCUAClient, AttributeIds, NodeClass, DataType, BrowseDirection, MessageSecurityMode, SecurityPolicy } = require('node-opcua-client');
const { OPCUACertificateManager } = require('node-opcua-certificate-manager');
let certificateManager;

function preview(value, depth = 0) {
  if (value == null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value === 'string') return value.length > 512 ? value.slice(0, 512) + '… [truncated]' : value;
  if (value instanceof Date) return value.toISOString();
  if (depth >= 3) return '[nested value omitted]';
  if (Buffer.isBuffer(value)) return { bytes: value.length, hex: value.subarray(0, 32).toString('hex'), truncated: value.length > 32 };
  if (Array.isArray(value) || ArrayBuffer.isView(value)) return { length: value.length, values: Array.from(value).slice(0, 20).map(v => preview(v, depth + 1)), truncated: value.length > 20 };
  if (typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 20).map(([k, v]) => [k, preview(v, depth + 1)]));
  return String(value);
}

function createReadOnlyClient(connection) {
  certificateManager ||= new OPCUACertificateManager({
    rootFolder: process.env.OPCUA_PKI_DIR || '/app/data/opcua-pki', automaticallyAcceptUnknownCertificate: false
  });
  const client = OPCUAClient.create({ applicationName: 'Twynix read-only discovery',
    endpointMustExist: true, securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None,
    connectionStrategy: { maxRetry: 0 }, keepSessionAlive: false, requestedSessionTimeout: 60000,
    defaultTransactionTimeout: 8000, transportSettings: { maxMessageSize: 1048576, maxChunkCount: 32 },
    clientCertificateManager: certificateManager });
  let session;
  let closed = false;
  let namespaces = [];
  function active() { if (closed || !session) throw new Error('Discovery transport closed'); }
  function identity(node) {
    return { nodeId: node.toString(), namespaceUri: namespaces[node.namespace] || null };
  }
  const close = async () => {
    closed = true;
    // Closing the session releases all server continuation points.
    try { if (session) await session.close(); } catch { /* disconnect remains mandatory */ }
    finally { await client.disconnect().catch(() => {}); }
  };
  return {
    async open() {
      try {
        await client.connect(connection.endpoint);
        if (closed) throw new Error('Discovery cancelled');
        // Never follow a different advertised endpoint or silently weaken security.
        session = await client.createSession();
        if (closed) throw new Error('Discovery cancelled');
        session.requestedMaxReferencesPerNode = 100;
        const data = await session.read({ nodeId: 'ns=0;i=2255', attributeId: AttributeIds.Value });
        if (!data.statusCode.isGood() || !Array.isArray(data.value.value)) throw new Error('Namespace table unavailable');
        namespaces = data.value.value;
        return namespaces;
      } catch (error) { await close(); throw error; }
    },
    async browse(nodeId, continuationPoint) {
      active();
      const result = continuationPoint ? await session.browseNext(continuationPoint, false) : await session.browse({ nodeId,
        referenceTypeId: 'HierarchicalReferences', browseDirection: BrowseDirection.Forward, includeSubtypes: true, resultMask: 63 });
      if (!result.statusCode.isGood()) throw new Error('Browse failed');
      if ((result.references || []).length > 100) throw new Error('Server exceeded browse limit');
      return { continuationPoint: result.continuationPoint, nodes: (result.references || []).filter(r => !r.nodeId.serverIndex).map(r => ({
        ...identity(r.nodeId), displayName: r.displayName.text || r.browseName.name,
        browseName: r.browseName.toString(), nodeClass: NodeClass[r.nodeClass]
      })) };
    },
    async inspect(nodeIds) {
      active();
      const attributes = ['NodeClass', 'DataType', 'ValueRank', 'UserAccessLevel', 'Value', 'Description'];
      const values = await session.read(nodeIds.flatMap(nodeId => attributes.map(key => ({ nodeId, attributeId: AttributeIds[key] }))));
      return nodeIds.map((nodeId, index) => ({ nodeId, attributes: Object.fromEntries(attributes.map((key, offset) => {
        const data = values[index * attributes.length + offset];
        let value = data.value.value;
        if (key === 'NodeClass') value = NodeClass[value] || value;
        if (key === 'DataType' && value) value = value.namespace === 0 ? (DataType[value.value] || value.toString()) : value.toString();
        if (key === 'Description') value = value?.text || null;
        if (key === 'UserAccessLevel' && typeof value === 'number') value = { read: !!(value & 1), write: !!(value & 2) };
        return [key, { status: data.statusCode.toString(), value: data.statusCode.isGood() ? preview(value) : null,
          sourceTimestamp: data.sourceTimestamp?.toISOString() || null, serverTimestamp: data.serverTimestamp?.toISOString() || null }];
      })) }));
    },
    close
  };
}
module.exports = { createReadOnlyClient, preview };
