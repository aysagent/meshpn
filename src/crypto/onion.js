import { encrypt, decrypt } from './encrypt.js';

// Binary layer format (much faster than JSON+base64):
// [1 byte: flags] [16 bytes: nextHop or zeros] [rest: payload]
// flags: bit 0 = isExit, bit 1 = hasNextHop

const NODE_ID_LENGTH = 16;

function encodeNodeId(nodeId) {
  const buf = Buffer.alloc(NODE_ID_LENGTH);
  if (nodeId) {
    buf.write(nodeId.substring(0, NODE_ID_LENGTH), 0, 'utf8');
  }
  return buf;
}

function decodeNodeId(buf) {
  const str = buf.toString('utf8').replace(/\0+$/, '');
  return str || null;
}

export class OnionRouter {
  constructor(sessionManager) {
    this.sessionManager = sessionManager;
  }

  wrap(payload, route, sessionKeys = null) {
    if (route.length === 0) {
      return payload;
    }
    
    let wrapped = typeof payload === 'string' ? Buffer.from(payload) : payload;
    
    const reversedRoute = [...route].reverse();
    
    for (let i = 0; i < reversedRoute.length; i++) {
      const nodeId = reversedRoute[i];
      const key = sessionKeys 
        ? sessionKeys[nodeId] 
        : this.sessionManager.getSessionKey(nodeId);
      
      if (!key) {
        throw new Error(`No session key for node ${nodeId}`);
      }
      
      const nextHop = i === 0 ? null : reversedRoute[i - 1];
      const isExit = i === 0;
      
      // Binary format
      const flags = (isExit ? 1 : 0) | (nextHop ? 2 : 0);
      const header = Buffer.alloc(1 + NODE_ID_LENGTH);
      header.writeUInt8(flags, 0);
      encodeNodeId(nextHop).copy(header, 1);
      
      const layerData = Buffer.concat([header, wrapped]);
      wrapped = encrypt(layerData, key);
    }
    
    return wrapped;
  }

  unwrap(encryptedPayload, myKey) {
    const decrypted = decrypt(encryptedPayload, myKey);
    
    const flags = decrypted.readUInt8(0);
    const isExit = (flags & 1) !== 0;
    const hasNextHop = (flags & 2) !== 0;
    const nextHop = hasNextHop ? decodeNodeId(decrypted.subarray(1, 1 + NODE_ID_LENGTH)) : null;
    const payload = decrypted.subarray(1 + NODE_ID_LENGTH);
    
    return { nextHop, isExit, payload };
  }
}

export class OnionPacketBuilder {
  constructor() {
    this.layers = [];
  }

  addLayer(nodeId, sessionKey) {
    this.layers.push({ nodeId, sessionKey });
    return this;
  }

  build(payload) {
    let wrapped = typeof payload === 'string' ? Buffer.from(payload) : payload;
    
    const reversedLayers = [...this.layers].reverse();
    
    for (let i = 0; i < reversedLayers.length; i++) {
      const { sessionKey } = reversedLayers[i];
      const nextHop = i === 0 ? null : reversedLayers[i - 1].nodeId;
      const isExit = i === 0;
      
      // Binary format
      const flags = (isExit ? 1 : 0) | (nextHop ? 2 : 0);
      const header = Buffer.alloc(1 + NODE_ID_LENGTH);
      header.writeUInt8(flags, 0);
      encodeNodeId(nextHop).copy(header, 1);
      
      const layerData = Buffer.concat([header, wrapped]);
      wrapped = encrypt(layerData, sessionKey);
    }
    
    return wrapped;
  }

  static unwrapLayer(encryptedData, sessionKey) {
    const decrypted = decrypt(encryptedData, sessionKey);
    
    const flags = decrypted.readUInt8(0);
    const isExit = (flags & 1) !== 0;
    const hasNextHop = (flags & 2) !== 0;
    const nextHop = hasNextHop ? decodeNodeId(decrypted.subarray(1, 1 + NODE_ID_LENGTH)) : null;
    const payload = decrypted.subarray(1 + NODE_ID_LENGTH);
    
    return { nextHop, isExit, payload };
  }
}

export function createOnionPacket(payload, routeWithKeys) {
  const builder = new OnionPacketBuilder();
  
  for (const { nodeId, sessionKey } of routeWithKeys) {
    builder.addLayer(nodeId, sessionKey);
  }
  
  return builder.build(payload);
}

export function peelOnionLayer(encryptedData, sessionKey) {
  return OnionPacketBuilder.unwrapLayer(encryptedData, sessionKey);
}
