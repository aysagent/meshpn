import { encrypt, decrypt } from './encrypt.js';

// Binary layer format:
// - 1 byte: flags (bit 0 = isExit, bit 1 = hasNextHop)
// - 16 bytes: nextHop nodeId (only if hasNextHop = 1, padded/truncated)
// - rest: payload (raw binary)
const FLAG_IS_EXIT = 0x01;
const FLAG_HAS_NEXT_HOP = 0x02;
const NODE_ID_SIZE = 16;

function encodeLayer(nextHop, isExit, payload) {
  let flags = 0;
  if (isExit) flags |= FLAG_IS_EXIT;
  if (nextHop) flags |= FLAG_HAS_NEXT_HOP;
  
  const headerSize = 1 + (nextHop ? NODE_ID_SIZE : 0);
  const layer = Buffer.alloc(headerSize + payload.length);
  
  let offset = 0;
  layer.writeUInt8(flags, offset++);
  
  if (nextHop) {
    const nodeIdBuf = Buffer.from(nextHop.padEnd(NODE_ID_SIZE, '\0').slice(0, NODE_ID_SIZE));
    nodeIdBuf.copy(layer, offset);
    offset += NODE_ID_SIZE;
  }
  
  payload.copy(layer, offset);
  return layer;
}

function decodeLayer(data) {
  let offset = 0;
  const flags = data.readUInt8(offset++);
  
  const isExit = !!(flags & FLAG_IS_EXIT);
  const hasNextHop = !!(flags & FLAG_HAS_NEXT_HOP);
  
  let nextHop = null;
  if (hasNextHop) {
    nextHop = data.subarray(offset, offset + NODE_ID_SIZE).toString().replace(/\0/g, '');
    offset += NODE_ID_SIZE;
  }
  
  const payload = data.subarray(offset);
  
  return { nextHop, isExit, payload };
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
      const layer = encodeLayer(nextHop, isExit, wrapped);
      
      wrapped = encrypt(layer, key);
    }
    
    return wrapped;
  }

  unwrap(encryptedPayload, myKey) {
    const decrypted = decrypt(encryptedPayload, myKey);
    return decodeLayer(decrypted);
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
      
      const layer = encodeLayer(nextHop, isExit, wrapped);
      wrapped = encrypt(layer, sessionKey);
    }
    
    return wrapped;
  }

  static unwrapLayer(encryptedData, sessionKey) {
    const decrypted = decrypt(encryptedData, sessionKey);
    return decodeLayer(decrypted);
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
