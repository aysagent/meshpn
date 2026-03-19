import { encrypt, decrypt } from './encrypt.js';

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
      
      const layer = {
        nextHop: i === 0 ? null : reversedRoute[i - 1],
        isExit: i === 0,
        payload: wrapped.toString('base64')
      };
      
      wrapped = encrypt(JSON.stringify(layer), key);
    }
    
    return wrapped;
  }

  unwrap(encryptedPayload, myKey) {
    const decrypted = decrypt(encryptedPayload, myKey);
    const layer = JSON.parse(decrypted.toString('utf8'));
    
    return {
      nextHop: layer.nextHop,
      isExit: layer.isExit,
      payload: Buffer.from(layer.payload, 'base64')
    };
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
      const { nodeId, sessionKey } = reversedLayers[i];
      const nextHop = i === 0 ? null : reversedLayers[i - 1].nodeId;
      
      const layer = {
        nextHop,
        isExit: i === 0,
        payload: wrapped.toString('base64')
      };
      
      wrapped = encrypt(JSON.stringify(layer), sessionKey);
    }
    
    return wrapped;
  }

  static unwrapLayer(encryptedData, sessionKey) {
    const decrypted = decrypt(encryptedData, sessionKey);
    const layer = JSON.parse(decrypted.toString('utf8'));
    
    return {
      nextHop: layer.nextHop,
      isExit: layer.isExit,
      payload: Buffer.from(layer.payload, 'base64')
    };
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
