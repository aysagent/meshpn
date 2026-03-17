import { EventEmitter } from 'events';

export class NATTable extends EventEmitter {
  constructor(config = {}) {
    super();
    this.entries = new Map();
    this.timeout = config.timeout || 300000;
    this.cleanupInterval = null;
  }

  start() {
    this.cleanupInterval = setInterval(() => {
      this._cleanup();
    }, 60000);
  }

  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.entries.clear();
  }

  createMapping(srcNodeId, srcIp, srcPort, dstIp, dstPort, protocol) {
    const key = `${srcIp}:${srcPort}:${dstIp}:${dstPort}:${protocol}`;
    
    let entry = this.entries.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
      return entry;
    }
    
    entry = {
      key,
      srcNodeId,
      srcIp,
      srcPort,
      dstIp,
      dstPort,
      protocol,
      createdAt: Date.now(),
      lastUsed: Date.now()
    };
    
    this.entries.set(key, entry);
    this.emit('mapping-created', entry);
    
    return entry;
  }

  findMapping(key) {
    const entry = this.entries.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
    }
    return entry;
  }

  findByResponse(dstIp, dstPort, srcIp, srcPort, protocol) {
    const key = `${dstIp}:${dstPort}:${srcIp}:${srcPort}:${protocol}`;
    return this.findMapping(key);
  }

  removeMapping(key) {
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      this.emit('mapping-removed', entry);
    }
  }

  _cleanup() {
    const now = Date.now();
    const expired = [];
    
    for (const [key, entry] of this.entries) {
      if (now - entry.lastUsed > this.timeout) {
        expired.push(key);
      }
    }
    
    for (const key of expired) {
      this.removeMapping(key);
    }
    
    if (expired.length > 0) {
      this.emit('cleanup', expired.length);
    }
  }

  getStats() {
    return {
      totalMappings: this.entries.size
    };
  }
}
