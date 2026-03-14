import { EventEmitter } from 'events';
import { randomBytes } from 'crypto';

export class MultipathScheduler extends EventEmitter {
  constructor(config = {}) {
    super();
    this.paths = [];
    this.pathWeights = new Map();
    this.currentPathIndex = 0;
    this.sequenceNumber = 0;
    this.flowId = config.flowId || randomBytes(8).toString('hex');
    this.strategy = config.strategy || 'round-robin';
    this.pathStats = new Map();
  }

  setPaths(paths) {
    this.paths = paths;
    this.pathWeights.clear();
    this.pathStats.clear();
    
    for (let i = 0; i < paths.length; i++) {
      const pathKey = this._getPathKey(paths[i]);
      this.pathWeights.set(pathKey, 1);
      this.pathStats.set(pathKey, {
        sent: 0,
        acked: 0,
        lost: 0,
        latency: []
      });
    }
    
    this.emit('paths-updated', paths);
  }

  addPath(path) {
    const pathKey = this._getPathKey(path);
    if (!this.pathWeights.has(pathKey)) {
      this.paths.push(path);
      this.pathWeights.set(pathKey, 1);
      this.pathStats.set(pathKey, {
        sent: 0,
        acked: 0,
        lost: 0,
        latency: []
      });
      this.emit('path-added', path);
    }
  }

  removePath(path) {
    const pathKey = this._getPathKey(path);
    const index = this.paths.findIndex(p => this._getPathKey(p) === pathKey);
    if (index !== -1) {
      this.paths.splice(index, 1);
      this.pathWeights.delete(pathKey);
      this.pathStats.delete(pathKey);
      if (this.currentPathIndex >= this.paths.length) {
        this.currentPathIndex = 0;
      }
      this.emit('path-removed', path);
    }
  }

  selectPath() {
    if (this.paths.length === 0) {
      return null;
    }
    
    switch (this.strategy) {
      case 'round-robin':
        return this._selectRoundRobin();
      case 'weighted':
        return this._selectWeighted();
      case 'lowest-latency':
        return this._selectLowestLatency();
      default:
        return this._selectRoundRobin();
    }
  }

  _selectRoundRobin() {
    const path = this.paths[this.currentPathIndex];
    this.currentPathIndex = (this.currentPathIndex + 1) % this.paths.length;
    return path;
  }

  _selectWeighted() {
    const totalWeight = Array.from(this.pathWeights.values()).reduce((a, b) => a + b, 0);
    let random = Math.random() * totalWeight;
    
    for (const path of this.paths) {
      const weight = this.pathWeights.get(this._getPathKey(path)) || 1;
      random -= weight;
      if (random <= 0) {
        return path;
      }
    }
    
    return this.paths[0];
  }

  _selectLowestLatency() {
    let bestPath = this.paths[0];
    let lowestAvgLatency = Infinity;
    
    for (const path of this.paths) {
      const stats = this.pathStats.get(this._getPathKey(path));
      if (stats && stats.latency.length > 0) {
        const avgLatency = stats.latency.reduce((a, b) => a + b, 0) / stats.latency.length;
        if (avgLatency < lowestAvgLatency) {
          lowestAvgLatency = avgLatency;
          bestPath = path;
        }
      }
    }
    
    return bestPath;
  }

  schedulePacket(payload) {
    const path = this.selectPath();
    if (!path) {
      return null;
    }
    
    const packet = {
      flowId: this.flowId,
      seq: this.sequenceNumber++,
      path,
      payload,
      timestamp: Date.now()
    };
    
    const pathKey = this._getPathKey(path);
    const stats = this.pathStats.get(pathKey);
    if (stats) {
      stats.sent++;
    }
    
    return packet;
  }

  schedulePacketMultipath(payload, pathCount = 2) {
    if (this.paths.length === 0) {
      return [];
    }
    
    const packets = [];
    const usedPaths = new Set();
    const seq = this.sequenceNumber++;
    
    for (let i = 0; i < Math.min(pathCount, this.paths.length); i++) {
      let path;
      let attempts = 0;
      
      do {
        path = this.selectPath();
        attempts++;
      } while (usedPaths.has(this._getPathKey(path)) && attempts < this.paths.length * 2);
      
      if (path) {
        usedPaths.add(this._getPathKey(path));
        packets.push({
          flowId: this.flowId,
          seq,
          pathIndex: i,
          totalPaths: Math.min(pathCount, this.paths.length),
          path,
          payload,
          timestamp: Date.now()
        });
        
        const pathKey = this._getPathKey(path);
        const stats = this.pathStats.get(pathKey);
        if (stats) {
          stats.sent++;
        }
      }
    }
    
    return packets;
  }

  recordAck(pathKey, latency) {
    const stats = this.pathStats.get(pathKey);
    if (stats) {
      stats.acked++;
      stats.latency.push(latency);
      
      if (stats.latency.length > 100) {
        stats.latency.shift();
      }
      
      this._adjustWeight(pathKey);
    }
  }

  recordLoss(pathKey) {
    const stats = this.pathStats.get(pathKey);
    if (stats) {
      stats.lost++;
      this._adjustWeight(pathKey);
    }
  }

  _adjustWeight(pathKey) {
    const stats = this.pathStats.get(pathKey);
    if (!stats) return;
    
    const deliveryRate = stats.sent > 0 
      ? stats.acked / stats.sent 
      : 1;
    
    const avgLatency = stats.latency.length > 0
      ? stats.latency.reduce((a, b) => a + b, 0) / stats.latency.length
      : 100;
    
    const weight = Math.max(0.1, deliveryRate * (1000 / (avgLatency + 100)));
    this.pathWeights.set(pathKey, weight);
  }

  _getPathKey(path) {
    if (path.route) {
      return `${path.route.join('-')}:${path.exitNode}`;
    }
    return JSON.stringify(path);
  }

  getPathStats() {
    const result = [];
    for (const path of this.paths) {
      const pathKey = this._getPathKey(path);
      const stats = this.pathStats.get(pathKey);
      const weight = this.pathWeights.get(pathKey);
      result.push({
        path,
        weight,
        stats
      });
    }
    return result;
  }

  getActivePaths() {
    return this.paths.filter(path => {
      const stats = this.pathStats.get(this._getPathKey(path));
      if (!stats) return true;
      return stats.sent === 0 || (stats.acked / stats.sent) > 0.5;
    });
  }

  reset() {
    this.sequenceNumber = 0;
    this.currentPathIndex = 0;
    this.flowId = randomBytes(8).toString('hex');
    
    for (const [key] of this.pathStats) {
      this.pathStats.set(key, {
        sent: 0,
        acked: 0,
        lost: 0,
        latency: []
      });
    }
  }
}

export class ReorderBuffer extends EventEmitter {
  constructor(config = {}) {
    super();
    this.buffer = new Map();
    this.expectedSeq = 0;
    this.windowSize = config.windowSize || 1000;
    this.timeout = config.timeout || 5000;
    this.cleanupInterval = null;
    this.seenMultipath = new Map();
  }

  start() {
    this.cleanupInterval = setInterval(() => {
      this._cleanup();
    }, 1000);
  }

  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  addPacket(packet) {
    const { flowId, seq, payload, pathIndex, totalPaths } = packet;
    
    if (totalPaths && totalPaths > 1) {
      const key = `${flowId}:${seq}`;
      if (this.seenMultipath.has(key)) {
        return;
      }
      this.seenMultipath.set(key, Date.now());
    }
    
    if (seq < this.expectedSeq) {
      return;
    }
    
    if (seq >= this.expectedSeq + this.windowSize) {
      this.expectedSeq = seq - this.windowSize + 1;
      this._flushOld();
    }
    
    if (seq === this.expectedSeq) {
      this.emit('packet', payload, packet);
      this.expectedSeq++;
      this._flushConsecutive();
    } else {
      this.buffer.set(seq, {
        payload,
        packet,
        timestamp: Date.now()
      });
    }
  }

  _flushConsecutive() {
    while (this.buffer.has(this.expectedSeq)) {
      const entry = this.buffer.get(this.expectedSeq);
      this.buffer.delete(this.expectedSeq);
      this.emit('packet', entry.payload, entry.packet);
      this.expectedSeq++;
    }
  }

  _flushOld() {
    for (const [seq] of this.buffer) {
      if (seq < this.expectedSeq) {
        this.buffer.delete(seq);
      }
    }
  }

  _cleanup() {
    const now = Date.now();
    
    for (const [seq, entry] of this.buffer) {
      if (now - entry.timestamp > this.timeout) {
        this.buffer.delete(seq);
        this.emit('timeout', seq, entry.packet);
        
        if (seq === this.expectedSeq) {
          this.expectedSeq++;
          this._flushConsecutive();
        }
      }
    }
    
    for (const [key, timestamp] of this.seenMultipath) {
      if (now - timestamp > this.timeout * 2) {
        this.seenMultipath.delete(key);
      }
    }
  }

  getBufferSize() {
    return this.buffer.size;
  }

  getExpectedSeq() {
    return this.expectedSeq;
  }

  reset() {
    this.buffer.clear();
    this.expectedSeq = 0;
    this.seenMultipath.clear();
  }
}
