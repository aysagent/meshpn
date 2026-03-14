import { EventEmitter } from 'events';

export class VirtualIPManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this.networkBase = config.networkBase || '10.200.0';
    this.networkCidr = config.networkCidr || '10.200.0.0/16';
    this.nextIp = config.startIp || 2;
    this.maxIp = config.maxIp || 65534;
    this.allocations = new Map();
    this.nodeToIp = new Map();
    this.reservedIps = new Set([1, 255]);
  }

  allocate(nodeId) {
    if (this.nodeToIp.has(nodeId)) {
      return this.nodeToIp.get(nodeId);
    }
    
    let ip = null;
    
    while (this.nextIp <= this.maxIp) {
      const candidateIp = this._formatIp(this.nextIp);
      this.nextIp++;
      
      if (!this.allocations.has(candidateIp) && !this.reservedIps.has(this.nextIp - 1)) {
        ip = candidateIp;
        break;
      }
    }
    
    if (!ip) {
      throw new Error('No available IP addresses');
    }
    
    this.allocations.set(ip, {
      nodeId,
      allocatedAt: Date.now()
    });
    this.nodeToIp.set(nodeId, ip);
    
    this.emit('allocated', { nodeId, ip });
    
    return ip;
  }

  release(nodeId) {
    const ip = this.nodeToIp.get(nodeId);
    if (!ip) {
      return false;
    }
    
    this.allocations.delete(ip);
    this.nodeToIp.delete(nodeId);
    
    this.emit('released', { nodeId, ip });
    
    return true;
  }

  getIpForNode(nodeId) {
    return this.nodeToIp.get(nodeId) || null;
  }

  getNodeForIp(ip) {
    const allocation = this.allocations.get(ip);
    return allocation ? allocation.nodeId : null;
  }

  setAllocation(nodeId, ip) {
    if (this.allocations.has(ip) && this.allocations.get(ip).nodeId !== nodeId) {
      throw new Error(`IP ${ip} already allocated to another node`);
    }
    
    const existingIp = this.nodeToIp.get(nodeId);
    if (existingIp && existingIp !== ip) {
      this.allocations.delete(existingIp);
    }
    
    this.allocations.set(ip, {
      nodeId,
      allocatedAt: Date.now()
    });
    this.nodeToIp.set(nodeId, ip);
  }

  reserve(ip) {
    const lastOctet = parseInt(ip.split('.')[3], 10);
    this.reservedIps.add(lastOctet);
  }

  _formatIp(lastOctets) {
    if (lastOctets <= 255) {
      return `${this.networkBase}.${lastOctets}`;
    }
    
    const third = Math.floor(lastOctets / 256);
    const fourth = lastOctets % 256;
    const baseParts = this.networkBase.split('.');
    return `${baseParts[0]}.${baseParts[1]}.${third}.${fourth}`;
  }

  isInNetwork(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    
    const networkParts = this.networkBase.split('.');
    return parts[0] === networkParts[0] && parts[1] === networkParts[1];
  }

  getAllocations() {
    const result = [];
    for (const [ip, info] of this.allocations) {
      result.push({
        ip,
        nodeId: info.nodeId,
        allocatedAt: info.allocatedAt
      });
    }
    return result;
  }

  getStats() {
    return {
      totalAllocated: this.allocations.size,
      networkCidr: this.networkCidr,
      nextAvailable: this._formatIp(this.nextIp)
    };
  }

  clear() {
    this.allocations.clear();
    this.nodeToIp.clear();
    this.nextIp = 2;
    this.emit('cleared');
  }
}

export class RoutingTable extends EventEmitter {
  constructor(localNodeId) {
    super();
    this.localNodeId = localNodeId;
    this.routes = new Map();
    this.directPeers = new Set();
  }

  addDirectPeer(nodeId, virtualIp) {
    this.directPeers.add(nodeId);
    this.routes.set(virtualIp, {
      nodeId,
      nextHop: nodeId,
      hops: 1,
      direct: true,
      updatedAt: Date.now()
    });
    this.emit('route-added', { virtualIp, nodeId, direct: true });
  }

  removeDirectPeer(nodeId) {
    this.directPeers.delete(nodeId);
    
    for (const [ip, route] of this.routes) {
      if (route.nextHop === nodeId) {
        this.routes.delete(ip);
        this.emit('route-removed', { virtualIp: ip, nodeId });
      }
    }
  }

  addRoute(virtualIp, nodeId, nextHop, hops) {
    const existing = this.routes.get(virtualIp);
    
    if (!existing || existing.hops > hops) {
      this.routes.set(virtualIp, {
        nodeId,
        nextHop,
        hops,
        direct: false,
        updatedAt: Date.now()
      });
      this.emit('route-added', { virtualIp, nodeId, nextHop, hops });
    }
  }

  getRoute(virtualIp) {
    return this.routes.get(virtualIp) || null;
  }

  getNextHop(virtualIp) {
    const route = this.routes.get(virtualIp);
    return route ? route.nextHop : null;
  }

  hasRoute(virtualIp) {
    return this.routes.has(virtualIp);
  }

  getAllRoutes() {
    const result = [];
    for (const [ip, route] of this.routes) {
      result.push({
        virtualIp: ip,
        ...route
      });
    }
    return result;
  }

  getDirectPeers() {
    return Array.from(this.directPeers);
  }

  clear() {
    this.routes.clear();
    this.directPeers.clear();
    this.emit('cleared');
  }
}
