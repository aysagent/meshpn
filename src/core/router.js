import { EventEmitter } from 'events';
import { NetworkGraph } from './graph.js';
import { createOnionPacket, peelOnionLayer } from '../crypto/onion.js';

export class MeshRouter extends EventEmitter {
  constructor(config) {
    super();
    this.localNodeId = config.localNodeId;
    this.graph = new NetworkGraph();
    this.routeCache = new Map();
    this.routeCacheTTL = config.routeCacheTTL || 30000;
    this.exitNodePreference = new Map();
    this.sessionManager = config.sessionManager;
  }

  updateTopology(topology) {
    this.graph.updateFromTopology(topology);
    this._invalidateRouteCache();
  }

  addLocalConnection(peerId, peerInfo = {}) {
    this.graph.addNode(peerId, peerInfo);
    this.graph.addEdge(this.localNodeId, peerId);
    this._invalidateRouteCache();
  }

  removeLocalConnection(peerId) {
    this.graph.removeEdge(this.localNodeId, peerId);
    this._invalidateRouteCache();
  }

  updateEdgeMetrics(peerId, metrics) {
    this.graph.updateEdgeMetrics(this.localNodeId, peerId, metrics);
  }

  findRouteToExit(preferredExitNode = null) {
    const cacheKey = `exit:${preferredExitNode || 'any'}`;
    const cached = this._getCachedRoute(cacheKey);
    if (cached && this.isRouteValid(cached.route)) {
      return cached;
    }
    
    let route = null;
    
    if (preferredExitNode) {
      route = this.graph.findShortestPath(this.localNodeId, preferredExitNode);
      if (route && route.length > 1) {
        route = route.slice(1);
        const validation = this.validateRoute(route);
        if (validation.valid) {
          this._cacheRoute(cacheKey, { route, exitNode: preferredExitNode });
          return { route, exitNode: preferredExitNode };
        }
        console.warn(`Invalid route to preferred exit ${preferredExitNode}: ${validation.reason}`);
      }
    }
    
    const result = this.graph.findPathToNearestExit(this.localNodeId);
    if (result) {
      route = result.path.slice(1);
      const validation = this.validateRoute(route);
      if (validation.valid) {
        this._cacheRoute(cacheKey, { route, exitNode: result.exitNode });
        return { route, exitNode: result.exitNode };
      }
      console.warn(`Invalid route to nearest exit ${result.exitNode}: ${validation.reason}`);
    }
    
    return null;
  }

  findMultiplePaths(count = 3) {
    const allPaths = this.graph.findAllPathsToExits(this.localNodeId, count * 2);
    
    const uniquePaths = [];
    const usedFirstHops = new Set();
    
    for (const pathInfo of allPaths) {
      if (pathInfo.path.length < 2) continue;
      
      const route = pathInfo.path.slice(1);
      const validation = this.validateRoute(route);
      if (!validation.valid) {
        continue;
      }
      
      const firstHop = pathInfo.path[1];
      if (!usedFirstHops.has(firstHop) || uniquePaths.length < count) {
        usedFirstHops.add(firstHop);
        uniquePaths.push({
          route,
          exitNode: pathInfo.exitNode,
          hops: pathInfo.hops
        });
        
        if (uniquePaths.length >= count) break;
      }
    }
    
    return uniquePaths;
  }

  getNextHop(destinationNodeId) {
    if (this.graph.hasEdge(this.localNodeId, destinationNodeId)) {
      return destinationNodeId;
    }
    
    const path = this.graph.findShortestPath(this.localNodeId, destinationNodeId);
    if (path && path.length > 1) {
      return path[1];
    }
    
    return null;
  }

  buildOnionPacket(payload, route) {
    const routeWithKeys = [];
    
    for (const nodeId of route) {
      const sessionKey = this.sessionManager.getSessionKey(nodeId);
      if (!sessionKey) {
        throw new Error(`No session key for node ${nodeId}`);
      }
      routeWithKeys.push({ nodeId, sessionKey });
    }
    
    return createOnionPacket(payload, routeWithKeys);
  }

  processIncomingPacket(encryptedPacket) {
    const mySessionKey = this._getMySessionKey();
    if (!mySessionKey) {
      throw new Error('No local session key available');
    }
    
    const layer = peelOnionLayer(encryptedPacket, mySessionKey);
    
    return {
      nextHop: layer.nextHop,
      isExit: layer.isExit,
      payload: layer.payload
    };
  }

  _getMySessionKey() {
    return this.sessionManager.getSessionKey(this.localNodeId);
  }

  setExitNodePreference(exitNodeId, preference) {
    this.exitNodePreference.set(exitNodeId, preference);
  }

  selectBestExitNode() {
    const exitNodes = this.graph.getExitNodes();
    if (exitNodes.length === 0) {
      return null;
    }
    
    let bestNode = null;
    let bestScore = -Infinity;
    
    for (const exitNode of exitNodes) {
      const path = this.graph.findShortestPath(this.localNodeId, exitNode.nodeId);
      if (!path) continue;
      
      const hops = path.length - 1;
      const preference = this.exitNodePreference.get(exitNode.nodeId) || 0;
      
      const score = preference - hops;
      
      if (score > bestScore) {
        bestScore = score;
        bestNode = exitNode.nodeId;
      }
    }
    
    return bestNode;
  }

  getReachableExitNodes() {
    const exitNodes = this.graph.getExitNodes();
    const reachable = [];
    
    for (const exitNode of exitNodes) {
      const path = this.graph.findShortestPath(this.localNodeId, exitNode.nodeId);
      if (path) {
        reachable.push({
          nodeId: exitNode.nodeId,
          virtualIp: exitNode.virtualIp,
          hops: path.length - 1
        });
      }
    }
    
    return reachable.sort((a, b) => a.hops - b.hops);
  }

  _getCachedRoute(key) {
    const cached = this.routeCache.get(key);
    if (cached && Date.now() - cached.timestamp < this.routeCacheTTL) {
      return cached.data;
    }
    this.routeCache.delete(key);
    return null;
  }

  _cacheRoute(key, data) {
    this.routeCache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  _invalidateRouteCache() {
    this.routeCache.clear();
    this.emit('routes-invalidated');
  }

  getConnectedPeers() {
    return this.graph.getNeighbors(this.localNodeId);
  }

  getGraphStats() {
    return {
      totalNodes: this.graph.nodes.size,
      exitNodes: this.graph.getExitNodes().length,
      relayNodes: this.graph.getRelayNodes().length,
      clientNodes: this.graph.getClientNodes().length,
      connectedPeers: this.getConnectedPeers().length
    };
  }

  validateRoute(route) {
    if (!route || route.length === 0) {
      return { valid: false, reason: 'Empty route' };
    }

    const seen = new Set();
    
    for (let i = 0; i < route.length; i++) {
      const nodeId = route[i];
      
      if (!nodeId) {
        return { valid: false, reason: `Invalid node at position ${i}` };
      }
      
      if (seen.has(nodeId)) {
        return { valid: false, reason: `Cycle detected: node ${nodeId} appears twice in route` };
      }
      seen.add(nodeId);
      
      if (nodeId === this.localNodeId && i !== 0) {
        return { valid: false, reason: `Route loops back to local node at position ${i}` };
      }
    }
    
    return { valid: true };
  }

  validateAndFilterRoutes(routes) {
    return routes.filter(routeInfo => {
      const validation = this.validateRoute(routeInfo.route);
      if (!validation.valid) {
        console.warn(`Filtered invalid route to ${routeInfo.exitNode}: ${validation.reason}`);
        return false;
      }
      return true;
    });
  }

  isRouteValid(route) {
    return this.validateRoute(route).valid;
  }
}
