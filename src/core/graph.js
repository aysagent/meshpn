import { EventEmitter } from 'events';

export class NetworkGraph extends EventEmitter {
  constructor() {
    super();
    this.nodes = new Map();
    this.edges = new Map();
    this.metrics = new Map();
  }

  addNode(nodeId, info = {}) {
    if (!this.nodes.has(nodeId)) {
      this.nodes.set(nodeId, {
        nodeId,
        role: info.role || 'client',
        virtualIp: info.virtualIp || null,
        publicKey: info.publicKey || null,
        addedAt: Date.now(),
        ...info
      });
      this.edges.set(nodeId, new Set());
      this.emit('node-added', nodeId);
    } else {
      const existing = this.nodes.get(nodeId);
      this.nodes.set(nodeId, { ...existing, ...info });
    }
  }

  removeNode(nodeId) {
    if (!this.nodes.has(nodeId)) {
      return;
    }
    
    const neighbors = this.edges.get(nodeId) || new Set();
    for (const neighbor of neighbors) {
      const neighborEdges = this.edges.get(neighbor);
      if (neighborEdges) {
        neighborEdges.delete(nodeId);
      }
      this.metrics.delete(this._edgeKey(nodeId, neighbor));
    }
    
    this.nodes.delete(nodeId);
    this.edges.delete(nodeId);
    this.emit('node-removed', nodeId);
  }

  addEdge(nodeA, nodeB, metrics = {}) {
    if (!this.edges.has(nodeA)) {
      this.edges.set(nodeA, new Set());
    }
    if (!this.edges.has(nodeB)) {
      this.edges.set(nodeB, new Set());
    }
    
    this.edges.get(nodeA).add(nodeB);
    this.edges.get(nodeB).add(nodeA);
    
    this.updateEdgeMetrics(nodeA, nodeB, metrics);
    
    this.emit('edge-added', nodeA, nodeB);
  }

  removeEdge(nodeA, nodeB) {
    const edgesA = this.edges.get(nodeA);
    const edgesB = this.edges.get(nodeB);
    
    if (edgesA) edgesA.delete(nodeB);
    if (edgesB) edgesB.delete(nodeA);
    
    this.metrics.delete(this._edgeKey(nodeA, nodeB));
    
    this.emit('edge-removed', nodeA, nodeB);
  }

  updateEdgeMetrics(nodeA, nodeB, metrics) {
    const key = this._edgeKey(nodeA, nodeB);
    const existing = this.metrics.get(key) || {};
    this.metrics.set(key, {
      ...existing,
      ...metrics,
      updatedAt: Date.now()
    });
  }

  getEdgeMetrics(nodeA, nodeB) {
    return this.metrics.get(this._edgeKey(nodeA, nodeB));
  }

  _edgeKey(nodeA, nodeB) {
    return nodeA < nodeB ? `${nodeA}:${nodeB}` : `${nodeB}:${nodeA}`;
  }

  getNeighbors(nodeId) {
    return Array.from(this.edges.get(nodeId) || []);
  }

  hasNode(nodeId) {
    return this.nodes.has(nodeId);
  }

  hasEdge(nodeA, nodeB) {
    const edges = this.edges.get(nodeA);
    return edges ? edges.has(nodeB) : false;
  }

  getNode(nodeId) {
    return this.nodes.get(nodeId);
  }

  getAllNodes() {
    return Array.from(this.nodes.values());
  }

  getNodesByRole(role) {
    const result = [];
    for (const node of this.nodes.values()) {
      if (node.role === role) {
        result.push(node);
      }
    }
    return result;
  }

  getExitNodes() {
    return this.getNodesByRole('exit');
  }

  getRelayNodes() {
    return this.getNodesByRole('relay');
  }

  getClientNodes() {
    return this.getNodesByRole('client');
  }

  findShortestPath(fromNodeId, toNodeId) {
    if (!this.nodes.has(fromNodeId) || !this.nodes.has(toNodeId)) {
      return null;
    }
    
    if (fromNodeId === toNodeId) {
      return [fromNodeId];
    }
    
    const visited = new Set();
    const queue = [[fromNodeId]];
    visited.add(fromNodeId);
    
    while (queue.length > 0) {
      const path = queue.shift();
      const current = path[path.length - 1];
      
      const neighbors = this.edges.get(current) || new Set();
      
      for (const neighbor of neighbors) {
        if (neighbor === toNodeId) {
          return [...path, neighbor];
        }
        
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push([...path, neighbor]);
        }
      }
    }
    
    return null;
  }

  findPathToNearestExit(fromNodeId) {
    const exitNodes = this.getExitNodes();
    if (exitNodes.length === 0) {
      return null;
    }
    
    const visited = new Set();
    const queue = [[fromNodeId]];
    visited.add(fromNodeId);
    
    while (queue.length > 0) {
      const path = queue.shift();
      const current = path[path.length - 1];
      
      const currentNode = this.nodes.get(current);
      if (currentNode && currentNode.role === 'exit' && current !== fromNodeId) {
        return { path, exitNode: current };
      }
      
      const neighbors = this.edges.get(current) || new Set();
      
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push([...path, neighbor]);
        }
      }
    }
    
    return null;
  }

  findAllPathsToExits(fromNodeId, maxPaths = 5) {
    const exitNodes = this.getExitNodes();
    const paths = [];
    
    for (const exitNode of exitNodes) {
      const path = this.findShortestPath(fromNodeId, exitNode.nodeId);
      if (path && path.length > 1) {
        paths.push({
          path,
          exitNode: exitNode.nodeId,
          hops: path.length - 1
        });
      }
    }
    
    paths.sort((a, b) => a.hops - b.hops);
    
    return paths.slice(0, maxPaths);
  }

  updateFromTopology(topology) {
    for (const [nodeId, info] of Object.entries(topology)) {
      this.addNode(nodeId, {
        role: info.role,
        virtualIp: info.virtualIp
      });
      
      for (const connectedNodeId of info.connectedTo || []) {
        if (this.nodes.has(connectedNodeId) || topology[connectedNodeId]) {
          this.addEdge(nodeId, connectedNodeId);
        }
      }
    }
    
    this.emit('topology-updated');
  }

  toJSON() {
    const nodes = {};
    const edges = [];
    
    for (const [nodeId, info] of this.nodes) {
      nodes[nodeId] = info;
    }
    
    const seenEdges = new Set();
    for (const [nodeA, neighbors] of this.edges) {
      for (const nodeB of neighbors) {
        const key = this._edgeKey(nodeA, nodeB);
        if (!seenEdges.has(key)) {
          seenEdges.add(key);
          edges.push({
            from: nodeA,
            to: nodeB,
            metrics: this.metrics.get(key)
          });
        }
      }
    }
    
    return { nodes, edges };
  }

  clear() {
    this.nodes.clear();
    this.edges.clear();
    this.metrics.clear();
    this.emit('cleared');
  }
}
