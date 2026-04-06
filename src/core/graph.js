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

  _bfs(startId, isGoal, excludeNodes = new Set()) {
    if (!this.nodes.has(startId)) return null;
    const visited = new Set([startId]);
    const queue = [[startId]];
    while (queue.length > 0) {
      const path = queue.shift();
      const current = path[path.length - 1];
      const hit = isGoal(current, path);
      if (hit) return hit;
      for (const nb of (this.edges.get(current) || [])) {
        if (!visited.has(nb) && !excludeNodes.has(nb)) { visited.add(nb); queue.push([...path, nb]); }
      }
    }
    return null;
  }

  findShortestPath(fromNodeId, toNodeId, excludeNodes = new Set()) {
    if (!this.nodes.has(toNodeId)) return null;
    if (fromNodeId === toNodeId) return [fromNodeId];
    return this._bfs(fromNodeId, (cur, path) => cur === toNodeId ? [...path] : null, excludeNodes);
  }

  /**
   * Dijkstra по весам latency из metrics (мс). Если метрика отсутствует — 100 мс на хоп.
   * Возвращает массив nodeId от from до to или null.
   */
  findShortestPathWeighted(fromNodeId, toNodeId, excludeNodes = new Set()) {
    if (!this.nodes.has(toNodeId)) return null;
    if (fromNodeId === toNodeId) return [fromNodeId];

    const DEFAULT_LATENCY = 100;
    const dist = new Map();
    const prev = new Map();
    // Min-heap: [cost, nodeId]
    const heap = [[0, fromNodeId]];
    dist.set(fromNodeId, 0);

    while (heap.length > 0) {
      // Extract min
      heap.sort((a, b) => a[0] - b[0]);
      const [cost, cur] = heap.shift();

      if (cur === toNodeId) {
        const path = [];
        let n = cur;
        while (n !== undefined) {
          path.unshift(n);
          n = prev.get(n);
        }
        return path;
      }

      if (cost > (dist.get(cur) ?? Infinity)) continue;

      for (const nb of (this.edges.get(cur) || [])) {
        if (excludeNodes.has(nb)) continue;
        const m = this.getEdgeMetrics(cur, nb);
        const w = (m && m.latency > 0) ? m.latency : DEFAULT_LATENCY;
        const newCost = cost + w;
        if (newCost < (dist.get(nb) ?? Infinity)) {
          dist.set(nb, newCost);
          prev.set(nb, cur);
          heap.push([newCost, nb]);
        }
      }
    }

    return null;
  }

  /**
   * Dijkstra к ближайшей exit-ноде (наименьшая суммарная latency).
   */
  findPathToNearestExitWeighted(fromNodeId, excludeNodes = new Set()) {
    if (!this.nodes.has(fromNodeId)) return null;

    const DEFAULT_LATENCY = 100;
    const dist = new Map();
    const prev = new Map();
    const heap = [[0, fromNodeId]];
    dist.set(fromNodeId, 0);

    while (heap.length > 0) {
      heap.sort((a, b) => a[0] - b[0]);
      const [cost, cur] = heap.shift();

      if (this.nodes.get(cur)?.role === 'exit' && cur !== fromNodeId) {
        const path = [];
        let n = cur;
        while (n !== undefined) {
          path.unshift(n);
          n = prev.get(n);
        }
        return { path, exitNode: cur, latency: cost };
      }

      if (cost > (dist.get(cur) ?? Infinity)) continue;

      for (const nb of (this.edges.get(cur) || [])) {
        if (excludeNodes.has(nb)) continue;
        const m = this.getEdgeMetrics(cur, nb);
        const w = (m && m.latency > 0) ? m.latency : DEFAULT_LATENCY;
        const newCost = cost + w;
        if (newCost < (dist.get(nb) ?? Infinity)) {
          dist.set(nb, newCost);
          prev.set(nb, cur);
          heap.push([newCost, nb]);
        }
      }
    }

    return null;
  }

  findPathToNearestExit(fromNodeId, excludeNodes = new Set()) {
    return this._bfs(fromNodeId, (cur, path) =>
      (this.nodes.get(cur)?.role === 'exit' && cur !== fromNodeId) ? { path, exitNode: cur } : null,
      excludeNodes
    );
  }

  findAllPathsToExits(fromNodeId, maxPaths = 5, excludeNodes = new Set()) {
    if (!this.nodes.has(fromNodeId)) return [];
    const paths = [];
    const visited = new Set([fromNodeId]);
    const queue = [[fromNodeId]];
    while (queue.length > 0 && paths.length < maxPaths) {
      const path = queue.shift();
      const cur = path[path.length - 1];
      if (this.nodes.get(cur)?.role === 'exit' && cur !== fromNodeId) {
        paths.push({ path, exitNode: cur, hops: path.length - 1 });
        if (paths.length >= maxPaths) break;
      }
      for (const nb of (this.edges.get(cur) || [])) {
        if (!visited.has(nb) && !excludeNodes.has(nb)) { visited.add(nb); queue.push([...path, nb]); }
      }
    }
    return paths.sort((a, b) => a.hops - b.hops);
  }

  updateFromTopology(topology) {
    const incomingNodeIds = new Set(Object.keys(topology));

    // Обновляем / добавляем узлы из нового снимка topology
    for (const [nodeId, info] of Object.entries(topology)) {
      this.addNode(nodeId, {
        role: info.role,
        virtualIp: info.virtualIp,
        _fromTopology: true,
      });

      for (const connectedNodeId of info.connectedTo || []) {
        if (this.nodes.has(connectedNodeId) || topology[connectedNodeId]) {
          this.addEdge(nodeId, connectedNodeId);
        }
      }
    }

    // Pruning: удаляем узлы, которые пришли из topology в прошлый раз, но отсутствуют сейчас.
    // Узлы, добавленные локально через addLocalConnection (не из topology), не трогаем.
    for (const [nodeId, info] of this.nodes) {
      if (info._fromTopology && !incomingNodeIds.has(nodeId)) {
        this.removeNode(nodeId);
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
