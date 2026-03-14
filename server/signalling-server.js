import { WebSocketServer } from 'ws';
import { EventEmitter } from 'events';

class SignallingServer extends EventEmitter {
  constructor(port = 8080) {
    super();
    this.port = port;
    this.wss = null;
    this.nodes = new Map();
    this.virtualIpCounter = 2;
    this.virtualNetwork = '10.200.0';
  }

  start() {
    this.wss = new WebSocketServer({ port: this.port });
    
    this.wss.on('listening', () => {
      console.log(`Signalling server listening on port ${this.port}`);
    });
    
    this.wss.on('connection', (ws) => {
      this._handleConnection(ws);
    });
    
    this.wss.on('error', (err) => {
      console.error('Server error:', err);
      this.emit('error', err);
    });
  }

  _handleConnection(ws) {
    let nodeId = null;
    
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        this._handleMessage(ws, message, nodeId, (id) => { nodeId = id; });
      } catch (err) {
        console.error('Failed to parse message:', err);
        ws.send(JSON.stringify({ type: 'error', error: 'Invalid message format' }));
      }
    });
    
    ws.on('close', () => {
      if (nodeId) {
        this._handleNodeDisconnect(nodeId);
      }
    });
    
    ws.on('error', (err) => {
      console.error(`WebSocket error for node ${nodeId}:`, err.message);
    });
  }

  _handleMessage(ws, message, currentNodeId, setNodeId) {
    switch (message.type) {
      case 'register':
        this._handleRegister(ws, message, setNodeId);
        break;
        
      case 'signal':
        this._handleSignal(currentNodeId, message);
        break;
        
      case 'get-peers':
        this._handleGetPeers(ws, currentNodeId);
        break;
        
      case 'get-exit-nodes':
        this._handleGetExitNodes(ws);
        break;
        
      case 'topology-update':
        this._handleTopologyUpdate(currentNodeId, message);
        break;
        
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;
        
      default:
        ws.send(JSON.stringify({ type: 'error', error: 'Unknown message type' }));
    }
  }

  _handleRegister(ws, message, setNodeId) {
    const { nodeId, publicKey, role } = message;
    
    if (!nodeId || !publicKey) {
      ws.send(JSON.stringify({ type: 'error', error: 'Missing nodeId or publicKey' }));
      return;
    }
    
    const virtualIp = `${this.virtualNetwork}.${this.virtualIpCounter++}`;
    
    const nodeInfo = {
      ws,
      nodeId,
      publicKey,
      role: role || 'client',
      virtualIp,
      connectedPeers: new Set(),
      registeredAt: Date.now()
    };
    
    this.nodes.set(nodeId, nodeInfo);
    setNodeId(nodeId);
    
    ws.send(JSON.stringify({
      type: 'registered',
      nodeId,
      virtualIp,
      networkCidr: '10.200.0.0/16'
    }));
    
    this._broadcastPeerJoin(nodeId, nodeInfo);
    
    console.log(`Node registered: ${nodeId} (${role}) - ${virtualIp}`);
    this.emit('node-registered', nodeInfo);
  }

  _handleSignal(fromNodeId, message) {
    const { to, signal } = message;
    
    if (!fromNodeId) {
      return;
    }
    
    const targetNode = this.nodes.get(to);
    if (!targetNode) {
      const fromNode = this.nodes.get(fromNodeId);
      if (fromNode) {
        fromNode.ws.send(JSON.stringify({
          type: 'signal-error',
          to,
          error: 'Target node not found'
        }));
      }
      return;
    }
    
    targetNode.ws.send(JSON.stringify({
      type: 'signal',
      from: fromNodeId,
      signal
    }));
  }

  _handleGetPeers(ws, excludeNodeId) {
    const peers = [];
    
    for (const [nodeId, info] of this.nodes) {
      if (nodeId !== excludeNodeId) {
        peers.push({
          nodeId,
          publicKey: info.publicKey,
          role: info.role,
          virtualIp: info.virtualIp
        });
      }
    }
    
    ws.send(JSON.stringify({
      type: 'peers',
      peers
    }));
  }

  _handleGetExitNodes(ws) {
    const exitNodes = [];
    
    for (const [nodeId, info] of this.nodes) {
      if (info.role === 'exit') {
        exitNodes.push({
          nodeId,
          publicKey: info.publicKey,
          virtualIp: info.virtualIp
        });
      }
    }
    
    ws.send(JSON.stringify({
      type: 'exit-nodes',
      exitNodes
    }));
  }

  _handleTopologyUpdate(fromNodeId, message) {
    const { connectedTo } = message;
    
    const nodeInfo = this.nodes.get(fromNodeId);
    if (!nodeInfo) {
      return;
    }
    
    nodeInfo.connectedPeers = new Set(connectedTo || []);
    
    this._broadcastTopology();
  }

  _handleNodeDisconnect(nodeId) {
    const nodeInfo = this.nodes.get(nodeId);
    if (!nodeInfo) {
      return;
    }
    
    this.nodes.delete(nodeId);
    
    this._broadcastPeerLeave(nodeId);
    
    console.log(`Node disconnected: ${nodeId}`);
    this.emit('node-disconnected', nodeId);
  }

  _broadcastPeerJoin(nodeId, nodeInfo) {
    const message = JSON.stringify({
      type: 'peer-join',
      peer: {
        nodeId,
        publicKey: nodeInfo.publicKey,
        role: nodeInfo.role,
        virtualIp: nodeInfo.virtualIp
      }
    });
    
    for (const [id, info] of this.nodes) {
      if (id !== nodeId) {
        info.ws.send(message);
      }
    }
  }

  _broadcastPeerLeave(nodeId) {
    const message = JSON.stringify({
      type: 'peer-leave',
      nodeId
    });
    
    for (const info of this.nodes.values()) {
      info.ws.send(message);
    }
  }

  _broadcastTopology() {
    const topology = {};
    
    for (const [nodeId, info] of this.nodes) {
      topology[nodeId] = {
        role: info.role,
        virtualIp: info.virtualIp,
        connectedTo: Array.from(info.connectedPeers)
      };
    }
    
    const message = JSON.stringify({
      type: 'topology',
      topology
    });
    
    for (const info of this.nodes.values()) {
      info.ws.send(message);
    }
  }

  getNodeCount() {
    return this.nodes.size;
  }

  getExitNodeCount() {
    let count = 0;
    for (const info of this.nodes.values()) {
      if (info.role === 'exit') count++;
    }
    return count;
  }

  stop() {
    if (this.wss) {
      for (const info of this.nodes.values()) {
        info.ws.close();
      }
      this.wss.close();
      console.log('Signalling server stopped');
    }
  }
}

const port = parseInt(process.env.PORT || '8080', 10);
const server = new SignallingServer(port);

process.on('SIGINT', () => {
  server.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  server.stop();
  process.exit(0);
});

server.start();

export { SignallingServer };
