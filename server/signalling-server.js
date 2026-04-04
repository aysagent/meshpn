import { WebSocketServer } from 'ws';
import { EventEmitter } from 'events';
import geoip from 'geoip-lite';
import fs from 'fs';
import path from 'path';

class SignallingServer extends EventEmitter {
  constructor(port = 8080, options = {}) {
    super();
    this.port = port;
    this.wss = null;
    this.nodes = new Map();
    this.virtualIpCounter = 2;
    this.virtualNetwork = '10.200.0';
    /** Map<nodeId, virtualIp> — статически закреплённые адреса. */
    this.pinnedIps = options.pinnedIps && typeof options.pinnedIps === 'object'
      ? options.pinnedIps
      : {};
  }

  /**
   * Безопасная отправка: проверяет readyState перед send, поглощает исключения.
   * @param {import('ws').WebSocket} ws
   * @param {string} data
   */
  _wsSend(ws, data) {
    if (!ws || ws.readyState !== ws.OPEN) {
      return;
    }
    try {
      ws.send(data);
    } catch (err) {
      console.warn('[Signalling] ws.send error (ignored):', err.message);
    }
  }

  _sendRegistered(ws, nodeId, virtualIp) {
    this._wsSend(ws, JSON.stringify({ type: 'registered', nodeId, virtualIp, networkCidr: '10.200.0.0/16' }));
  }

  start() {
    // maxPayload ограничивает размер входящего сообщения (64 KB достаточно для SDP/ICE JSON)
    this.wss = new WebSocketServer({ port: this.port, maxPayload: 65536 });
    
    this.wss.on('listening', () => {
      console.log(`Signalling server listening on port ${this.port}`);
    });
    
    this.wss.on('connection', (ws, req) => {
      this._handleConnection(ws, req);
    });
    
    this.wss.on('error', (err) => {
      console.error('Server error:', err);
      this.emit('error', err);
    });
  }

  _handleConnection(ws, req) {
    const rawAddr = req?.socket?.remoteAddress || '';
    ws._remoteAddress = rawAddr.replace(/^::ffff:/, '');
    let nodeId = null;
    
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        this._handleMessage(ws, message, nodeId, (id) => { nodeId = id; });
      } catch (err) {
        console.error('Failed to parse message:', err);
        this._wsSend(ws, JSON.stringify({ type: 'error', error: 'Invalid message format' }));
      }
    });
    
    ws.on('close', () => {
      this._handleWsClose(ws);
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
        this._wsSend(ws, JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;

      default:
        this._wsSend(ws, JSON.stringify({ type: 'error', error: 'Unknown message type' }));
    }
  }

  _handleRegister(ws, message, setNodeId) {
    const { nodeId, publicKey, name } = message;
    // Автодетект роли: явный флаг nat/relay имеет приоритет над полем role
    const resolvedRole = message.nat?.enabled ? 'exit'
      : message.relay ? 'relay'
      : (message.role || 'client');
    const role = resolvedRole;

    if (!nodeId || !publicKey) {
      this._wsSend(ws, JSON.stringify({ type: 'error', error: 'Missing nodeId or publicKey' }));
      return;
    }

    const label = name || nodeId.substring(0, 8);
    const existingNode = this.nodes.get(nodeId);
    if (existingNode) {
      // Не шлём peer-leave: это рвёт рабочий WebRTC между exit и клиентом при лишь
      // переподключении signalling WS (тот же nodeId). Залипший транспорт снимает
      // реальный peer-leave при закрытии старого сокета или новый offer от клиента.

      // Закрываем старый сокет, если он ещё открыт (не тот же объект, что пришёл сейчас)
      if (existingNode.ws !== ws && existingNode.ws.readyState === existingNode.ws.OPEN) {
        try { existingNode.ws.terminate(); } catch { /* ignore */ }
      }

      existingNode.ws = ws;
      if (publicKey) {
        existingNode.publicKey = publicKey;
      }
      if (role) {
        existingNode.role = role;
      }
      if (name) {
        existingNode.name = name;
      }
      setNodeId(nodeId);

      this._sendRegistered(ws, nodeId, existingNode.virtualIp);

      this._broadcastPeerJoin(nodeId, existingNode);

      console.log(`Node re-registered: ${label} (${existingNode.role}) - ${existingNode.virtualIp}`);
      return;
    }

    let virtualIp;
    if (this.pinnedIps[nodeId]) {
      const pinned = this.pinnedIps[nodeId];
      // Проверяем что IP не занят другой нодой
      const conflict = [...this.nodes.values()].find(
        (n) => n.virtualIp === pinned && n.nodeId !== nodeId,
      );
      if (conflict) {
        console.warn(`[Signalling] Pinned IP ${pinned} for ${label} is already used by ${conflict.name || conflict.nodeId.substring(0, 8)}`);
        virtualIp = `${this.virtualNetwork}.${this.virtualIpCounter++}`;
      } else {
        virtualIp = pinned;
        console.log(`[Signalling] Assigned pinned IP ${virtualIp} to ${label}`);
      }
    } else {
      virtualIp = `${this.virtualNetwork}.${this.virtualIpCounter++}`;
    }
    const externalIp = ws._remoteAddress || null;
    const geo = externalIp ? geoip.lookup(externalIp) : null;

    const nodeInfo = {
      ws,
      nodeId,
      name: name || null,
      publicKey,
      role: role || 'client',
      virtualIp,
      externalIp,
      geo,
      connectedPeers: new Set(),
      registeredAt: Date.now()
    };

    this.nodes.set(nodeId, nodeInfo);
    setNodeId(nodeId);

    this._sendRegistered(ws, nodeId, virtualIp);

    this._broadcastPeerJoin(nodeId, nodeInfo);

    const geoStr = geo ? ` [${geo.country}${geo.city ? '/' + geo.city : ''}]` : '';
    console.log(`Node registered: ${label} (${role}) - ${virtualIp}${geoStr}`);
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
        this._wsSend(fromNode.ws, JSON.stringify({
          type: 'signal-error',
          to,
          error: 'Target node not found'
        }));
      }
      return;
    }

    this._wsSend(targetNode.ws, JSON.stringify({
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
          name: info.name || null,
          publicKey: info.publicKey,
          role: info.role,
          virtualIp: info.virtualIp,
          externalIp: info.externalIp || null,
          geo: info.geo || null,
        });
      }
    }
    
    this._wsSend(ws, JSON.stringify({
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
          name: info.name || null,
          publicKey: info.publicKey,
          virtualIp: info.virtualIp,
          externalIp: info.externalIp || null,
          geo: info.geo || null,
        });
      }
    }
    
    this._wsSend(ws, JSON.stringify({
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

  /**
   * Удалять ноду только если закрылся её текущий WebSocket (не устаревший после re-register).
   */
  _handleWsClose(ws) {
    for (const [nodeId, info] of this.nodes) {
      if (info.ws !== ws) {
        continue;
      }
      this.nodes.delete(nodeId);
      this._broadcastPeerLeave(nodeId);
      console.log(`Node disconnected: ${info.name || nodeId.substring(0, 8)}`);
      this.emit('node-disconnected', nodeId);
      return;
    }
  }

  _broadcastPeerJoin(nodeId, nodeInfo) {
    const message = JSON.stringify({
      type: 'peer-join',
      peer: {
        nodeId,
        name: nodeInfo.name || null,
        publicKey: nodeInfo.publicKey,
        role: nodeInfo.role,
        virtualIp: nodeInfo.virtualIp,
        externalIp: nodeInfo.externalIp || null,
        geo: nodeInfo.geo || null,
      }
    });
    
    for (const [id, info] of this.nodes) {
      if (id !== nodeId) {
        this._wsSend(info.ws, message);
      }
    }
  }

  /** peer-leave всем, кроме самого nodeId (при удалении ноды из map её уже нет в цикле). */
  _broadcastPeerLeave(nodeId) {
    const message = JSON.stringify({
      type: 'peer-leave',
      nodeId
    });

    for (const [id, info] of this.nodes) {
      if (id === nodeId) {
        continue;
      }
      this._wsSend(info.ws, message);
    }
  }

  _broadcastTopology() {
    const topology = {};

    for (const [nodeId, info] of this.nodes) {
      topology[nodeId] = {
        name: info.name || null,
        role: info.role,
        virtualIp: info.virtualIp,
        externalIp: info.externalIp || null,
        geo: info.geo || null,
        connectedTo: Array.from(info.connectedPeers)
      };
    }

    const message = JSON.stringify({
      type: 'topology',
      topology
    });

    for (const info of this.nodes.values()) {
      this._wsSend(info.ws, message);
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

function loadServerConfig() {
  const configPath = process.env.SIGNALLING_CONFIG
    || path.join(process.cwd(), 'server', 'server-config.json');
  try {
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, 'utf8');
      console.log(`[Signalling] Loaded server config from ${configPath}`);
      return JSON.parse(raw);
    }
  } catch (err) {
    console.warn(`[Signalling] Failed to load server config: ${err.message}`);
  }
  return {};
}

const serverConfig = loadServerConfig();
const server = new SignallingServer(port, serverConfig);

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
