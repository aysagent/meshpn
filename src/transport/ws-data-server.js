import { WebSocketServer, WebSocket } from 'ws';
import { EventEmitter } from 'events';

export class WebSocketDataServer extends EventEmitter {
  constructor(config = {}) {
    super();
    this.port = config.port || 8081;
    this.server = null;
    this.connections = new Map();
    this.nodeId = config.nodeId;
  }

  async start() {
    return new Promise((resolve, reject) => {
      this.server = new WebSocketServer({ port: this.port });
      
      this.server.on('listening', () => {
        console.log(`[WS-DATA] WebSocket data server listening on port ${this.port}`);
        resolve(this.port);
      });
      
      this.server.on('error', (err) => {
        console.error('[WS-DATA] Server error:', err.message);
        reject(err);
      });
      
      this.server.on('connection', (ws, req) => {
        this._handleConnection(ws, req);
      });
    });
  }

  _handleConnection(ws, req) {
    const peerId = req.headers['x-peer-id'];
    const peerPublicKey = req.headers['x-peer-public-key'];
    
    if (!peerId) {
      console.warn('[WS-DATA] Connection rejected: missing peer ID');
      ws.close(4001, 'Missing peer ID');
      return;
    }
    
    console.log(`[WS-DATA] Client connected: ${peerId}`);
    
    this.connections.set(peerId, ws);
    
    ws.isAlive = true;
    ws.peerId = peerId;
    
    ws.on('pong', () => {
      ws.isAlive = true;
    });
    
    ws.on('message', (data) => {
      const buffer = data instanceof Buffer ? data : Buffer.from(data);
      this.emit('message', peerId, buffer);
    });
    
    ws.on('close', () => {
      console.log(`[WS-DATA] Client disconnected: ${peerId}`);
      this.connections.delete(peerId);
      this.emit('peer-disconnected', peerId);
    });
    
    ws.on('error', (err) => {
      console.error(`[WS-DATA] Connection error for ${peerId}:`, err.message);
      this.emit('error', peerId, err);
    });
    
    this.emit('peer-connected', peerId, { publicKey: peerPublicKey });
  }

  send(peerId, data) {
    const ws = this.connections.get(peerId);
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return false;
    }
    
    try {
      const buffer = typeof data === 'string' ? Buffer.from(data) : data;
      ws.send(buffer);
      return true;
    } catch (err) {
      console.error(`[WS-DATA] Failed to send to ${peerId}:`, err.message);
      return false;
    }
  }

  isConnected(peerId) {
    const ws = this.connections.get(peerId);
    return ws && ws.readyState === WebSocket.OPEN;
  }

  close(peerId) {
    const ws = this.connections.get(peerId);
    if (ws) {
      ws.close();
      this.connections.delete(peerId);
    }
  }

  getConnectedPeers() {
    const connected = [];
    for (const [peerId, ws] of this.connections) {
      if (ws.readyState === WebSocket.OPEN) {
        connected.push(peerId);
      }
    }
    return connected;
  }

  stop() {
    if (this.server) {
      for (const ws of this.connections.values()) {
        ws.close();
      }
      this.connections.clear();
      this.server.close();
      this.server = null;
      console.log('[WS-DATA] Server stopped');
    }
  }
}
