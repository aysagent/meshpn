import WebSocket from 'ws';
import { EventEmitter } from 'events';

export class WebSocketTransport extends EventEmitter {
  constructor(config = {}) {
    super();
    this.serverUrl = config.serverUrl;
    this.connections = new Map();
    this.server = null;
    this.reconnectInterval = config.reconnectInterval || 5000;
    this.reconnectAttempts = new Map();
    this.maxReconnectAttempts = config.maxReconnectAttempts || 10;
  }

  async startServer(port) {
    return new Promise((resolve, reject) => {
      this.server = new WebSocket.Server({ port });
      
      this.server.on('listening', () => {
        resolve(port);
      });
      
      this.server.on('error', reject);
      
      this.server.on('connection', (ws, req) => {
        const peerId = req.headers['x-peer-id'];
        if (!peerId) {
          ws.close(4001, 'Missing peer ID');
          return;
        }
        
        this._setupConnection(peerId, ws);
      });
    });
  }

  async connect(peerId, url) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url, {
        headers: { 'X-Peer-ID': peerId }
      });
      
      ws.on('open', () => {
        this._setupConnection(peerId, ws);
        this.reconnectAttempts.delete(peerId);
        resolve();
      });
      
      ws.on('error', (err) => {
        reject(err);
      });
    });
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
      console.error(`Failed to send to ${peerId}:`, err.message);
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

  closeAll() {
    for (const peerId of this.connections.keys()) {
      this.close(peerId);
    }
    if (this.server) {
      this.server.close();
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

  _setupConnection(peerId, ws) {
    this.connections.set(peerId, ws);
    
    ws.on('message', (data) => {
      const buffer = data instanceof Buffer ? data : Buffer.from(data);
      this.emit('message', peerId, buffer);
    });
    
    ws.on('close', () => {
      this.connections.delete(peerId);
      this.emit('peer-disconnected', peerId);
    });
    
    ws.on('error', (err) => {
      this.emit('error', peerId, err);
    });
    
    this.emit('peer-connected', peerId);
  }
}
