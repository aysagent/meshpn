import WebSocket from 'ws';
import { EventEmitter } from 'events';
import { TransportSendBuffer, unframe } from './send-buffer.js';

export class WebSocketTransport extends EventEmitter {
  constructor(config = {}) {
    super();
    this.serverUrl = config.serverUrl;
    this.localNodeId = config.localNodeId;
    this.connections = new Map();
    this.sendBuffers = new Map();
    this.server = null;
    this.reconnectInterval = config.reconnectInterval || 5000;
    this.reconnectAttempts = new Map();
    this.maxReconnectAttempts = config.maxReconnectAttempts || 10;
    this.connectTimeout = config.connectTimeout || 5000;
  }
  
  setLocalNodeId(nodeId) {
    this.localNodeId = nodeId;
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

  async connect(peerId, url, timeout = null) {
    const connectTimeout = timeout || this.connectTimeout;
    
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        ws.close();
        reject(new Error(`Connection timeout after ${connectTimeout}ms`));
      }, connectTimeout);
      
      const ws = new WebSocket(url, {
        headers: { 
          'X-Peer-ID': this.localNodeId || peerId
        }
      });
      
      ws.on('open', () => {
        clearTimeout(timeoutId);
        this._setupConnection(peerId, ws);
        this.reconnectAttempts.delete(peerId);
        resolve();
      });
      
      ws.on('error', (err) => {
        clearTimeout(timeoutId);
        reject(err);
      });
    });
  }

  send(peerId, data) {
    const sb = this.sendBuffers.get(peerId);
    if (!sb) return false;

    const buffer = typeof data === 'string' ? Buffer.from(data) : data;
    sb.push(buffer);
    return true;
  }

  isConnected(peerId) {
    const ws = this.connections.get(peerId);
    return ws && ws.readyState === WebSocket.OPEN;
  }

  close(peerId) {
    const sb = this.sendBuffers.get(peerId);
    if (sb) { sb.stop(); this.sendBuffers.delete(peerId); }
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
    for (const sb of this.sendBuffers.values()) sb.stop();
    this.sendBuffers.clear();
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

    const sb = new TransportSendBuffer((frame) => {
      try { ws.send(frame); } catch {}
    });
    this.sendBuffers.set(peerId, sb);
    
    ws.on('message', (data) => {
      const raw = data instanceof Buffer ? data : Buffer.from(data);
      const packets = unframe(raw);
      for (const buffer of packets) {
        this.emit('message', peerId, buffer);
      }
    });
    
    ws.on('close', () => {
      const buf = this.sendBuffers.get(peerId);
      if (buf) { buf.stop(); this.sendBuffers.delete(peerId); }
      this.connections.delete(peerId);
      this.emit('peer-disconnected', peerId);
    });
    
    ws.on('error', (err) => {
      this.emit('error', peerId, err);
    });
    
    this.emit('peer-connected', peerId);
  }
}
