import WebSocket from 'ws';
import { EventEmitter } from 'events';

export class SignallingClient extends EventEmitter {
  constructor(serverUrl, identity) {
    super();
    this.serverUrl = serverUrl;
    this.identity = identity;
    this.ws = null;
    this.connected = false;
    this.registered = false;
    this.virtualIp = null;
    this.reconnectTimer = null;
    this.reconnectInterval = 5000;
    this.pingInterval = null;
    this.peers = new Map();
    this.exitNodes = new Map();
  }

  async connect(role = 'client') {
    this.role = role;
    
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.serverUrl);
      
      this.ws.on('open', () => {
        this.connected = true;
        this._startPingInterval();
        this._register();
        resolve();
      });
      
      this.ws.on('message', (data) => {
        this._handleMessage(data);
      });
      
      this.ws.on('close', () => {
        this._handleDisconnect();
      });
      
      this.ws.on('error', (err) => {
        if (!this.connected) {
          reject(err);
        } else {
          this.emit('error', err);
        }
      });
    });
  }

  _register() {
    this._send({
      type: 'register',
      nodeId: this.identity.nodeId,
      publicKey: this.identity.exportPublicKey(),
      role: this.role
    });
  }

  _handleMessage(data) {
    try {
      const message = JSON.parse(data.toString());
      
      switch (message.type) {
        case 'registered':
          this.registered = true;
          this.virtualIp = message.virtualIp;
          this.emit('registered', {
            virtualIp: message.virtualIp,
            networkCidr: message.networkCidr
          });
          this._requestPeers();
          this._requestExitNodes();
          break;
          
        case 'peers':
          this._handlePeersList(message.peers);
          break;
          
        case 'exit-nodes':
          this._handleExitNodesList(message.exitNodes);
          break;
          
        case 'peer-join':
          this._handlePeerJoin(message.peer);
          break;
          
        case 'peer-leave':
          this._handlePeerLeave(message.nodeId);
          break;
          
        case 'signal':
          this.emit('signal', message.from, message.signal);
          break;
          
        case 'signal-error':
          this.emit('signal-error', message.to, message.error);
          break;
          
        case 'topology':
          this.emit('topology', message.topology);
          break;
          
        case 'pong':
          this.emit('pong', message.timestamp);
          break;
          
        case 'error':
          this.emit('server-error', message.error);
          break;
      }
    } catch (err) {
      console.error('Failed to parse signalling message:', err);
    }
  }

  _handlePeersList(peers) {
    for (const peer of peers) {
      this.peers.set(peer.nodeId, peer);
      if (peer.role === 'exit') {
        this.exitNodes.set(peer.nodeId, peer);
      }
    }
    this.emit('peers-updated', Array.from(this.peers.values()));
  }

  _handleExitNodesList(exitNodes) {
    for (const node of exitNodes) {
      this.exitNodes.set(node.nodeId, node);
    }
    this.emit('exit-nodes-updated', Array.from(this.exitNodes.values()));
  }

  _handlePeerJoin(peer) {
    this.peers.set(peer.nodeId, peer);
    if (peer.role === 'exit') {
      this.exitNodes.set(peer.nodeId, peer);
    }
    this.emit('peer-join', peer);
  }

  _handlePeerLeave(nodeId) {
    this.peers.delete(nodeId);
    this.exitNodes.delete(nodeId);
    this.emit('peer-leave', nodeId);
  }

  _handleDisconnect() {
    this.connected = false;
    this.registered = false;
    
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
    
    this.emit('disconnected');
    this._scheduleReconnect();
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) {
      return;
    }
    
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      try {
        await this.connect(this.role);
        this.emit('reconnected');
      } catch (err) {
        console.error('Reconnect failed:', err.message);
        this._scheduleReconnect();
      }
    }, this.reconnectInterval);
  }

  _startPingInterval() {
    this.pingInterval = setInterval(() => {
      this._send({ type: 'ping' });
    }, 30000);
  }

  _send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  sendSignal(toNodeId, signal) {
    this._send({
      type: 'signal',
      to: toNodeId,
      signal
    });
  }

  updateTopology(connectedPeers) {
    this._send({
      type: 'topology-update',
      connectedTo: connectedPeers
    });
  }

  _requestPeers() {
    this._send({ type: 'get-peers' });
  }

  _requestExitNodes() {
    this._send({ type: 'get-exit-nodes' });
  }

  getPeer(nodeId) {
    return this.peers.get(nodeId);
  }

  getAllPeers() {
    return Array.from(this.peers.values());
  }

  getExitNodes() {
    return Array.from(this.exitNodes.values());
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
    
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    
    this.connected = false;
    this.registered = false;
  }
}
