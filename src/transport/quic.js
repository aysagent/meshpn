import { EventEmitter } from 'events';
import dgram from 'dgram';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export class QuicTransport extends EventEmitter {
  constructor(config = {}) {
    super();
    this.port = config.port || 0;
    this.socket = null;
    this.connections = new Map();
    this.peerAddresses = new Map();
    this.sessionKeys = new Map();
    this.portHoppingEnabled = config.portHopping || false;
    this.portHoppingInterval = config.portHoppingInterval || 30000;
    this.portHoppingTimer = null;
  }

  async start() {
    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket('udp4');
      
      this.socket.on('error', (err) => {
        this.emit('error', null, err);
        reject(err);
      });
      
      this.socket.on('message', (msg, rinfo) => {
        this._handleMessage(msg, rinfo);
      });
      
      this.socket.on('listening', () => {
        const addr = this.socket.address();
        this.port = addr.port;
        
        if (this.portHoppingEnabled) {
          this._startPortHopping();
        }
        
        resolve(this.port);
      });
      
      this.socket.bind(this.port);
    });
  }

  setSessionKey(peerId, key) {
    this.sessionKeys.set(peerId, key);
  }

  setPeerAddress(peerId, address, port) {
    this.peerAddresses.set(peerId, { address, port });
    this.connections.set(peerId, true);
    this.emit('peer-connected', peerId);
  }

  send(peerId, data) {
    const peer = this.peerAddresses.get(peerId);
    if (!peer) {
      return false;
    }
    
    const sessionKey = this.sessionKeys.get(peerId);
    if (!sessionKey) {
      return false;
    }
    
    try {
      const buffer = typeof data === 'string' ? Buffer.from(data) : data;
      const encrypted = this._encrypt(buffer, sessionKey);
      
      const packet = Buffer.alloc(encrypted.length + 16);
      const peerIdBuffer = Buffer.from(peerId.padEnd(16, '\0').slice(0, 16));
      peerIdBuffer.copy(packet, 0);
      encrypted.copy(packet, 16);
      
      this.socket.send(packet, peer.port, peer.address);
      return true;
    } catch (err) {
      console.error(`Failed to send to ${peerId}:`, err.message);
      return false;
    }
  }

  isConnected(peerId) {
    return this.connections.has(peerId) && this.peerAddresses.has(peerId);
  }

  close(peerId) {
    this.connections.delete(peerId);
    this.peerAddresses.delete(peerId);
    this.sessionKeys.delete(peerId);
    this.emit('peer-disconnected', peerId);
  }

  closeAll() {
    if (this.portHoppingTimer) {
      clearInterval(this.portHoppingTimer);
    }
    
    for (const peerId of this.connections.keys()) {
      this.close(peerId);
    }
    
    if (this.socket) {
      this.socket.close();
    }
  }

  getConnectedPeers() {
    return Array.from(this.connections.keys());
  }

  getPort() {
    return this.port;
  }

  _handleMessage(msg, rinfo) {
    if (msg.length < 17) {
      return;
    }
    
    const peerIdBuffer = msg.subarray(0, 16);
    const peerId = peerIdBuffer.toString().replace(/\0/g, '').trim();
    const encrypted = msg.subarray(16);
    
    const sessionKey = this.sessionKeys.get(peerId);
    if (!sessionKey) {
      return;
    }
    
    try {
      const decrypted = this._decrypt(encrypted, sessionKey);
      
      this.peerAddresses.set(peerId, { address: rinfo.address, port: rinfo.port });
      
      if (!this.connections.has(peerId)) {
        this.connections.set(peerId, true);
        this.emit('peer-connected', peerId);
      }
      
      this.emit('message', peerId, decrypted);
    } catch (err) {
      console.error(`Failed to decrypt message from ${peerId}:`, err.message);
    }
  }

  _encrypt(data, key) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]);
  }

  _decrypt(data, key) {
    const iv = data.subarray(0, 12);
    const authTag = data.subarray(12, 28);
    const encrypted = data.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  async _startPortHopping() {
    this.portHoppingTimer = setInterval(async () => {
      const oldPort = this.port;
      const newPort = 10000 + Math.floor(Math.random() * 55000);
      
      try {
        await this._rebind(newPort);
        this.emit('port-changed', { oldPort, newPort });
      } catch (err) {
        console.error('Port hopping failed:', err.message);
      }
    }, this.portHoppingInterval);
  }

  async _rebind(newPort) {
    return new Promise((resolve, reject) => {
      const newSocket = dgram.createSocket('udp4');
      
      newSocket.on('error', reject);
      
      newSocket.on('message', (msg, rinfo) => {
        this._handleMessage(msg, rinfo);
      });
      
      newSocket.on('listening', () => {
        const oldSocket = this.socket;
        this.socket = newSocket;
        this.port = newPort;
        
        if (oldSocket) {
          oldSocket.close();
        }
        
        resolve();
      });
      
      newSocket.bind(newPort);
    });
  }
}
