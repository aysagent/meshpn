import { EventEmitter } from 'events';
import { WebRTCTransport } from './webrtc.js';
import { QuicTransport } from './quic.js';
import { WebSocketTransport } from './websocket.js';

const TRANSPORT_PRIORITY = ['webrtc', 'quic', 'websocket'];

export class TransportManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = config;
    this.transports = new Map();
    this.peerTransports = new Map();
    this.preferredOrder = config.preferredOrder || TRANSPORT_PRIORITY;
    
    this._initTransports();
  }

  _initTransports() {
    if (this.config.webrtc !== false) {
      const webrtc = new WebRTCTransport(this.config.webrtc || {});
      this._setupTransportEvents('webrtc', webrtc);
      this.transports.set('webrtc', webrtc);
    }
    
    if (this.config.quic !== false) {
      const quic = new QuicTransport(this.config.quic || {});
      this._setupTransportEvents('quic', quic);
      this.transports.set('quic', quic);
    }
    
    if (this.config.websocket !== false) {
      const websocket = new WebSocketTransport(this.config.websocket || {});
      this._setupTransportEvents('websocket', websocket);
      this.transports.set('websocket', websocket);
    }
  }

  _setupTransportEvents(type, transport) {
    transport.on('peer-connected', (peerId) => {
      if (!this.peerTransports.has(peerId)) {
        this.peerTransports.set(peerId, new Set());
      }
      this.peerTransports.get(peerId).add(type);
      this.emit('peer-connected', peerId, type);
    });
    
    transport.on('peer-disconnected', (peerId) => {
      const transports = this.peerTransports.get(peerId);
      if (transports) {
        transports.delete(type);
        if (transports.size === 0) {
          this.peerTransports.delete(peerId);
          this.emit('peer-disconnected', peerId);
        }
      }
    });
    
    transport.on('message', (peerId, data) => {
      this.emit('message', peerId, data, type);
    });
    
    transport.on('ice-candidate', (peerId, candidate) => {
      this.emit('ice-candidate', peerId, candidate);
    });
    
    transport.on('error', (peerId, err) => {
      this.emit('transport-error', type, peerId, err);
    });
  }

  getTransport(type) {
    return this.transports.get(type);
  }

  async startQuic() {
    const quic = this.transports.get('quic');
    if (quic) {
      return await quic.start();
    }
    return null;
  }

  async testTurnConnectivity() {
    const webrtc = this.transports.get('webrtc');
    if (webrtc && webrtc.testTurnConnectivity) {
      return await webrtc.testTurnConnectivity();
    }
    return { success: false, reason: 'no_webrtc_transport' };
  }

  async createWebRTCOffer(peerId) {
    const webrtc = this.transports.get('webrtc');
    if (!webrtc) {
      throw new Error('WebRTC transport not available');
    }
    return await webrtc.createOffer(peerId);
  }

  async handleWebRTCOffer(peerId, offer) {
    const webrtc = this.transports.get('webrtc');
    if (!webrtc) {
      throw new Error('WebRTC transport not available');
    }
    return await webrtc.handleOffer(peerId, offer);
  }

  async handleWebRTCAnswer(peerId, answer) {
    const webrtc = this.transports.get('webrtc');
    if (!webrtc) {
      throw new Error('WebRTC transport not available');
    }
    await webrtc.handleAnswer(peerId, answer);
  }

  async addIceCandidate(peerId, candidate) {
    const webrtc = this.transports.get('webrtc');
    if (webrtc) {
      await webrtc.addIceCandidate(peerId, candidate);
    }
  }

  send(peerId, data, preferredTransport = null) {
    const transports = this.peerTransports.get(peerId);
    if (!transports || transports.size === 0) {
      return false;
    }
    
    const order = preferredTransport 
      ? [preferredTransport, ...this.preferredOrder.filter(t => t !== preferredTransport)]
      : this.preferredOrder;
    
    for (const type of order) {
      if (transports.has(type)) {
        const transport = this.transports.get(type);
        if (transport && transport.send(peerId, data)) {
          return true;
        }
      }
    }
    
    return false;
  }

  broadcast(data, excludePeers = []) {
    const peers = this.getConnectedPeers();
    const results = new Map();
    
    for (const peerId of peers) {
      if (!excludePeers.includes(peerId)) {
        results.set(peerId, this.send(peerId, data));
      }
    }
    
    return results;
  }

  isConnected(peerId) {
    const transports = this.peerTransports.get(peerId);
    return transports && transports.size > 0;
  }

  getConnectedPeers() {
    return Array.from(this.peerTransports.keys());
  }

  getAvailableTransports(peerId) {
    return Array.from(this.peerTransports.get(peerId) || []);
  }

  close(peerId) {
    for (const transport of this.transports.values()) {
      transport.close(peerId);
    }
    this.peerTransports.delete(peerId);
  }

  closeAll() {
    for (const transport of this.transports.values()) {
      transport.closeAll();
    }
    this.peerTransports.clear();
  }

  setQuicSessionKey(peerId, key) {
    const quic = this.transports.get('quic');
    if (quic) {
      quic.setSessionKey(peerId, key);
    }
  }

  setQuicPeerAddress(peerId, address, port) {
    const quic = this.transports.get('quic');
    if (quic) {
      quic.setPeerAddress(peerId, address, port);
    }
  }
}
