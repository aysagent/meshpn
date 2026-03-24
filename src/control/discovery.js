import { EventEmitter } from 'events';
import { SignallingClient } from './signalling.js';
import { SessionManager } from '../crypto/session.js';

export class PeerDiscovery extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.identity = config.identity;
    this.transportManager = config.transportManager;
    this.signalling = null;
    this.sessionManager = new SessionManager();
    this.pendingConnections = new Map();
    this.establishedPeers = new Set();
    this.transportMode = config.transportMode || 'webrtc';
    this.dataServer = config.dataServer || null;
    
    console.log(`[DISCOVERY] Transport mode: ${this.transportMode}, dataServer: ${this.dataServer}`);
    
    this.transportManager.setLocalNodeId(this.identity.nodeId);
  }

  async start(role = 'client') {
    this.signalling = new SignallingClient(
      this.config.signallingServer,
      this.identity,
      this.config.signalling && typeof this.config.signalling === 'object'
        ? this.config.signalling
        : {},
    );
    
    this._setupSignallingEvents();
    this._setupTransportEvents();
    
    await this.signalling.connect(role);
  }

  _setupSignallingEvents() {
    this.signalling.on('registered', (info) => {
      this.emit('registered', info);
    });
    
    this.signalling.on('peers-updated', (peers) => {
      this._handlePeersUpdate(peers);
    });
    
    this.signalling.on('peer-join', (peer) => {
      this._initiateConnection(peer);
    });
    
    this.signalling.on('peer-leave', (nodeId) => {
      this._handlePeerLeave(nodeId);
    });
    
    this.signalling.on('signal', (fromNodeId, signal) => {
      this._handleSignal(fromNodeId, signal);
    });
    
    this.signalling.on('topology', (topology) => {
      this.emit('topology', topology);
    });
    
    this.signalling.on('disconnected', () => {
      this.emit('signalling-disconnected');
    });
    
    this.signalling.on('reconnected', () => {
      this.emit('signalling-reconnected');
    });
  }

  _setupTransportEvents() {
    this.transportManager.on('ice-candidate', (peerId, candidate) => {
      this.signalling.sendSignal(peerId, {
        type: 'ice-candidate',
        candidate
      });
    });
    
    this.transportManager.on('peer-connected', (peerId, transport) => {
      console.log(`[DISCOVERY] Transport peer-connected: ${peerId} via ${transport}`);
      this.establishedPeers.add(peerId);
      this.pendingConnections.delete(peerId);
      
      this._updateTopology();
      this.emit('peer-connected', peerId, transport);
    });
    
    this.transportManager.on('peer-disconnected', (peerId) => {
      console.log(`[DISCOVERY] Transport peer-disconnected: ${peerId}`);
      this.establishedPeers.delete(peerId);
      this.sessionManager.removeSession(peerId);
      
      this._updateTopology();
      this.emit('peer-disconnected', peerId);
    });
  }

  async _handlePeersUpdate(peers) {
    for (const peer of peers) {
      if (!this.establishedPeers.has(peer.nodeId) && 
          !this.pendingConnections.has(peer.nodeId)) {
        await this._initiateConnection(peer);
      }
    }
  }

  async _initiateConnection(peer) {
    console.log(`[DISCOVERY] Initiating connection to ${peer.nodeId}, myId=${this.identity.nodeId}`);
    
    if (this.pendingConnections.has(peer.nodeId) || 
        this.establishedPeers.has(peer.nodeId)) {
      console.log(`[DISCOVERY] Skipping ${peer.nodeId} - already pending or established`);
      return;
    }
    
    const wsUrl = peer.dataServer || this.dataServer;
    const shouldTryWebSocket = (this.transportMode === 'websocket' || this.transportMode === 'auto') && wsUrl;
    
    console.log(`[DISCOVERY] shouldTryWebSocket=${shouldTryWebSocket}, wsUrl=${wsUrl}, transportMode=${this.transportMode}`);
    
    // For WebSocket, always try to connect (it's client-server, not P2P negotiation)
    // For WebRTC, use nodeId comparison to avoid duplicate offers
    if (!shouldTryWebSocket && this.identity.nodeId > peer.nodeId) {
      console.log(`[DISCOVERY] Skipping ${peer.nodeId} - waiting for peer to initiate WebRTC (myId > peerId)`);
      return;
    }
    
    this.pendingConnections.set(peer.nodeId, {
      peer,
      initiator: true,
      timestamp: Date.now()
    });
    
    const myEphemeralPubKey = this.sessionManager.createSession(peer.nodeId);
    
    if (shouldTryWebSocket) {
      try {
        console.log(`[DISCOVERY] Trying WebSocket connection to ${peer.nodeId} at ${wsUrl}`);
        await this.transportManager.connectWebSocket(peer.nodeId, wsUrl, 5000);
        
        this.signalling.sendSignal(peer.nodeId, {
          type: 'session-key',
          ephemeralPubKey: myEphemeralPubKey
        });
        
        console.log(`[DISCOVERY] WebSocket connection established to ${peer.nodeId}`);
        return;
      } catch (err) {
        console.log(`[DISCOVERY] WebSocket failed for ${peer.nodeId}: ${err.message}`);
        if (this.transportMode === 'websocket') {
          this.pendingConnections.delete(peer.nodeId);
          return;
        }
      }
    }
    
    console.log(`[DISCOVERY] Creating WebRTC offer for ${peer.nodeId}`);
    
    try {
      const offer = await this.transportManager.createWebRTCOffer(peer.nodeId);
      
      this.signalling.sendSignal(peer.nodeId, {
        type: 'offer',
        offer,
        ephemeralPubKey: myEphemeralPubKey
      });
      
      console.log(`[DISCOVERY] Offer sent to ${peer.nodeId}`);
    } catch (err) {
      console.error(`[DISCOVERY] Failed to create offer for ${peer.nodeId}:`, err.message);
      this.pendingConnections.delete(peer.nodeId);
    }
  }

  async _handleSignal(fromNodeId, signal) {
    switch (signal.type) {
      case 'offer':
        await this._handleOffer(fromNodeId, signal);
        break;
        
      case 'answer':
        await this._handleAnswer(fromNodeId, signal);
        break;
        
      case 'ice-candidate':
        await this.transportManager.addIceCandidate(fromNodeId, signal.candidate);
        break;
        
      case 'session-key':
        this._handleSessionKey(fromNodeId, signal);
        break;
        
      case 'session-key-ack':
        this._handleSessionKeyAck(fromNodeId, signal);
        break;
    }
  }
  
  _handleSessionKey(fromNodeId, signal) {
    console.log(`[DISCOVERY] Received session key from ${fromNodeId}`);
    
    if (signal.ephemeralPubKey) {
      const myEphemeralPubKey = this.sessionManager.createSession(fromNodeId);
      this.sessionManager.completeSession(fromNodeId, signal.ephemeralPubKey);
      console.log(`[DISCOVERY] Session key established with ${fromNodeId}`);
      
      this.signalling.sendSignal(fromNodeId, {
        type: 'session-key-ack',
        ephemeralPubKey: myEphemeralPubKey
      });
    }
  }
  
  _handleSessionKeyAck(fromNodeId, signal) {
    console.log(`[DISCOVERY] Received session key ack from ${fromNodeId}`);
    
    if (signal.ephemeralPubKey) {
      this.sessionManager.completeSession(fromNodeId, signal.ephemeralPubKey);
      console.log(`[DISCOVERY] Session key completed with ${fromNodeId}`);
    }
  }

  async _handleOffer(fromNodeId, signal) {
    console.log(`[DISCOVERY] Received offer from ${fromNodeId}`);
    
    // Skip WebRTC if already connected via WebSocket
    if (this.transportManager.isConnected(fromNodeId)) {
      const transports = this.transportManager.getAvailableTransports(fromNodeId);
      if (transports.includes('websocket')) {
        console.log(`[DISCOVERY] Skipping WebRTC offer from ${fromNodeId} - already connected via WebSocket`);
        return;
      }
    }
    
    this.pendingConnections.set(fromNodeId, {
      initiator: false,
      timestamp: Date.now()
    });
    
    try {
      const myEphemeralPubKey = this.sessionManager.createSession(fromNodeId);
      
      if (signal.ephemeralPubKey) {
        this.sessionManager.completeSession(fromNodeId, signal.ephemeralPubKey);
        console.log(`[DISCOVERY] Session key established with ${fromNodeId}`);
      }
      
      const answer = await this.transportManager.handleWebRTCOffer(fromNodeId, signal.offer);
      
      this.signalling.sendSignal(fromNodeId, {
        type: 'answer',
        answer,
        ephemeralPubKey: myEphemeralPubKey
      });
      
      console.log(`[DISCOVERY] Answer sent to ${fromNodeId}`);
      
      const sessionKey = this.sessionManager.getSessionKey(fromNodeId);
      if (sessionKey) {
        this.transportManager.setQuicSessionKey(fromNodeId, sessionKey);
      }
    } catch (err) {
      console.error(`[DISCOVERY] Failed to handle offer from ${fromNodeId}:`, err.message);
      this.pendingConnections.delete(fromNodeId);
    }
  }

  async _handleAnswer(fromNodeId, signal) {
    console.log(`[DISCOVERY] Received answer from ${fromNodeId}`);
    
    try {
      await this.transportManager.handleWebRTCAnswer(fromNodeId, signal.answer);
      
      if (signal.ephemeralPubKey) {
        this.sessionManager.completeSession(fromNodeId, signal.ephemeralPubKey);
        console.log(`[DISCOVERY] Session key established with ${fromNodeId}`);
        
        const sessionKey = this.sessionManager.getSessionKey(fromNodeId);
        if (sessionKey) {
          this.transportManager.setQuicSessionKey(fromNodeId, sessionKey);
        }
      }
    } catch (err) {
      console.error(`[DISCOVERY] Failed to handle answer from ${fromNodeId}:`, err.message);
      this.pendingConnections.delete(fromNodeId);
    }
  }

  _handlePeerLeave(nodeId) {
    this.pendingConnections.delete(nodeId);
    this.establishedPeers.delete(nodeId);
    this.sessionManager.removeSession(nodeId);
    this.transportManager.close(nodeId);
    
    this.emit('peer-leave', nodeId);
  }

  _updateTopology() {
    this.signalling.updateTopology(Array.from(this.establishedPeers));
  }

  getSessionKey(peerId) {
    return this.sessionManager.getSessionKey(peerId);
  }

  getVirtualIp() {
    return this.signalling?.virtualIp;
  }

  getAllPeers() {
    return this.signalling?.getAllPeers() || [];
  }

  getExitNodes() {
    return this.signalling?.getExitNodes() || [];
  }

  getConnectedPeers() {
    return Array.from(this.establishedPeers);
  }

  stop() {
    if (this.signalling) {
      this.signalling.disconnect();
    }
    this.transportManager.closeAll();
    this.sessionManager.clear();
    this.pendingConnections.clear();
    this.establishedPeers.clear();
  }
}
