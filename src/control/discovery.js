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
  }

  async start(role = 'client') {
    this.signalling = new SignallingClient(
      this.config.signallingServer,
      this.identity
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
      this.establishedPeers.add(peerId);
      this.pendingConnections.delete(peerId);
      
      this._updateTopology();
      this.emit('peer-connected', peerId, transport);
    });
    
    this.transportManager.on('peer-disconnected', (peerId) => {
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
    if (this.pendingConnections.has(peer.nodeId) || 
        this.establishedPeers.has(peer.nodeId)) {
      return;
    }
    
    if (this.identity.nodeId > peer.nodeId) {
      return;
    }
    
    this.pendingConnections.set(peer.nodeId, {
      peer,
      initiator: true,
      timestamp: Date.now()
    });
    
    try {
      const myEphemeralPubKey = this.sessionManager.createSession(peer.nodeId);
      
      const offer = await this.transportManager.createWebRTCOffer(peer.nodeId);
      
      this.signalling.sendSignal(peer.nodeId, {
        type: 'offer',
        offer,
        ephemeralPubKey: myEphemeralPubKey
      });
    } catch (err) {
      console.error(`Failed to create offer for ${peer.nodeId}:`, err.message);
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
    }
  }

  async _handleOffer(fromNodeId, signal) {
    this.pendingConnections.set(fromNodeId, {
      initiator: false,
      timestamp: Date.now()
    });
    
    try {
      const myEphemeralPubKey = this.sessionManager.createSession(fromNodeId);
      
      if (signal.ephemeralPubKey) {
        this.sessionManager.completeSession(fromNodeId, signal.ephemeralPubKey);
      }
      
      const answer = await this.transportManager.handleWebRTCOffer(fromNodeId, signal.offer);
      
      this.signalling.sendSignal(fromNodeId, {
        type: 'answer',
        answer,
        ephemeralPubKey: myEphemeralPubKey
      });
      
      const sessionKey = this.sessionManager.getSessionKey(fromNodeId);
      if (sessionKey) {
        this.transportManager.setQuicSessionKey(fromNodeId, sessionKey);
      }
    } catch (err) {
      console.error(`Failed to handle offer from ${fromNodeId}:`, err.message);
      this.pendingConnections.delete(fromNodeId);
    }
  }

  async _handleAnswer(fromNodeId, signal) {
    try {
      await this.transportManager.handleWebRTCAnswer(fromNodeId, signal.answer);
      
      if (signal.ephemeralPubKey) {
        this.sessionManager.completeSession(fromNodeId, signal.ephemeralPubKey);
        
        const sessionKey = this.sessionManager.getSessionKey(fromNodeId);
        if (sessionKey) {
          this.transportManager.setQuicSessionKey(fromNodeId, sessionKey);
        }
      }
    } catch (err) {
      console.error(`Failed to handle answer from ${fromNodeId}:`, err.message);
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
