import { EventEmitter } from 'events';
import { SignallingClient } from './signalling.js';
import { SessionManager } from '../crypto/session.js';
import { sessionDebugLog } from '../debug/session-log.js';

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

    /** Цепочка Promise: сообщения signalling обрабатываются по одному (иначе ICE может прийти до setRemoteDescription). */
    this._signallingWorkChain = Promise.resolve();

    /**
     * peer-leave от сервера часто гоняется с mesh auto-reconnect (ICE упал, exit шлёт новый offer).
     * Немедленный close() убивает новый PC. Откладываем leave и снимаем при peer-join / peer-connected.
     * 450ms мало для ICE (логи: H2_apply срабатывал до peer-connected). Берём запас под offer/answer/ICE.
     */
    this._peerLeaveDelayMs = 4000;
    /** @type {Map<string, ReturnType<typeof setTimeout>>} */
    this._peerLeaveTimers = new Map();
  }

  _clearPendingPeerLeave(nodeId) {
    const t = this._peerLeaveTimers.get(nodeId);
    if (t != null) {
      clearTimeout(t);
      this._peerLeaveTimers.delete(nodeId);
    }
  }

  _enqueueSignallingWork(fn) {
    this._signallingWorkChain = this._signallingWorkChain
      .then(() => fn())
      .catch((err) => {
        console.error('[DISCOVERY] Signalling async handler error:', err?.message || err);
      });
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
      this._enqueueSignallingWork(() => this._handlePeersUpdate(peers));
    });

    this.signalling.on('peer-join', (peer) => {
      this._clearPendingPeerLeave(peer.nodeId);
      this._enqueueSignallingWork(async () => {
        await this._supersedePendingMeshHandshake(peer.nodeId, 'peer-join');
        await this._initiateConnection(peer);
      });
    });

    this.signalling.on('peer-leave', (nodeId) => {
      this._enqueueSignallingWork(() => {
        this._handlePeerLeave(nodeId);
      });
    });

    this.signalling.on('signal', (fromNodeId, signal) => {
      this._enqueueSignallingWork(() => this._handleSignal(fromNodeId, signal));
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
      this._clearPendingPeerLeave(peerId);
      console.log(`[DISCOVERY] Transport peer-connected: ${peerId} via ${transport}`);
      this.establishedPeers.add(peerId);
      this.pendingConnections.delete(peerId);
      
      this._updateTopology();
      this.emit('peer-connected', peerId, transport);
    });
    
    this.transportManager.on('peer-disconnected', (peerId) => {
      console.log(`[DISCOVERY] Transport peer-disconnected: ${peerId}`);
      const stillInSignalling = !!this.signalling?.getPeer?.(peerId);
      // #region agent log
      sessionDebugLog({
        runId: 'webrtc-drop',
        hypothesisId: 'H_peer_disconnected_ctx',
        location: 'discovery.js:peer-disconnected',
        message: 'transport peer-disconnected',
        data: {
          peerId: (peerId || '').slice(0, 12),
          stillInSignalling,
          myId: (this.identity?.nodeId || '').slice(0, 12),
        },
      });
      // #endregion
      this.establishedPeers.delete(peerId);
      this.sessionManager.removeSession(peerId);

      this._updateTopology();
      this.emit('peer-disconnected', peerId);

      if (stillInSignalling) {
        this._enqueueSignallingWork(() => this._maybeReconnectMeshPeer(peerId));
      }
    });
  }

  /**
   * ICE/WebRTC мог упасть без peer-leave; если пир всё ещё в списке signalling — новый handshake.
   * После реального peer-leave пира уже нет в signalling — повтор не запускаем.
   */
  async _maybeReconnectMeshPeer(peerId) {
    const peer = this.signalling?.getPeer?.(peerId);
    if (!peer) {
      return;
    }
    if (this.establishedPeers.has(peerId) || this.pendingConnections.has(peerId)) {
      return;
    }
    console.warn(`[DISCOVERY] Mesh reconnect to ${peerId} (signalling still lists peer)`);
    // #region agent log
    sessionDebugLog({
      runId: 'webrtc-drop',
      hypothesisId: 'H_mesh_auto_reconnect',
      location: 'discovery.js:_maybeReconnectMeshPeer',
      message: 'scheduling _initiateConnection after transport drop',
      data: { peerId: (peerId || '').slice(0, 12) },
    });
    // #endregion
    await this._initiateConnection(peer);
  }

  async _handlePeersUpdate(peers) {
    for (const peer of peers) {
      this._clearPendingPeerLeave(peer.nodeId);
      if (this.establishedPeers.has(peer.nodeId)) {
        continue;
      }
      await this._supersedePendingMeshHandshake(peer.nodeId, 'peers-updated');
      await this._initiateConnection(peer);
    }
  }

  /**
   * Сервер прислал peer-join / полный список: старый in-flight offer (pending) без established
   * нельзя оставлять — иначе _initiateConnection делает «Skipping … already pending» и mesh залипает.
   */
  async _supersedePendingMeshHandshake(nodeId, reason) {
    if (this.establishedPeers.has(nodeId) || !this.pendingConnections.has(nodeId)) {
      return;
    }
    // #region agent log
    sessionDebugLog({
      runId: 'webrtc-drop',
      hypothesisId: 'H8_peer_join_supersedes_pending',
      location: 'discovery.js:_supersedePendingMeshHandshake',
      message: 'reset stale pending transport before new handshake',
      data: {
        nodeId: (nodeId || '').slice(0, 12),
        reason,
        myId: (this.identity?.nodeId || '').slice(0, 12),
      },
    });
    // #endregion
    console.warn(`[DISCOVERY] Superseding stale pending handshake for ${nodeId} (${reason})`);
    this.pendingConnections.delete(nodeId);
    this.transportManager.close(nodeId);
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
    
    console.log(
      `[DISCOVERY] Creating WebRTC offer for ${peer.nodeId} at ${new Date().toISOString()}`,
    );
    
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
    // #region agent log
    sessionDebugLog({
      runId: 'webrtc-drop',
      hypothesisId: 'H2_peer_leave_scheduled',
      location: 'discovery.js:_handlePeerLeave',
      message: 'peer-leave debounced',
      data: {
        nodeId: (nodeId || '').slice(0, 12),
        myId: (this.identity?.nodeId || '').slice(0, 12),
        delayMs: this._peerLeaveDelayMs,
      },
    });
    // #endregion
    this._clearPendingPeerLeave(nodeId);
    const timer = setTimeout(() => {
      this._peerLeaveTimers.delete(nodeId);
      this._applyPeerLeave(nodeId);
    }, this._peerLeaveDelayMs);
    this._peerLeaveTimers.set(nodeId, timer);
  }

  _applyPeerLeave(nodeId) {
    if (this.signalling?.getPeer?.(nodeId)) {
      // #region agent log
      sessionDebugLog({
        runId: 'webrtc-drop',
        hypothesisId: 'H7_apply_peer_leave_skipped',
        location: 'discovery.js:_applyPeerLeave',
        message: 'skip close: peer again in signalling roster',
        data: { nodeId: (nodeId || '').slice(0, 12), myId: (this.identity?.nodeId || '').slice(0, 12) },
      });
      // #endregion
      console.log(`[DISCOVERY] _applyPeerLeave skipped (signalling still has peer): ${nodeId}`);
      return;
    }
    if (this.transportManager?.isConnected?.(nodeId)) {
      // #region agent log
      sessionDebugLog({
        runId: 'webrtc-drop',
        hypothesisId: 'H7_apply_peer_leave_skipped',
        location: 'discovery.js:_applyPeerLeave',
        message: 'skip close: transport already connected',
        data: { nodeId: (nodeId || '').slice(0, 12), myId: (this.identity?.nodeId || '').slice(0, 12) },
      });
      // #endregion
      console.log(`[DISCOVERY] _applyPeerLeave skipped (transport connected): ${nodeId}`);
      return;
    }

    console.warn(`[DISCOVERY] _applyPeerLeave → close transport: ${nodeId}`);
    // #region agent log
    sessionDebugLog({
      runId: 'webrtc-drop',
      hypothesisId: 'H2_discovery_applyPeerLeave',
      location: 'discovery.js:_applyPeerLeave',
      message: 'closing transport and session after debounce',
      data: { nodeId: (nodeId || '').slice(0, 12), myId: (this.identity?.nodeId || '').slice(0, 12) },
    });
    // #endregion
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
    for (const t of this._peerLeaveTimers.values()) {
      clearTimeout(t);
    }
    this._peerLeaveTimers.clear();
    if (this.signalling) {
      this.signalling.disconnect();
    }
    this.transportManager.closeAll();
    this.sessionManager.clear();
    this.pendingConnections.clear();
    this.establishedPeers.clear();
  }
}
