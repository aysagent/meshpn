import { EventEmitter } from 'events';
import { Identity, SessionManager } from '../crypto/index.js';
import { createOnionPacket, peelOnionLayer } from '../crypto/onion.js';
import { encrypt, decrypt } from '../crypto/encrypt.js';
import { TransportManager } from '../transport/index.js';
import { PeerDiscovery } from '../control/index.js';
import { MeshRouter, MultipathScheduler, ReorderBuffer } from './index.js';
import { TunManager, Packet, PacketType, parseIPPacket } from '../network/index.js';
import { ExitNode } from '../exit/index.js';

export class MeshNode extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.role = config.role || 'client';
    
    this.identity = config.identity || new Identity(config.privateKey);
    this.nodeId = this.identity.nodeId;
    
    this.sessionManager = new SessionManager();
    
    this.transportManager = new TransportManager({
      webrtc: {
        iceServers: config.iceServers || [
          { urls: 'stun:stun.l.google.com:19302' }
        ]
      },
      quic: config.quic || {},
      websocket: config.websocket || {}
    });
    
    this.discovery = new PeerDiscovery({
      identity: this.identity,
      transportManager: this.transportManager,
      signallingServer: config.signallingServer
    });
    
    this.router = new MeshRouter({
      localNodeId: this.nodeId,
      sessionManager: this.sessionManager
    });
    
    this.scheduler = new MultipathScheduler({
      strategy: config.multipathStrategy || 'round-robin'
    });
    
    this.reorderBuffer = new ReorderBuffer({
      windowSize: config.reorderWindowSize || 1000,
      timeout: config.reorderTimeout || 5000
    });
    
    this.processedPackets = new Map();
    this.packetCacheTTL = config.packetCacheTTL || 60000;
    this.cacheCleanupInterval = null;
    
    this.loopStats = {
      ttlDropped: 0,
      duplicateDropped: 0,
      loopDropped: 0,
      splitHorizonDropped: 0,
      totalProcessed: 0,
      totalForwarded: 0
    };
    
    this.tunManager = null;
    this.exitNodeHandler = null;
    this.virtualIp = null;
    this.running = false;
  }

  _isPacketDuplicate(packet) {
    const key = `${packet.flowId}:${packet.seq}`;
    if (this.processedPackets.has(key)) {
      return true;
    }
    this.processedPackets.set(key, Date.now());
    return false;
  }

  _startCacheCleanup() {
    this.cacheCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, timestamp] of this.processedPackets) {
        if (now - timestamp > this.packetCacheTTL) {
          this.processedPackets.delete(key);
        }
      }
    }, 30000);
  }

  _stopCacheCleanup() {
    if (this.cacheCleanupInterval) {
      clearInterval(this.cacheCleanupInterval);
      this.cacheCleanupInterval = null;
    }
  }

  async start() {
    console.log(`Starting mesh node ${this.nodeId} as ${this.role}...`);
    
    this._setupEventHandlers();
    
    await this.discovery.start(this.role);
    
    if (this.role === 'exit') {
      this.exitNodeHandler = new ExitNode({
        nodeId: this.nodeId
      });
      
      this.exitNodeHandler.on('internet-response', (response) => {
        this._handleInternetResponse(response);
      });
      
      await this.exitNodeHandler.start();
      console.log('Exit node handler started');
    }
    
    this.reorderBuffer.start();
    this._startCacheCleanup();
    
    this.running = true;
    this.emit('started');
    
    console.log(`Mesh node ${this.nodeId} started successfully`);
  }

  _setupEventHandlers() {
    this.discovery.on('registered', async (info) => {
      this.virtualIp = info.virtualIp;
      console.log(`Registered with virtual IP: ${this.virtualIp}`);
      
      if (this.role === 'client' && this.config.enableTun !== false) {
        this.tunManager = new TunManager(this.config.tun || {});
        
        this.tunManager.on('outbound-packet', (packet) => {
          this._handleOutboundPacket(packet);
        });
        
        try {
          await this.tunManager.setup(this.virtualIp);
        } catch (err) {
          console.warn('TUN setup failed, running in relay mode:', err.message);
        }
      }
      
      this.emit('registered', info);
    });
    
    this.discovery.on('peer-connected', (peerId, transport) => {
      console.log(`Peer connected: ${peerId} via ${transport}`);
      
      const peerInfo = this.discovery.getAllPeers().find(p => p.nodeId === peerId);
      if (peerInfo) {
        this.router.addLocalConnection(peerId, peerInfo);
      }
      
      this._updateMultipathRoutes();
      this.emit('peer-connected', peerId);
    });
    
    this.discovery.on('peer-disconnected', (peerId) => {
      console.log(`Peer disconnected: ${peerId}`);
      this.router.removeLocalConnection(peerId);
      this._updateMultipathRoutes();
      this.emit('peer-disconnected', peerId);
    });
    
    this.discovery.on('topology', (topology) => {
      this.router.updateTopology(topology);
      this._updateMultipathRoutes();
    });
    
    this.transportManager.on('message', (peerId, data, transport) => {
      this._handleIncomingMessage(peerId, data);
    });
    
    this.reorderBuffer.on('packet', (payload, packet) => {
      this._processReorderedPacket(payload, packet);
    });
  }

  _handleOutboundPacket(ipPacket) {
    if (!this.running) return;
    
    const parsed = parseIPPacket(ipPacket);
    if (!parsed || !parsed.valid) return;
    
    const routeInfo = this.router.findRouteToExit();
    if (!routeInfo) {
      console.warn('No route to exit node available');
      return;
    }
    
    this._sendThroughMesh(ipPacket, routeInfo);
  }

  _sendThroughMesh(payload, routeInfo) {
    const { route, exitNode } = routeInfo;
    
    const routeWithKeys = [];
    for (const nodeId of route) {
      const sessionKey = this.discovery.getSessionKey(nodeId);
      if (!sessionKey) {
        console.warn(`No session key for ${nodeId}`);
        return;
      }
      routeWithKeys.push({ nodeId, sessionKey });
    }
    
    try {
      const onionPacket = createOnionPacket(payload, routeWithKeys);
      
      const packet = new Packet({
        type: PacketType.DATA,
        srcNode: this.nodeId,
        dstNode: exitNode,
        route,
        payload: onionPacket
      });
      
      const nextHop = route[0];
      const serialized = packet.serialize();
      
      if (!this.transportManager.send(nextHop, serialized)) {
        console.warn(`Failed to send to ${nextHop}`);
      }
    } catch (err) {
      console.error('Failed to create onion packet:', err.message);
    }
  }

  _handleIncomingMessage(peerId, data) {
    try {
      const packet = Packet.deserialize(data);
      
      switch (packet.type) {
        case PacketType.DATA:
          this._handleDataPacket(peerId, packet);
          break;
        case PacketType.PING:
          this._handlePing(peerId, packet);
          break;
        case PacketType.PONG:
          this._handlePong(peerId, packet);
          break;
        case PacketType.ACK:
          this._handleAck(peerId, packet);
          break;
        default:
          console.warn(`Unknown packet type: ${packet.type}`);
      }
    } catch (err) {
      console.error('Failed to process incoming message:', err.message);
    }
  }

  _handleDataPacket(peerId, packet) {
    this.loopStats.totalProcessed++;
    
    if (packet.isTTLExpired()) {
      this.loopStats.ttlDropped++;
      console.warn(`Dropping packet ${packet.flowId}: TTL expired`);
      return;
    }
    
    if (this._isPacketDuplicate(packet)) {
      this.loopStats.duplicateDropped++;
      return;
    }
    
    if (packet.hasVisited(this.nodeId)) {
      this.loopStats.loopDropped++;
      console.warn(`Dropping packet ${packet.flowId}: loop detected (already visited ${this.nodeId})`);
      return;
    }
    
    packet.addVisitedNode(this.nodeId);
    
    if (!packet.decrementTTL()) {
      this.loopStats.ttlDropped++;
      console.warn(`Dropping packet ${packet.flowId}: TTL reached zero`);
      return;
    }
    
    const sessionKey = this.discovery.getSessionKey(peerId);
    if (!sessionKey) {
      console.warn(`No session key for ${peerId}`);
      return;
    }
    
    try {
      const layer = peelOnionLayer(packet.payload, sessionKey);
      
      if (layer.isExit) {
        if (this.role === 'exit' && this.exitNodeHandler) {
          this._processExitPacket(packet, layer.payload);
        } else {
          console.warn('Received exit packet but not an exit node');
        }
      } else if (layer.nextHop) {
        this._forwardPacket(packet, layer.nextHop, layer.payload, peerId);
      }
    } catch (err) {
      console.error('Failed to peel onion layer:', err.message);
    }
  }

  _forwardPacket(originalPacket, nextHop, newPayload, fromPeerId = null) {
    if (nextHop === fromPeerId) {
      this.loopStats.splitHorizonDropped++;
      console.warn(`Split horizon: refusing to send packet ${originalPacket.flowId} back to ${fromPeerId}`);
      return;
    }
    
    if (nextHop === originalPacket.srcNode) {
      this.loopStats.loopDropped++;
      console.warn(`Loop prevention: refusing to send packet back to source ${nextHop}`);
      return;
    }
    
    const forwardPacket = originalPacket.clone();
    forwardPacket.payload = newPayload;
    forwardPacket.incrementHop();
    
    const serialized = forwardPacket.serialize();
    
    if (this.transportManager.send(nextHop, serialized)) {
      this.loopStats.totalForwarded++;
    } else {
      console.warn(`Failed to forward to ${nextHop}`);
    }
  }

  async _processExitPacket(packet, payload) {
    if (!this.exitNodeHandler) return;
    
    try {
      await this.exitNodeHandler.processPacket(packet, payload);
    } catch (err) {
      console.error('Exit processing failed:', err.message);
    }
  }

  _handleInternetResponse(response) {
    const { srcNodeId, srcIp, srcPort, data, protocol } = response;
    
    const routeInfo = this.router.graph.findShortestPath(this.nodeId, srcNodeId);
    if (!routeInfo || routeInfo.length < 2) {
      console.warn(`No route back to ${srcNodeId}`);
      return;
    }
    
    const route = routeInfo.slice(1);
    const routeWithKeys = [];
    
    for (const nodeId of route) {
      const sessionKey = this.discovery.getSessionKey(nodeId);
      if (!sessionKey) {
        console.warn(`No session key for ${nodeId}`);
        return;
      }
      routeWithKeys.push({ nodeId, sessionKey });
    }
    
    try {
      const onionPacket = createOnionPacket(data, routeWithKeys);
      
      const packet = new Packet({
        type: PacketType.DATA,
        srcNode: this.nodeId,
        dstNode: srcNodeId,
        route,
        payload: onionPacket
      });
      
      const nextHop = route[0];
      const serialized = packet.serialize();
      
      this.transportManager.send(nextHop, serialized);
    } catch (err) {
      console.error('Failed to send response:', err.message);
    }
  }

  _processReorderedPacket(payload, packetInfo) {
    if (this.tunManager && this.tunManager.isRunning()) {
      this.tunManager.injectPacket(payload);
    }
    
    this.emit('packet-received', payload);
  }

  _handlePing(peerId, packet) {
    const pongPacket = new Packet({
      type: PacketType.PONG,
      srcNode: this.nodeId,
      dstNode: peerId,
      payload: Buffer.from(packet.timestamp.toString())
    });
    
    this.transportManager.send(peerId, pongPacket.serialize());
  }

  _handlePong(peerId, packet) {
    const originalTimestamp = parseInt(packet.payload.toString(), 10);
    const latency = Date.now() - originalTimestamp;
    
    this.router.updateEdgeMetrics(peerId, { latency });
    this.emit('pong', peerId, latency);
  }

  _handleAck(peerId, packet) {
    const pathKey = `${peerId}`;
    const latency = Date.now() - packet.timestamp;
    this.scheduler.recordAck(pathKey, latency);
  }

  _updateMultipathRoutes() {
    const paths = this.router.findMultiplePaths(3);
    if (paths.length > 0) {
      this.scheduler.setPaths(paths);
    }
  }

  sendPing(peerId) {
    const pingPacket = new Packet({
      type: PacketType.PING,
      srcNode: this.nodeId,
      dstNode: peerId
    });
    
    return this.transportManager.send(peerId, pingPacket.serialize());
  }

  getStats() {
    return {
      nodeId: this.nodeId,
      role: this.role,
      virtualIp: this.virtualIp,
      running: this.running,
      connectedPeers: this.discovery.getConnectedPeers(),
      exitNodes: this.discovery.getExitNodes(),
      routing: this.router.getGraphStats(),
      scheduler: this.scheduler.getPathStats(),
      reorderBuffer: this.reorderBuffer.getBufferSize(),
      loopPrevention: { ...this.loopStats },
      packetCacheSize: this.processedPackets.size
    };
  }

  getLoopStats() {
    return { ...this.loopStats };
  }

  resetLoopStats() {
    this.loopStats = {
      ttlDropped: 0,
      duplicateDropped: 0,
      loopDropped: 0,
      splitHorizonDropped: 0,
      totalProcessed: 0,
      totalForwarded: 0
    };
  }

  async stop() {
    console.log(`Stopping mesh node ${this.nodeId}...`);
    
    this.running = false;
    
    this._stopCacheCleanup();
    this.reorderBuffer.stop();
    
    if (this.exitNodeHandler) {
      this.exitNodeHandler.stop();
    }
    
    if (this.tunManager) {
      await this.tunManager.shutdown();
    }
    
    this.discovery.stop();
    
    this.processedPackets.clear();
    
    this.emit('stopped');
    console.log(`Mesh node ${this.nodeId} stopped`);
  }
}
