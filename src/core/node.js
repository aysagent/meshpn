import { EventEmitter } from 'events';
import { Identity, SessionManager } from '../crypto/index.js';
import { createOnionPacket, peelOnionLayer } from '../crypto/onion.js';
import { encrypt, decrypt } from '../crypto/encrypt.js';
import { TransportManager } from '../transport/index.js';
import { PeerDiscovery } from '../control/index.js';
import { MeshRouter, MultipathScheduler, ReorderBuffer } from './index.js';
import { TunManager, Packet, PacketType, parseIPPacket } from '../network/index.js';
import { NATManager, UserSpaceNAT } from '../exit/index.js';
import http from 'http';

export class MeshNode extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.role = config.role || 'client';
    
    this.isClient = this.role === 'client' || this.role === 'client-relay';
    this.isRelay = this.role === 'relay' || this.role === 'client-relay';
    this.isExit = this.role === 'exit';
    
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
    
    this.tcpConnections = new Map();
    this.tcpConnectionTimeout = config.tcpConnectionTimeout || 300000;
    
    this.loopStats = {
      ttlDropped: 0,
      duplicateDropped: 0,
      loopDropped: 0,
      splitHorizonDropped: 0,
      totalProcessed: 0,
      totalForwarded: 0
    };
    
    // Traffic statistics
    this.trafficStats = {
      bytesSent: 0,
      bytesReceived: 0,
      packetsSent: 0,
      packetsReceived: 0,
      lastResetTime: Date.now()
    };
    this.statsInterval = null;
    
    this.tunManager = null;
    this.exitNodeHandler = null;
    this.virtualIp = null;
    
    this.natMappings = new Map();
    this.natMappingTimeout = config.natMappingTimeout || 300000;
    
    this.natMode = config.natMode || 'system';
    
    if (this.isExit) {
      if (this.natMode === 'userspace') {
        this.userSpaceNAT = new UserSpaceNAT(config.nat || {});
        this.natManager = null;
      } else {
        this.userSpaceNAT = null;
        this.natManager = new NATManager(config.nat || {});
      }
    } else {
      this.userSpaceNAT = null;
      this.natManager = null;
    }
    
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
      this._cleanupTcpConnections();
    }, 30000);
  }

  _startKeepalive() {
    this.keepaliveInterval = setInterval(() => {
      const peers = this.discovery.getConnectedPeers();
      for (const peerId of peers) {
        this.sendPing(peerId);
      }
    }, 30000); // Ping every 30 seconds
  }

  _stopKeepalive() {
    if (this.keepaliveInterval) {
      clearInterval(this.keepaliveInterval);
      this.keepaliveInterval = null;
    }
  }

  _startTrafficStats() {
    if (!this.isClient) return;
    
    this.statsInterval = setInterval(() => {
      const now = Date.now();
      const elapsed = (now - this.trafficStats.lastResetTime) / 1000;
      
      if (elapsed > 0) {
        const downloadSpeed = this.trafficStats.bytesReceived / elapsed;
        const uploadSpeed = this.trafficStats.bytesSent / elapsed;
        
        const formatSpeed = (bytesPerSec) => {
          if (bytesPerSec >= 1024 * 1024) {
            return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
          } else if (bytesPerSec >= 1024) {
            return `${(bytesPerSec / 1024).toFixed(2)} KB/s`;
          }
          return `${bytesPerSec.toFixed(0)} B/s`;
        };
        
        const peers = this.discovery.getConnectedPeers().length;
        
        console.log(`[STATS] ↓ ${formatSpeed(downloadSpeed)} | ↑ ${formatSpeed(uploadSpeed)} | Peers: ${peers}`);
        
        // Reset counters
        this.trafficStats.bytesSent = 0;
        this.trafficStats.bytesReceived = 0;
        this.trafficStats.packetsSent = 0;
        this.trafficStats.packetsReceived = 0;
        this.trafficStats.lastResetTime = now;
      }
    }, 5000);
  }

  _stopTrafficStats() {
    if (this.statsInterval) {
      clearInterval(this.statsInterval);
      this.statsInterval = null;
    }
  }

  _stopCacheCleanup() {
    if (this.cacheCleanupInterval) {
      clearInterval(this.cacheCleanupInterval);
      this.cacheCleanupInterval = null;
    }
  }

  _setupNATCleanup() {
    const cleanup = async () => {
      console.log('\n[NAT] Shutting down, cleaning up NAT...');
      if (this.natManager) {
        await this.natManager.disable();
      }
      process.exit(0);
    };

    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
  }

  async start() {
    console.log(`Starting mesh node ${this.nodeId} as ${this.role}...`);
    
    this._setupEventHandlers();
    
    const discoveryRole = this.isRelay ? 'relay' : this.role;
    await this.discovery.start(discoveryRole);
    
    this.reorderBuffer.start();
    this._startCacheCleanup();
    this._startKeepalive();
    this._startTrafficStats();
    
    this.running = true;
    this.emit('started');
    
    console.log(`Mesh node ${this.nodeId} started successfully`);
  }

  _setupEventHandlers() {
    this.discovery.on('registered', async (info) => {
      if (this.tunManager) {
        console.log(`Already have TUN (${this.virtualIp}), ignoring new registration with ${info.virtualIp}`);
        return;
      }
      
      this.virtualIp = info.virtualIp;
      console.log(`Registered with virtual IP: ${this.virtualIp}`);
      
      if (this.isExit && this.natMode === 'userspace') {
        this.userSpaceNAT.setLocalVirtualIp(this.virtualIp);
        this.userSpaceNAT.start();
        this._startEchoServer();
        console.log('Exit node ready (user-space NAT)');
        this.emit('registered', info);
        return;
      }
      
      const needsTun = (this.isClient || (this.isExit && this.natMode === 'system')) && this.config.enableTun !== false;
      
      if (needsTun && !this.tunManager) {
        this.tunManager = new TunManager(this.config.tun || {});
        if (this.isClient) {
          this.tunManager.on('outbound-packet', (packet) => {
            this._handleOutboundPacket(packet);
          });
        } else if (this.isExit) {
          this.tunManager.on('outbound-packet', (packet) => {
            this._handleExitTunPacket(packet);
          });
        }
        
        try {
          await this.tunManager.setup(this.virtualIp);
          if (this.isRelay) {
            console.log('Running as client-relay: TUN enabled + packet forwarding');
          } else if (this.isExit) {
            console.log('Exit node TUN interface ready (system NAT)');
            
            if (this.natManager && this.config.nat?.enabled !== false) {
              const tunName = this.tunManager.getInterfaceName();
              const extInterface = this.config.nat?.externalInterface || null;
              const success = await this.natManager.enable(tunName, extInterface);
              if (success) {
                this._setupNATCleanup();
              }
            }
          }
        } catch (err) {
          console.warn('TUN setup failed:', err.message);
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
    
    if (!parsed.srcIp.startsWith('10.200.')) return;
    
    // Only drop packets to self (loopback)
    if (parsed.srcIp === this.virtualIp && parsed.dstIp === this.virtualIp) return;
    
    console.log(`[TUN] Outbound: ${parsed.srcIp}:${parsed.srcPort} -> ${parsed.dstIp}:${parsed.dstPort}`);
    
    const routeInfo = this.router.findRouteToExit();
    if (!routeInfo) {
      console.warn('[TUN] No route to exit node available');
      return;
    }
    
    console.log(`[TUN] Route found: exit=${routeInfo.exitNode}, hops=${routeInfo.route.length}`);
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
      
      console.log(`[TUN] Sending packet to next hop: ${nextHop}, serialized size: ${serialized.length}`);
      
      if (!this.transportManager.send(nextHop, serialized)) {
        console.warn(`[TUN] Failed to send to ${nextHop}`);
      } else {
        this.trafficStats.bytesSent += payload.length;
        this.trafficStats.packetsSent++;
      }
    } catch (err) {
      console.error('[TUN] Failed to create onion packet:', err.message);
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
    console.log(`[MESH] Received data packet from ${peerId}, flowId=${packet.flowId}, dst=${packet.dstNode}`);
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
        if (this.isExit) {
          this._processExitPacket(packet, layer.payload);
        } else if (this.isClient && packet.dstNode === this.nodeId) {
          this.reorderBuffer.addPacket({
            flowId: packet.flowId,
            seq: packet.seq || 0,
            payload: layer.payload,
            pathIndex: packet.pathIndex || 0,
            totalPaths: packet.totalPaths || 1
          });
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
    if (this.userSpaceNAT) {
      const sendResponse = (targetNodeId, responsePacket) => {
        this._sendExitResponse(targetNodeId, responsePacket);
      };
      this.userSpaceNAT.handlePacket(payload, packet.srcNode, sendResponse);
      return;
    }
    
    if (!this.tunManager) {
      console.warn('[EXIT] No TUN manager for exit node');
      return;
    }
    
    try {
      const parsed = parseIPPacket(payload);
      if (!parsed) {
        console.warn('[EXIT] Failed to parse IP packet');
        return;
      }
      
      const { srcIp, dstIp, srcPort, dstPort, protocol } = parsed;
      console.log(`[EXIT] Processing: ${srcIp}:${srcPort} -> ${dstIp}:${dstPort} proto=${protocol}`);
      
      const mappingKey = `${srcIp}:${srcPort}:${dstIp}:${dstPort}:${protocol}`;
      this.natMappings.set(mappingKey, {
        srcNodeId: packet.srcNode,
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        protocol,
        createdAt: Date.now()
      });
      
      console.log(`[EXIT] NAT mapping created: ${mappingKey} -> ${packet.srcNode}`);
      
      this.tunManager.injectPacket(payload);
      console.log(`[EXIT] Packet injected to TUN`);
      
    } catch (err) {
      console.error('[EXIT] Processing failed:', err.message);
    }
  }

  _handleExitTunPacket(packet) {
    const parsed = parseIPPacket(packet);
    if (!parsed) {
      console.warn('[EXIT] Failed to parse TUN packet');
      return;
    }
    
    const { srcIp, dstIp, srcPort, dstPort, protocol } = parsed;
    
    if (dstIp.startsWith('10.200.')) {
      const mappingKey = `${dstIp}:${dstPort}:${srcIp}:${srcPort}:${protocol}`;
      const mapping = this.natMappings.get(mappingKey);
      
      if (!mapping) {
        console.warn(`[EXIT] No NAT mapping for ${mappingKey}`);
        return;
      }
      
      console.log(`[EXIT] Response: ${srcIp}:${srcPort} -> ${dstIp}:${dstPort} for client ${mapping.srcNodeId}`);
      
      this._sendExitResponse(mapping.srcNodeId, packet);
    }
  }

  _sendExitResponse(targetNodeId, ipPacket) {
    const routeInfo = this.router.graph.findShortestPath(this.nodeId, targetNodeId);
    if (!routeInfo || routeInfo.length < 2) {
      console.warn(`[EXIT] No route back to ${targetNodeId}`);
      return;
    }
    
    console.log(`[EXIT] Sending response via: ${routeInfo.join(' -> ')}`);
    
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
      const onionPacket = createOnionPacket(ipPacket, routeWithKeys);
      
      const packet = new Packet({
        type: PacketType.DATA,
        srcNode: this.nodeId,
        dstNode: targetNodeId,
        route,
        payload: onionPacket
      });
      
      const nextHop = route[0];
      const serialized = packet.serialize();
      
      console.log(`[EXIT] Sending to ${nextHop}, size: ${serialized.length}`);
      const sent = this.transportManager.send(nextHop, serialized);
      if (sent) {
        console.log(`[EXIT] Response sent successfully`);
      } else {
        console.warn(`[EXIT] Failed to send to ${nextHop}`);
      }
    } catch (err) {
      console.error('[EXIT] Failed to send response:', err.message);
    }
  }

  _processReorderedPacket(payload, packetInfo) {
    // Update traffic stats
    this.trafficStats.bytesReceived += payload.length;
    this.trafficStats.packetsReceived++;
    
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

  _getTcpConnectionKey(srcNodeId, srcIp, srcPort, dstIp, dstPort) {
    return `${srcNodeId}:${srcIp}:${srcPort}:${dstIp}:${dstPort}`;
  }

  _getOrCreateTcpConnection(srcNodeId, srcIp, srcPort, dstIp, dstPort) {
    const key = this._getTcpConnectionKey(srcNodeId, srcIp, srcPort, dstIp, dstPort);
    
    if (!this.tcpConnections.has(key)) {
      this.tcpConnections.set(key, {
        seqNum: Math.floor(Math.random() * 0xFFFFFFFF),
        ackNum: 0,
        lastUsed: Date.now()
      });
    }
    
    const conn = this.tcpConnections.get(key);
    conn.lastUsed = Date.now();
    return conn;
  }

  _getTcpSeqNum(srcNodeId, srcIp, srcPort, dstIp, dstPort) {
    const conn = this._getOrCreateTcpConnection(srcNodeId, srcIp, srcPort, dstIp, dstPort);
    return conn.seqNum;
  }

  _getTcpAckNum(srcNodeId, srcIp, srcPort, dstIp, dstPort) {
    const conn = this._getOrCreateTcpConnection(srcNodeId, srcIp, srcPort, dstIp, dstPort);
    return conn.ackNum;
  }

  _updateTcpSeqNum(srcNodeId, srcIp, srcPort, dstIp, dstPort, dataLength) {
    const conn = this._getOrCreateTcpConnection(srcNodeId, srcIp, srcPort, dstIp, dstPort);
    conn.seqNum = (conn.seqNum + dataLength) >>> 0;
  }

  _updateTcpAckNum(srcNodeId, srcIp, srcPort, dstIp, dstPort, seqNum, dataLength) {
    const conn = this._getOrCreateTcpConnection(srcNodeId, srcIp, srcPort, dstIp, dstPort);
    conn.ackNum = (seqNum + dataLength) >>> 0;
  }

  _cleanupTcpConnections() {
    const now = Date.now();
    for (const [key, conn] of this.tcpConnections) {
      if (now - conn.lastUsed > this.tcpConnectionTimeout) {
        this.tcpConnections.delete(key);
      }
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

  _startEchoServer() {
    const port = 8888;
    this.echoServer = http.createServer((req, res) => {
      console.log(`[ECHO] Request from ${req.socket.remoteAddress}: ${req.method} ${req.url}`);
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`Hello from exit node!\nVirtual IP: ${this.virtualIp}\nNode ID: ${this.nodeId}\nTimestamp: ${new Date().toISOString()}\n`);
    });
    
    this.echoServer.listen(port, '0.0.0.0', () => {
      console.log(`[ECHO] Test server listening on port ${port}`);
      console.log(`[ECHO] Test with: curl http://${this.virtualIp}:${port}/`);
    });
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
    this._stopKeepalive();
    this._stopTrafficStats();
    this.reorderBuffer.stop();
    
    if (this.userSpaceNAT) {
      this.userSpaceNAT.stop();
    }
    
    if (this.exitNodeHandler) {
      this.exitNodeHandler.stop();
    }
    
    if (this.tunManager) {
      await this.tunManager.shutdown();
    }
    
    this.discovery.stop();
    
    this.processedPackets.clear();
    this.tcpConnections.clear();
    
    this.emit('stopped');
    console.log(`Mesh node ${this.nodeId} stopped`);
  }
}
