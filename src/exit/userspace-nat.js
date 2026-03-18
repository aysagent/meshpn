import { EventEmitter } from 'events';
import net from 'net';
import dgram from 'dgram';
import { 
  PROTOCOLS, 
  TCP_FLAGS, 
  parseIPPacket, 
  buildTCPPacket, 
  buildUDPPacket 
} from '../network/index.js';

const TCP_STATE = {
  CONNECTING: 'CONNECTING',
  ESTABLISHED: 'ESTABLISHED',
  FIN_WAIT: 'FIN_WAIT',
  CLOSED: 'CLOSED'
};

export class UserSpaceNAT extends EventEmitter {
  constructor(config = {}) {
    super();
    this.tcpConnections = new Map();
    this.udpSockets = new Map();
    this.connectionTimeout = config.connectionTimeout || 300000;
    this.maxConnections = config.maxConnections || 50;
    this.connectingCount = 0;
    this.cleanupInterval = null;
    this.packetCount = 0;
    this.lastPacketCountTime = Date.now();
    this.localVirtualIp = null; // Set by MeshNode after registration
  }
  
  setLocalVirtualIp(ip) {
    this.localVirtualIp = ip;
    console.log(`[UserSpaceNAT] Local virtual IP set to ${ip}`);
  }

  start() {
    this.cleanupInterval = setInterval(() => {
      this._cleanup();
    }, 60000);
    console.log('[UserSpaceNAT] Started');
    
    // Event loop health check - should print every second
    // this.healthCounter = 0;
    // this.healthInterval = setInterval(() => {
    //   this.healthCounter++;
    //   console.log(`[UserSpaceNAT] HEALTH: tick ${this.healthCounter}, pending=${this.connectingCount}`);
    // }, 1000);
    
    // Single test at startup (disabled periodic)
    setTimeout(() => {
      this._testConnectivity('delayed-startup');
    }, 3000);
  }
  
  _testConnectivity(label) {
    console.log(`[UserSpaceNAT] TEST(${label}): Connecting...`);
    const testSocket = new net.Socket();
    testSocket.setTimeout(10000);
    
    testSocket.on('connect', () => {
      console.log(`[UserSpaceNAT] TEST(${label}): SUCCESS`);
      testSocket.destroy();
    });
    
    testSocket.on('error', (err) => {
      console.log(`[UserSpaceNAT] TEST(${label}): ERROR:`, err.message);
    });
    
    testSocket.on('timeout', () => {
      console.log(`[UserSpaceNAT] TEST(${label}): TIMEOUT`);
      testSocket.destroy();
    });
    
    testSocket.connect(80, '34.160.111.145');
  }

  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    if (this.testInterval) {
      clearInterval(this.testInterval);
      this.testInterval = null;
    }
    
    for (const [key, conn] of this.tcpConnections) {
      this._closeTCPConnection(key, conn);
    }
    this.tcpConnections.clear();
    
    for (const [key, info] of this.udpSockets) {
      try {
        info.socket.close();
      } catch {}
    }
    this.udpSockets.clear();
    
    console.log('[UserSpaceNAT] Stopped');
  }

  handlePacket(ipPacket, srcNodeId, sendResponse) {
    // Process synchronously - setImmediate was blocking event loop
    this._processPacket(ipPacket, srcNodeId, sendResponse);
  }
  
  _processPacket(ipPacket, srcNodeId, sendResponse) {
    this.packetCount++;
    const now = Date.now();
    if (now - this.lastPacketCountTime >= 1000) {
      console.log(`[UserSpaceNAT] Packets/sec: ${this.packetCount}, pending connects: ${this.connectingCount}`);
      this.packetCount = 0;
      this.lastPacketCountTime = now;
    }
    
    const parsed = parseIPPacket(ipPacket);
    if (!parsed || !parsed.valid) {
      return;
    }

    const { protocol, srcIp, dstIp, srcPort, dstPort } = parsed;

    if (protocol === PROTOCOLS.TCP) {
      this._handleTCP(parsed, srcNodeId, sendResponse);
    } else if (protocol === PROTOCOLS.UDP) {
      this._handleUDP(parsed, srcNodeId, sendResponse);
    }
  }

  _handleTCP(parsed, srcNodeId, sendResponse) {
    const { srcIp, dstIp, srcPort, dstPort, tcpSeq, tcpFlags, data } = parsed;
    const key = `${srcIp}:${srcPort}:${dstIp}:${dstPort}`;
    
    let conn = this.tcpConnections.get(key);

    if (parsed.tcpFlagsRST) {
      if (conn) {
        this._closeTCPConnection(key, conn);
      }
      return;
    }

    if (parsed.tcpFlagsSYN && !parsed.tcpFlagsACK) {
      if (conn && conn.state !== TCP_STATE.CLOSED) {
        return;
      }
      
      // Limit concurrent connections
      if (this.connectingCount >= this.maxConnections) {
        console.log(`[UserSpaceNAT] Too many connections (${this.connectingCount}), dropping SYN`);
        return;
      }
      
      this.connectingCount++;
      
      // If destination is our own virtual IP, connect to localhost instead
      const actualDstIp = (this.localVirtualIp && dstIp === this.localVirtualIp) ? '127.0.0.1' : dstIp;
      const isLocal = actualDstIp === '127.0.0.1';
      
      console.log(`[UserSpaceNAT] New connection to ${dstIp}:${dstPort}${isLocal ? ' (LOCAL)' : ''} (active: ${this.connectingCount})`);

      conn = {
        key,
        srcNodeId,
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        actualDstIp,
        sendResponse,
        state: TCP_STATE.CONNECTING,
        clientSeq: tcpSeq,
        clientAck: 0,
        serverSeq: Math.floor(Math.random() * 0xffffffff),
        socket: null,
        pendingData: [],
        lastActivity: Date.now()
      };

      this.tcpConnections.set(key, conn);

      const socket = new net.Socket();
      conn.socket = socket;
      
      socket.setTimeout(30000);

      socket.on('lookup', (err, address, family, host) => {
        console.log(`[UserSpaceNAT] DNS lookup for ${dstIp}: err=${err}, addr=${address}`);
      });

      socket.on('connect', () => {
        this.connectingCount--;
        console.log(`[UserSpaceNAT] Connected to ${actualDstIp}:${dstPort} (for ${dstIp}) (active: ${this.connectingCount})`);
        
        if (conn.state === TCP_STATE.CLOSED) {
          socket.destroy();
          return;
        }

        conn.state = TCP_STATE.ESTABLISHED;
        conn.lastActivity = Date.now();

        const synAckPacket = buildTCPPacket(
          dstIp, srcIp,
          dstPort, srcPort,
          conn.serverSeq,
          conn.clientSeq + 1,
          TCP_FLAGS.SYN | TCP_FLAGS.ACK
        );

        conn.serverSeq++;
        conn.clientAck = conn.clientSeq + 1;

        console.log(`[UserSpaceNAT] Sending SYN-ACK to ${srcNodeId}, packet size: ${synAckPacket.length}`);
        sendResponse(srcNodeId, synAckPacket);

        if (conn.pendingData.length > 0) {
          for (const chunk of conn.pendingData) {
            socket.write(chunk);
          }
          conn.pendingData = [];
        }
      });

      socket.on('data', (data) => {
        if (conn.state === TCP_STATE.CLOSED) return;
        
        conn.lastActivity = Date.now();
        
        const responsePacket = buildTCPPacket(
          dstIp, srcIp,
          dstPort, srcPort,
          conn.serverSeq,
          conn.clientAck,
          TCP_FLAGS.PSH | TCP_FLAGS.ACK,
          data
        );

        conn.serverSeq += data.length;

        sendResponse(srcNodeId, responsePacket);
      });

      socket.on('end', () => {
        if (conn.state === TCP_STATE.CLOSED) return;
        
        const finPacket = buildTCPPacket(
          dstIp, srcIp,
          dstPort, srcPort,
          conn.serverSeq,
          conn.clientAck,
          TCP_FLAGS.FIN | TCP_FLAGS.ACK
        );

        conn.serverSeq++;
        conn.state = TCP_STATE.FIN_WAIT;

        sendResponse(srcNodeId, finPacket);
      });

      socket.on('error', (err) => {
        if (conn.state === TCP_STATE.CONNECTING) {
          this.connectingCount--;
        }
        console.error(`[UserSpaceNAT] TCP error ${dstIp}:${dstPort}:`, err.message);
        
        if (conn.state !== TCP_STATE.CLOSED) {
          const rstPacket = buildTCPPacket(
            dstIp, srcIp,
            dstPort, srcPort,
            conn.serverSeq,
            conn.clientAck,
            TCP_FLAGS.RST
          );
          sendResponse(srcNodeId, rstPacket);
        }
        
        this._closeTCPConnection(key, conn);
      });

      socket.on('timeout', () => {
        if (conn.state === TCP_STATE.CONNECTING) {
          this.connectingCount--;
        }
        console.log(`[UserSpaceNAT] Socket timeout for ${dstIp}:${dstPort}`);
        socket.destroy();
        this._closeTCPConnection(key, conn);
      });

      socket.on('close', (hadError) => {
        console.log(`[UserSpaceNAT] Socket closed for ${dstIp}:${dstPort}, hadError=${hadError}`);
        if (conn.state !== TCP_STATE.CLOSED) {
          this._closeTCPConnection(key, conn);
        }
      });

      console.log(`[UserSpaceNAT] Calling socket.connect() for ${actualDstIp}:${dstPort}...`);
      socket.connect(dstPort, actualDstIp, () => {
        console.log(`[UserSpaceNAT] CALLBACK: Connected to ${actualDstIp}:${dstPort}!`);
      });
      console.log(`[UserSpaceNAT] socket.connect() returned, connecting=${socket.connecting}`);
      
      // Diagnostic: check socket state after 1 second
      setTimeout(() => {
        console.log(`[UserSpaceNAT] DIAGNOSTIC ${dstIp}:${dstPort}: connecting=${socket.connecting}, destroyed=${socket.destroyed}, readyState=${socket.readyState}, pending=${socket.pending}`);
      }, 1000);
      return;
    }

    if (!conn) {
      const rstPacket = buildTCPPacket(
        dstIp, srcIp,
        dstPort, srcPort,
        0,
        tcpSeq + 1,
        TCP_FLAGS.RST | TCP_FLAGS.ACK
      );
      sendResponse(srcNodeId, rstPacket);
      return;
    }

    conn.lastActivity = Date.now();

    if (parsed.tcpFlagsACK && !parsed.tcpFlagsSYN && !parsed.tcpFlagsFIN && data.length === 0) {
      return;
    }

    if (parsed.tcpFlagsFIN) {
      conn.clientAck = tcpSeq + 1;
      
      const ackPacket = buildTCPPacket(
        dstIp, srcIp,
        dstPort, srcPort,
        conn.serverSeq,
        conn.clientAck,
        TCP_FLAGS.ACK
      );
      sendResponse(srcNodeId, ackPacket);
      
      if (conn.socket) {
        conn.socket.end();
      }
      
      this._closeTCPConnection(key, conn);
      return;
    }

    if (data && data.length > 0) {
      conn.clientAck = tcpSeq + data.length;

      if (conn.state === TCP_STATE.ESTABLISHED && conn.socket) {
        conn.socket.write(data);
      } else if (conn.state === TCP_STATE.CONNECTING) {
        conn.pendingData.push(data);
      }

      const ackPacket = buildTCPPacket(
        dstIp, srcIp,
        dstPort, srcPort,
        conn.serverSeq,
        conn.clientAck,
        TCP_FLAGS.ACK
      );
      sendResponse(srcNodeId, ackPacket);
    }
  }

  _handleUDP(parsed, srcNodeId, sendResponse) {
    const { srcIp, dstIp, srcPort, dstPort, data } = parsed;
    const key = `${srcIp}:${srcPort}:${dstIp}:${dstPort}`;
    
    let info = this.udpSockets.get(key);

    if (!info) {
      const socket = dgram.createSocket('udp4');

      socket.on('message', (msg, rinfo) => {
        const responsePacket = buildUDPPacket(
          dstIp, srcIp,
          dstPort, srcPort,
          msg
        );
        
        info.lastActivity = Date.now();
        sendResponse(srcNodeId, responsePacket);
      });

      socket.on('error', (err) => {
        console.error(`[UserSpaceNAT] UDP error ${dstIp}:${dstPort}:`, err.message);
        this.udpSockets.delete(key);
      });

      info = {
        socket,
        srcNodeId,
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        sendResponse,
        lastActivity: Date.now()
      };

      this.udpSockets.set(key, info);
    }

    info.lastActivity = Date.now();
    
    if (data && data.length > 0) {
      info.socket.send(data, dstPort, dstIp);
    }
  }

  _closeTCPConnection(key, conn) {
    if (conn.state === TCP_STATE.CLOSED) return;
    
    conn.state = TCP_STATE.CLOSED;
    
    if (conn.socket) {
      try {
        conn.socket.destroy();
      } catch {}
      conn.socket = null;
    }
    
    this.tcpConnections.delete(key);
  }

  _cleanup() {
    const now = Date.now();
    
    for (const [key, conn] of this.tcpConnections) {
      if (now - conn.lastActivity > this.connectionTimeout) {
        this._closeTCPConnection(key, conn);
      }
    }
    
    for (const [key, info] of this.udpSockets) {
      if (now - info.lastActivity > this.connectionTimeout) {
        try {
          info.socket.close();
        } catch {}
        this.udpSockets.delete(key);
      }
    }
  }

  getStats() {
    return {
      tcpConnections: this.tcpConnections.size,
      udpSockets: this.udpSockets.size
    };
  }
}
