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
    this.localVirtualIp = null;
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
  }
  
  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
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
    const parsed = parseIPPacket(ipPacket);
    if (!parsed || !parsed.valid) {
      return;
    }

    const { protocol, srcIp, dstIp, srcPort, dstPort } = parsed;

    if (protocol === PROTOCOLS.TCP) {
      this._handleTCP(parsed, srcNodeId, sendResponse);
    } else if (protocol === PROTOCOLS.UDP) {
      this._handleUDP(parsed, srcNodeId, sendResponse);
    } else if (protocol === PROTOCOLS.ICMP) {
      this._handleICMP(parsed, srcNodeId, sendResponse);
    }
  }

  _handleICMP(parsed, srcNodeId, sendResponse) {
    const { srcIp, dstIp, icmpType, icmpCode, icmpData } = parsed;
    
    // ICMP Echo Request (ping) = type 8
    if (icmpType === 8) {
      console.log(`[UserSpaceNAT] ICMP Echo Request from ${srcIp} to ${dstIp}`);
      
      // If destination is our virtual IP, reply directly
      if (dstIp === this.localVirtualIp) {
        const echoReply = this._buildICMPEchoReply(parsed);
        console.log(`[UserSpaceNAT] Sending ICMP Echo Reply to ${srcIp}`);
        sendResponse(srcNodeId, echoReply);
      }
      // For external IPs, we would need raw sockets which require root
      // and are complex to implement. Skip for now.
    }
  }

  _buildICMPEchoReply(parsed) {
    const { srcIp, dstIp, icmpData, ipId } = parsed;
    
    // Build ICMP Echo Reply (type 0, code 0)
    // icmpData contains: identifier (2 bytes) + sequence (2 bytes) + payload
    const icmpHeader = Buffer.alloc(8);
    icmpHeader.writeUInt8(0, 0);  // Type: Echo Reply
    icmpHeader.writeUInt8(0, 1);  // Code: 0
    icmpHeader.writeUInt16BE(0, 2);  // Checksum (calculated later)
    
    // Copy identifier and sequence from request
    if (icmpData && icmpData.length >= 4) {
      icmpData.copy(icmpHeader, 4, 0, 4);
    }
    
    // Payload (rest of icmpData after identifier+sequence)
    const payload = icmpData && icmpData.length > 4 ? icmpData.subarray(4) : Buffer.alloc(0);
    
    // Full ICMP packet
    const icmpPacket = Buffer.concat([icmpHeader, payload]);
    
    // Calculate ICMP checksum
    let sum = 0;
    for (let i = 0; i < icmpPacket.length; i += 2) {
      if (i + 1 < icmpPacket.length) {
        sum += icmpPacket.readUInt16BE(i);
      } else {
        sum += icmpPacket[i] << 8;
      }
    }
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    icmpPacket.writeUInt16BE(~sum & 0xffff, 2);
    
    // Build IP header
    const ipHeader = Buffer.alloc(20);
    ipHeader.writeUInt8(0x45, 0);  // Version + IHL
    ipHeader.writeUInt8(0, 1);     // TOS
    ipHeader.writeUInt16BE(20 + icmpPacket.length, 2);  // Total length
    ipHeader.writeUInt16BE(ipId || 0, 4);  // Identification
    ipHeader.writeUInt16BE(0, 6);  // Flags + Fragment offset
    ipHeader.writeUInt8(64, 8);    // TTL
    ipHeader.writeUInt8(1, 9);     // Protocol: ICMP
    ipHeader.writeUInt16BE(0, 10); // Header checksum (calculated later)
    
    // Source IP (exit node) -> Destination IP (original source)
    const srcParts = dstIp.split('.').map(Number);
    const dstParts = srcIp.split('.').map(Number);
    ipHeader.writeUInt8(srcParts[0], 12);
    ipHeader.writeUInt8(srcParts[1], 13);
    ipHeader.writeUInt8(srcParts[2], 14);
    ipHeader.writeUInt8(srcParts[3], 15);
    ipHeader.writeUInt8(dstParts[0], 16);
    ipHeader.writeUInt8(dstParts[1], 17);
    ipHeader.writeUInt8(dstParts[2], 18);
    ipHeader.writeUInt8(dstParts[3], 19);
    
    // Calculate IP header checksum
    let ipSum = 0;
    for (let i = 0; i < 20; i += 2) {
      ipSum += ipHeader.readUInt16BE(i);
    }
    while (ipSum >> 16) {
      ipSum = (ipSum & 0xffff) + (ipSum >> 16);
    }
    ipHeader.writeUInt16BE(~ipSum & 0xffff, 10);
    
    return Buffer.concat([ipHeader, icmpPacket]);
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
      
      console.log(`[UserSpaceNAT] Connecting to ${dstIp}:${dstPort}${isLocal ? ' (local)' : ''}`);

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

      socket.on('connect', () => {
        this.connectingCount--;
        console.log(`[UserSpaceNAT] Connected to ${dstIp}:${dstPort}`);
        
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
        
        // Segment large data into smaller chunks (MSS ~1360 for MTU 1400)
        const MSS = 1360;
        let offset = 0;
        
        while (offset < data.length) {
          const chunk = data.subarray(offset, offset + MSS);
          const isLast = (offset + MSS >= data.length);
          
          const responsePacket = buildTCPPacket(
            dstIp, srcIp,
            dstPort, srcPort,
            conn.serverSeq,
            conn.clientAck,
            isLast ? (TCP_FLAGS.PSH | TCP_FLAGS.ACK) : TCP_FLAGS.ACK,
            chunk
          );

          conn.serverSeq += chunk.length;
          offset += chunk.length;

          sendResponse(srcNodeId, responsePacket);
        }
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
        socket.destroy();
        this._closeTCPConnection(key, conn);
      });

      socket.on('close', () => {
        if (conn.state !== TCP_STATE.CLOSED) {
          this._closeTCPConnection(key, conn);
        }
      });

      socket.connect(dstPort, actualDstIp);
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
