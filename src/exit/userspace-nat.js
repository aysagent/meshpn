import { EventEmitter } from 'events';
import net from 'net';
import dgram from 'dgram';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';
import { 
  PROTOCOLS, 
  TCP_FLAGS, 
  parseIPPacket, 
  buildTCPPacket, 
  buildUDPPacket 
} from '../network/index.js';
import { metrics } from '../debug/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ICMP_HELPER_PATH = path.join(__dirname, '../../helpers/icmp-helper');

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
    /** Сколько mesh-сегментов «в полёте» к клиенту до паузы чтения с реального сервера (iperf -R). */
    this.tcpMaxPending = config.maxPendingResponses ?? 200;
    /** Ниже этого порога pending + окно клиента > 0 — снова resume к серверу. */
    this.tcpResumePending = Math.max(30, Math.floor(this.tcpMaxPending * 0.35));
    this.connectionTimeout = config.connectionTimeout || 300000;
    this.maxConnections = config.maxConnections || 50;
    this.connectingCount = 0;
    this.cleanupInterval = null;
    this.localVirtualIp = null;
    
    // ICMP helper
    this.icmpHelper = null;
    this.icmpPending = new Map();
    this.icmpBuffer = '';
  }
  
  setLocalVirtualIp(ip) {
    this.localVirtualIp = ip;
    console.log(`[UserSpaceNAT] Local virtual IP set to ${ip}`);
  }

  start() {
    this.cleanupInterval = setInterval(() => {
      this._cleanup();
    }, 60000);
    
    // Start ICMP helper on Linux
    if (os.platform() === 'linux') {
      this._startICMPHelper();
    }
    
    console.log('[UserSpaceNAT] Started');
  }
  
  _startICMPHelper() {
    if (!fs.existsSync(ICMP_HELPER_PATH)) {
      console.warn('[UserSpaceNAT] icmp-helper not found, external ping will not work');
      console.warn('[UserSpaceNAT] Run: cd helpers && make');
      return;
    }
    
    this.icmpHelper = spawn(ICMP_HELPER_PATH, [], {
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    this.icmpHelper.stdout.on('data', (data) => {
      this.icmpBuffer += data.toString();
      this._processICMPResponses();
    });
    
    this.icmpHelper.stderr.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg === 'READY') {
        console.log('[UserSpaceNAT] ICMP helper ready');
      } else if (msg.startsWith('ERROR')) {
        console.error(`[UserSpaceNAT] ICMP helper: ${msg}`);
      }
    });
    
    this.icmpHelper.on('error', (err) => {
      console.error('[UserSpaceNAT] ICMP helper error:', err.message);
      this.icmpHelper = null;
    });
    
    this.icmpHelper.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        console.error(`[UserSpaceNAT] ICMP helper exited with code ${code}`);
      }
      this.icmpHelper = null;
    });
  }
  
  _processICMPResponses() {
    const lines = this.icmpBuffer.split('\n');
    this.icmpBuffer = lines.pop() || '';
    
    for (const line of lines) {
      if (!line.trim()) continue;
      
      const parts = line.split(' ');
      const cmd = parts[0];
      
      if (cmd === 'REP') {
        // REP <src_ip> <id> <seq> <ttl> <payload_hex>
        const srcIp = parts[1];
        const id = parseInt(parts[2], 10);
        const seq = parseInt(parts[3], 10);
        const ttl = parseInt(parts[4], 10);
        const payloadHex = parts[5] || '';
        
        const key = `${id}:${seq}`;
        const pending = this.icmpPending.get(key);
        
        if (pending) {
          this.icmpPending.delete(key);
          const reply = this._buildICMPReplyFromExternal(
            srcIp, pending.srcIp, id, seq, ttl, payloadHex
          );
          pending.sendResponse(pending.srcNodeId, reply);
        }
      } else if (cmd === 'TIMEOUT') {
        // TIMEOUT <id> <seq>
        const id = parseInt(parts[1], 10);
        const seq = parseInt(parts[2], 10);
        const key = `${id}:${seq}`;
        this.icmpPending.delete(key);
      }
    }
  }
  
  _buildICMPReplyFromExternal(extSrcIp, clientIp, id, seq, ttl, payloadHex) {
    // Convert hex payload to buffer
    const payload = payloadHex ? Buffer.from(payloadHex, 'hex') : Buffer.alloc(0);
    
    // Build ICMP Echo Reply
    const icmpHeader = Buffer.alloc(8);
    icmpHeader.writeUInt8(0, 0);  // Type: Echo Reply
    icmpHeader.writeUInt8(0, 1);  // Code: 0
    icmpHeader.writeUInt16BE(0, 2);  // Checksum
    icmpHeader.writeUInt16BE(id, 4);  // Identifier
    icmpHeader.writeUInt16BE(seq, 6);  // Sequence
    
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
    ipHeader.writeUInt16BE(Math.floor(Math.random() * 65535), 4);  // ID
    ipHeader.writeUInt16BE(0, 6);  // Flags + Fragment offset
    ipHeader.writeUInt8(ttl, 8);   // TTL from external reply
    ipHeader.writeUInt8(1, 9);     // Protocol: ICMP
    ipHeader.writeUInt16BE(0, 10); // Checksum
    
    // Source: external IP, Destination: client IP
    const srcParts = extSrcIp.split('.').map(Number);
    const dstParts = clientIp.split('.').map(Number);
    ipHeader.writeUInt8(srcParts[0], 12);
    ipHeader.writeUInt8(srcParts[1], 13);
    ipHeader.writeUInt8(srcParts[2], 14);
    ipHeader.writeUInt8(srcParts[3], 15);
    ipHeader.writeUInt8(dstParts[0], 16);
    ipHeader.writeUInt8(dstParts[1], 17);
    ipHeader.writeUInt8(dstParts[2], 18);
    ipHeader.writeUInt8(dstParts[3], 19);
    
    // Calculate IP checksum
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
  
  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    
    // Stop ICMP helper
    if (this.icmpHelper) {
      this.icmpHelper.kill();
      this.icmpHelper = null;
    }
    this.icmpPending.clear();
    
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
    const startTime = Date.now();
    this._processPacket(ipPacket, srcNodeId, sendResponse);
    const elapsed = Date.now() - startTime;
    metrics.recordNATProcess(ipPacket.length, elapsed);
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

  /**
   * Сколько mesh-сегментов можно держать «в полёте» без переполнения приёмного окна клиента
   * (без парсинга TCP WS — берём 16-bit Window из заголовка).
   */
  _maxPendingForConn(conn) {
    const MSS = 1360;
    const w = conn.peerRecvWindow ?? 65535;
    if (w === 0) return 0;
    const slack = 6;
    const byWin = Math.floor(w / MSS) + slack;
    return Math.min(this.tcpMaxPending, Math.max(slack, byWin));
  }

  _resumePendingTarget(conn) {
    const maxP = this._maxPendingForConn(conn);
    if (maxP <= 0) return 0;
    return Math.max(4, Math.floor(maxP * 0.35));
  }

  /**
   * Окно приёма клиента (из его TCP-заголовка) и cumulative ACK по нашему serverSeq.
   * Раньше pendingResponses уменьшали на 5 за любой ACK — счётчик не сходился, сокет к iperf
   * зря pause/resume, на клиенте переполнялся буфер → TCP ZeroWindow.
   */
  _updatePeerWindowAndAck(conn, parsed) {
    if (conn.state !== TCP_STATE.ESTABLISHED && conn.state !== TCP_STATE.FIN_WAIT) return;

    conn.peerRecvWindow = parsed.tcpWindow;

    if (!parsed.tcpFlagsACK) {
      this._flushServerReadBacklog(conn);
      this._syncServerSocketPause(conn);
      return;
    }

    const ack = parsed.tcpAck >>> 0;
    if (conn.lastPeerAck === undefined) {
      conn.lastPeerAck = ack;
      this._flushServerReadBacklog(conn);
      this._syncServerSocketPause(conn);
      return;
    }

    const prev = conn.lastPeerAck >>> 0;
    const delta = (ack - prev) >>> 0;
    if (delta > 0 && delta < 0x80000000) {
      conn.lastPeerAck = ack;
      if (conn.pendingResponses > 0) {
        const mss = 1360;
        const released = Math.min(
          conn.pendingResponses,
          Math.max(1, Math.ceil(delta / mss)),
        );
        conn.pendingResponses -= released;
      }
    }

    this._flushServerReadBacklog(conn);
    this._syncServerSocketPause(conn);
  }

  /** Данные от реального сервера (iperf), ещё не ушедшие в mesh к клиенту. */
  _flushServerReadBacklog(conn) {
    if (
      (conn.state !== TCP_STATE.ESTABLISHED && conn.state !== TCP_STATE.FIN_WAIT)
      || !conn.sendResponse
    ) {
      return;
    }

    const MSS = 1360;
    let backlog = conn.serverReadBacklog;
    if (!backlog || backlog.length === 0) {
      this._maybeSendServerFin(conn);
      return;
    }

    const { dstIp, srcIp, dstPort, srcPort, srcNodeId, sendResponse } = conn;
    let offset = 0;
    const maxP = this._maxPendingForConn(conn);

    while (offset < backlog.length && maxP > 0 && conn.pendingResponses < maxP) {
      const chunkSize = Math.min(MSS, backlog.length - offset);
      const chunk = backlog.subarray(offset, offset + chunkSize);
      const atEndOfBacklog = offset + chunkSize >= backlog.length;
      const responsePacket = buildTCPPacket(
        dstIp, srcIp,
        dstPort, srcPort,
        conn.serverSeq,
        conn.clientAck,
        atEndOfBacklog ? (TCP_FLAGS.PSH | TCP_FLAGS.ACK) : TCP_FLAGS.ACK,
        chunk,
      );

      conn.serverSeq += chunk.length;
      offset += chunkSize;
      conn.pendingResponses++;
      sendResponse(srcNodeId, responsePacket);
      metrics.recordResponse(responsePacket.length);
    }

    conn.serverReadBacklog = offset < backlog.length ? backlog.subarray(offset) : null;
    this._maybeSendServerFin(conn);
  }

  _maybeSendServerFin(conn) {
    if (
      !conn.eofFromServer
      || conn.finSent
      || conn.state !== TCP_STATE.ESTABLISHED
      || (conn.serverReadBacklog && conn.serverReadBacklog.length > 0)
      || conn.pendingResponses > 0
    ) {
      return;
    }

    const { dstIp, srcIp, dstPort, srcPort, srcNodeId, sendResponse } = conn;
    conn.finSent = true;
    conn.state = TCP_STATE.FIN_WAIT;

    const finPacket = buildTCPPacket(
      dstIp, srcIp,
      dstPort, srcPort,
      conn.serverSeq,
      conn.clientAck,
      TCP_FLAGS.FIN | TCP_FLAGS.ACK,
    );
    conn.serverSeq++;
    sendResponse(srcNodeId, finPacket);
  }

  _syncServerSocketPause(conn) {
    if (
      !conn.socket
      || (conn.state !== TCP_STATE.ESTABLISHED && conn.state !== TCP_STATE.FIN_WAIT)
    ) {
      return;
    }

    const win = conn.peerRecvWindow ?? 65535;
    const maxP = this._maxPendingForConn(conn);
    const overInFlight = maxP > 0 && conn.pendingResponses >= maxP;
    const zeroWin = win === 0;
    const backlogBytes = conn.serverReadBacklog?.length ?? 0;
    const backlogStuck = backlogBytes > 0 && (overInFlight || zeroWin || maxP === 0);

    const needPause = zeroWin || overInFlight || backlogStuck;

    const resumeBelow = this._resumePendingTarget(conn);
    const canResume =
      conn.serverSocketPaused
      && win > 0
      && maxP > 0
      && conn.pendingResponses < resumeBelow
      && conn.pendingResponses < maxP
      && !backlogStuck;

    if (needPause && !conn.serverSocketPaused) {
      conn.socket.pause();
      conn.serverSocketPaused = true;
    } else if (canResume) {
      conn.socket.resume();
      conn.serverSocketPaused = false;
    }
  }

  _handleICMP(parsed, srcNodeId, sendResponse) {
    const { srcIp, dstIp, icmpType, icmpData } = parsed;
    
    // ICMP Echo Request (ping) = type 8
    if (icmpType === 8) {
      
      // If destination is our virtual IP, reply directly
      if (dstIp === this.localVirtualIp) {
        const echoReply = this._buildICMPEchoReply(parsed);
        sendResponse(srcNodeId, echoReply);
        return;
      }
      
      // For external IPs, use ICMP helper
      if (this.icmpHelper && icmpData && icmpData.length >= 4) {
        const id = icmpData.readUInt16BE(0);
        const seq = icmpData.readUInt16BE(2);
        const payload = icmpData.length > 4 ? icmpData.subarray(4) : Buffer.alloc(0);
        const payloadHex = payload.toString('hex');
        
        const key = `${id}:${seq}`;
        this.icmpPending.set(key, { srcIp, srcNodeId, sendResponse });
        
        const cmd = `REQ ${dstIp} ${id} ${seq} ${payloadHex}\n`;
        this.icmpHelper.stdin.write(cmd);
      }
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
      metrics.recordTCPConnection();
      
      // If destination is our own virtual IP, connect to localhost instead
      const actualDstIp = (this.localVirtualIp && dstIp === this.localVirtualIp) ? '127.0.0.1' : dstIp;
      const isLocal = actualDstIp === '127.0.0.1';
      

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
        lastActivity: Date.now(),
        pendingResponses: 0,
        peerRecvWindow: parsed.tcpWindow ?? 65535,
        lastPeerAck: undefined,
        serverSocketPaused: false,
        serverReadBacklog: null,
        eofFromServer: false,
        finSent: false,
        clientFinSeen: false,
        clientFinSeq: null,
        socketEndedToServer: false,
      };

      this.tcpConnections.set(key, conn);

      const socket = new net.Socket();
      conn.socket = socket;
      
      socket.setTimeout(30000);

      socket.on('connect', () => {
        this.connectingCount--;
        
        if (conn.state === TCP_STATE.CLOSED) {
          socket.destroy();
          return;
        }

        conn.state = TCP_STATE.ESTABLISHED;
        conn.lastActivity = Date.now();
        conn.peerRecvWindow = 65535;

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
        metrics.recordTCPData(0, data.length);

        conn.serverReadBacklog = conn.serverReadBacklog
          ? Buffer.concat([conn.serverReadBacklog, data])
          : data;

        this._flushServerReadBacklog(conn);
        this._syncServerSocketPause(conn);
      });

      socket.on('end', () => {
        if (conn.state === TCP_STATE.CLOSED) return;

        conn.eofFromServer = true;
        this._flushServerReadBacklog(conn);
        this._maybeSendServerFin(conn);
        this._syncServerSocketPause(conn);
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

    if (
      (conn.state === TCP_STATE.ESTABLISHED || conn.state === TCP_STATE.FIN_WAIT)
      && !parsed.tcpFlagsRST
    ) {
      this._updatePeerWindowAndAck(conn, parsed);
    }

    // Чистый ACK от клиента (всё уже учтено в _updatePeerWindowAndAck)
    if (parsed.tcpFlagsACK && !parsed.tcpFlagsSYN && !parsed.tcpFlagsFIN && data.length === 0) {
      return;
    }

    if (parsed.tcpFlagsFIN) {
      // Повторный FIN (retransmit) — снова ACK, иначе conn уже удалён → !conn → RST в mesh.
      if (conn.clientFinSeen && conn.clientFinSeq === tcpSeq) {
        const dupAck = buildTCPPacket(
          dstIp, srcIp,
          dstPort, srcPort,
          conn.serverSeq,
          conn.clientAck,
          TCP_FLAGS.ACK,
        );
        sendResponse(srcNodeId, dupAck);
        return;
      }

      conn.clientFinSeen = true;
      conn.clientFinSeq = tcpSeq;
      conn.clientAck = tcpSeq + 1;

      const ackPacket = buildTCPPacket(
        dstIp, srcIp,
        dstPort, srcPort,
        conn.serverSeq,
        conn.clientAck,
        TCP_FLAGS.ACK,
      );
      sendResponse(srcNodeId, ackPacket);

      if (conn.socket && !conn.socketEndedToServer) {
        try {
          conn.socket.end();
        } catch {
          /* ignore */
        }
        conn.socketEndedToServer = true;
      }

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

    if (conn.state === TCP_STATE.ESTABLISHED || conn.state === TCP_STATE.FIN_WAIT) {
      this._syncServerSocketPause(conn);
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
