import { EventEmitter } from 'events';
import dgram from 'dgram';
import net from 'net';
import dns from 'dns';
import { promisify } from 'util';
import { 
  buildTcpSynAckPacket, 
  buildTcpAckPacket, 
  buildTcpRstPacket, 
  buildTcpFinPacket
} from '../network/packet.js';

const dnsResolve = promisify(dns.resolve4);

export const TCPState = {
  LISTEN: 0,
  SYN_RECEIVED: 1,
  ESTABLISHED: 2,
  FIN_WAIT_1: 3,
  FIN_WAIT_2: 4,
  CLOSING: 5,
  TIME_WAIT: 6,
  CLOSED: 7
};

export const TCPFlags = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
};

export class NATTable extends EventEmitter {
  constructor(config = {}) {
    super();
    this.entries = new Map();
    this.reverseMap = new Map();
    this.portStart = config.portStart || 40000;
    this.portEnd = config.portEnd || 60000;
    this.nextPort = this.portStart;
    this.timeout = config.timeout || 300000;
    this.cleanupInterval = null;
  }

  start() {
    this.cleanupInterval = setInterval(() => {
      this._cleanup();
    }, 60000);
  }

  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.entries.clear();
    this.reverseMap.clear();
  }

  createMapping(srcNodeId, srcIp, srcPort, dstIp, dstPort, protocol, tcpInfo = null) {
    const key = `${srcNodeId}:${srcIp}:${srcPort}:${dstIp}:${dstPort}:${protocol}`;
    
    let entry = this.entries.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
      if (tcpInfo) {
        entry.clientSeqNum = tcpInfo.seqNum;
        entry.clientAckNum = tcpInfo.ackNum;
        entry.clientDataLen = tcpInfo.dataLen || 0;
      }
      return entry;
    }
    
    const natPort = this._allocatePort();
    
    entry = {
      key,
      srcNodeId,
      srcIp,
      srcPort,
      dstIp,
      dstPort,
      protocol,
      natPort,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      bytesIn: 0,
      bytesOut: 0,
      serverSeqNum: Math.floor(Math.random() * 0xFFFFFFFF),
      clientSeqNum: tcpInfo ? tcpInfo.seqNum : 0,
      clientAckNum: tcpInfo ? tcpInfo.ackNum : 0,
      clientDataLen: tcpInfo ? (tcpInfo.dataLen || 0) : 0,
      tcpState: TCPState.LISTEN,
      serverConn: null,
      pendingData: []
    };
    
    this.entries.set(key, entry);
    this.reverseMap.set(`${dstIp}:${dstPort}:${natPort}:${protocol}`, entry);
    
    this.emit('mapping-created', entry);
    
    return entry;
  }

  findMapping(key) {
    const entry = this.entries.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
    }
    return entry;
  }

  findReverseMapping(dstIp, dstPort, natPort, protocol) {
    const key = `${dstIp}:${dstPort}:${natPort}:${protocol}`;
    const entry = this.reverseMap.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
    }
    return entry;
  }

  removeMapping(key) {
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      this.reverseMap.delete(`${entry.dstIp}:${entry.dstPort}:${entry.natPort}:${entry.protocol}`);
      this.emit('mapping-removed', entry);
    }
  }

  _allocatePort() {
    const port = this.nextPort;
    this.nextPort++;
    if (this.nextPort > this.portEnd) {
      this.nextPort = this.portStart;
    }
    return port;
  }

  _cleanup() {
    const now = Date.now();
    const expired = [];
    
    for (const [key, entry] of this.entries) {
      if (now - entry.lastUsed > this.timeout) {
        expired.push(key);
      }
    }
    
    for (const key of expired) {
      this.removeMapping(key);
    }
    
    if (expired.length > 0) {
      this.emit('cleanup', expired.length);
    }
  }

  getStats() {
    return {
      totalMappings: this.entries.size,
      portRange: `${this.portStart}-${this.portEnd}`,
      nextPort: this.nextPort
    };
  }
}

export class ExitNodeForwarder extends EventEmitter {
  constructor(config = {}) {
    super();
    this.natTable = new NATTable(config.nat || {});
    this.udpSockets = new Map();
    this.tcpConnections = new Map();
    this.publicIp = config.publicIp || null;
    this.enabled = false;
  }

  async start() {
    this.natTable.start();
    this.enabled = true;
    
    if (!this.publicIp) {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        this.publicIp = data.ip;
      } catch {
        console.warn('Could not determine public IP');
      }
    }
    
    this.emit('started', { publicIp: this.publicIp });
  }

  stop() {
    this.enabled = false;
    this.natTable.stop();
    
    for (const socket of this.udpSockets.values()) {
      socket.close();
    }
    this.udpSockets.clear();
    
    for (const conn of this.tcpConnections.values()) {
      conn.destroy();
    }
    this.tcpConnections.clear();
    
    this.emit('stopped');
  }

  async forwardUDP(srcNodeId, srcIp, srcPort, dstIp, dstPort, payload) {
    if (!this.enabled) {
      return null;
    }
    
    const mapping = this.natTable.createMapping(
      srcNodeId, srcIp, srcPort, dstIp, dstPort, 'udp'
    );
    
    let socket = this.udpSockets.get(mapping.natPort);
    
    if (!socket) {
      socket = dgram.createSocket('udp4');
      
      socket.on('message', (msg, rinfo) => {
        this._handleUDPResponse(mapping.natPort, msg, rinfo);
      });
      
      socket.on('error', (err) => {
        this.emit('error', { type: 'udp', error: err });
      });
      
      await new Promise((resolve, reject) => {
        socket.bind(mapping.natPort, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      
      this.udpSockets.set(mapping.natPort, socket);
    }
    
    return new Promise((resolve, reject) => {
      socket.send(payload, dstPort, dstIp, (err) => {
        if (err) {
          reject(err);
        } else {
          mapping.bytesOut += payload.length;
          resolve(mapping);
        }
      });
    });
  }

  _handleUDPResponse(natPort, data, rinfo) {
    for (const entry of this.natTable.entries.values()) {
      if (entry.natPort === natPort && 
          entry.dstIp === rinfo.address && 
          entry.dstPort === rinfo.port &&
          entry.protocol === 'udp') {
        
        entry.bytesIn += data.length;
        entry.lastUsed = Date.now();
        
        this.emit('response', {
          srcNodeId: entry.srcNodeId,
          srcIp: entry.srcIp,
          srcPort: entry.srcPort,
          dstIp: entry.dstIp,
          dstPort: entry.dstPort,
          data,
          protocol: 'udp'
        });
        
        return;
      }
    }
  }

  async forwardTCP(srcNodeId, srcIp, srcPort, dstIp, dstPort, payload, tcpInfo = null) {
    if (!this.enabled) {
      return null;
    }
    
    const mapping = this.natTable.createMapping(
      srcNodeId, srcIp, srcPort, dstIp, dstPort, 'tcp', tcpInfo
    );
    
    const connKey = mapping.key;
    let conn = this.tcpConnections.get(connKey);
    
    try {
      if (!conn || conn.destroyed) {
        conn = await this._createTCPConnection(mapping);
        this.tcpConnections.set(connKey, conn);
      }
      
      return new Promise((resolve, reject) => {
        conn.write(payload, (err) => {
          if (err) {
            reject(err);
          } else {
            mapping.bytesOut += payload.length;
            resolve(mapping);
          }
        });
      });
    } catch (err) {
      console.error(`[EXIT] TCP forward failed to ${dstIp}:${dstPort}:`, err.message);
      this.tcpConnections.delete(connKey);
      this.natTable.removeMapping(connKey);
      return null;
    }
  }

  async _createTCPConnection(mapping) {
    return new Promise((resolve, reject) => {
      const conn = net.createConnection({
        host: mapping.dstIp,
        port: mapping.dstPort
      });
      
      conn.on('connect', () => {
        console.log(`[EXIT] TCP connected to ${mapping.dstIp}:${mapping.dstPort}`);
        resolve(conn);
      });
      
      conn.on('data', (data) => {
        mapping.bytesIn += data.length;
        mapping.lastUsed = Date.now();
        
        console.log(`[EXIT] TCP data received: ${data.length} bytes from ${mapping.dstIp}:${mapping.dstPort}`);
        
        const responseSeqNum = mapping.serverSeqNum;
        const responseAckNum = (mapping.clientSeqNum + mapping.clientDataLen) >>> 0;
        
        mapping.serverSeqNum = (mapping.serverSeqNum + data.length) >>> 0;
        
        this.emit('response', {
          srcNodeId: mapping.srcNodeId,
          srcIp: mapping.srcIp,
          srcPort: mapping.srcPort,
          dstIp: mapping.dstIp,
          dstPort: mapping.dstPort,
          data,
          protocol: 'tcp',
          tcpSeqNum: responseSeqNum,
          tcpAckNum: responseAckNum
        });
      });
      
      conn.on('error', (err) => {
        console.error(`[EXIT] TCP error for ${mapping.dstIp}:${mapping.dstPort}:`, err.message);
        reject(err);
      });
      
      conn.on('close', () => {
        console.log(`[EXIT] TCP closed for ${mapping.dstIp}:${mapping.dstPort}`);
        this.tcpConnections.delete(mapping.key);
        this.natTable.removeMapping(mapping.key);
      });
    });
  }

  async resolveDNS(hostname) {
    try {
      const addresses = await dnsResolve(hostname);
      return addresses[0];
    } catch (err) {
      this.emit('error', { type: 'dns', hostname, error: err });
      return null;
    }
  }

  getStats() {
    return {
      enabled: this.enabled,
      publicIp: this.publicIp,
      nat: this.natTable.getStats(),
      activeUdpSockets: this.udpSockets.size,
      activeTcpConnections: this.tcpConnections.size
    };
  }
}

export class ExitNode extends EventEmitter {
  constructor(config = {}) {
    super();
    this.forwarder = new ExitNodeForwarder(config);
    this.nodeId = config.nodeId;
    this.virtualIp = config.virtualIp;
  }

  async start() {
    this.forwarder.on('response', (response) => {
      this.emit('internet-response', response);
    });
    
    this.forwarder.on('error', (error) => {
      this.emit('error', error);
    });
    
    await this.forwarder.start();
    this.emit('started');
  }

  async processPacket(packet, payload) {
    console.log(`[EXIT] Processing packet from ${packet.srcNode}, payload length: ${payload.length}`);
    
    const ipHeader = this._parseIPHeader(payload);
    if (!ipHeader) {
      console.log('[EXIT] Failed to parse IP header');
      return null;
    }
    
    const { srcIp, dstIp, protocol, srcPort, dstPort, data, tcpSeqNum, tcpAckNum } = ipHeader;
    console.log(`[EXIT] Forwarding: ${srcIp}:${srcPort} -> ${dstIp}:${dstPort} proto=${protocol} data_len=${data.length}`);
    
    if (protocol === 1) {
      if (ipHeader.icmpType === 8) {
        console.log(`[EXIT] ICMP Echo Request from ${srcIp}, id=${ipHeader.icmpId}, seq=${ipHeader.icmpSeq}`);
        return this._handleIcmpEchoRequest(packet, ipHeader);
      }
      console.log(`[EXIT] Ignoring ICMP type ${ipHeader.icmpType}`);
      return null;
    } else if (protocol === 17) {
      return await this.forwarder.forwardUDP(
        packet.srcNode,
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        data
      );
    } else if (protocol === 6) {
      return await this._handleTcpPacket(packet, ipHeader);
    }
    
    return null;
  }

  async _handleTcpPacket(packet, ipHeader) {
    const { srcIp, dstIp, srcPort, dstPort, tcpSeqNum, tcpAckNum, tcpFlags, data } = ipHeader;
    
    const isSyn = (tcpFlags & TCPFlags.SYN) !== 0;
    const isAck = (tcpFlags & TCPFlags.ACK) !== 0;
    const isFin = (tcpFlags & TCPFlags.FIN) !== 0;
    const isRst = (tcpFlags & TCPFlags.RST) !== 0;
    const isPsh = (tcpFlags & TCPFlags.PSH) !== 0;
    
    console.log(`[EXIT] TCP flags: SYN=${isSyn} ACK=${isAck} FIN=${isFin} RST=${isRst} PSH=${isPsh} seq=${tcpSeqNum} ack=${tcpAckNum}`);
    
    const tcpInfo = { seqNum: tcpSeqNum, ackNum: tcpAckNum, dataLen: data.length };
    const mapping = this.forwarder.natTable.createMapping(
      packet.srcNode, srcIp, srcPort, dstIp, dstPort, 'tcp', tcpInfo
    );
    
    if (isRst) {
      console.log(`[EXIT] TCP RST received, closing connection`);
      this._closeTcpConnection(mapping);
      return null;
    }
    
    if (isSyn && !isAck) {
      if (mapping.tcpState === TCPState.LISTEN || mapping.tcpState === TCPState.SYN_RECEIVED) {
        console.log(`[EXIT] TCP SYN received, sending SYN-ACK`);
        mapping.clientSeqNum = tcpSeqNum;
        mapping.tcpState = TCPState.SYN_RECEIVED;
        
        this._sendTcpSynAck(packet.srcNode, dstIp, srcIp, dstPort, srcPort, mapping.serverSeqNum, tcpSeqNum);
        mapping.serverSeqNum = (mapping.serverSeqNum + 1) >>> 0;
        return mapping;
      }
    }
    
    if (isAck && !isSyn) {
      if (mapping.tcpState === TCPState.SYN_RECEIVED) {
        console.log(`[EXIT] TCP ACK received after SYN-ACK, connection established`);
        mapping.tcpState = TCPState.ESTABLISHED;
        mapping.clientAckNum = tcpAckNum;
        
        if (data.length > 0) {
          console.log(`[EXIT] ACK contains data: ${data.length} bytes, queuing`);
          mapping.pendingData.push(data);
          mapping.clientSeqNum = tcpSeqNum;
          mapping.clientDataLen = data.length;
        }
        
        try {
          await this._establishServerConnection(mapping);
        } catch (err) {
          console.error(`[EXIT] Failed to connect to server: ${err.message}`);
          this._sendTcpRst(packet.srcNode, dstIp, srcIp, dstPort, srcPort, tcpAckNum);
          this._closeTcpConnection(mapping);
          return null;
        }
        return mapping;
      }
      
      if (mapping.tcpState === TCPState.ESTABLISHED) {
        if (data.length > 0 || isPsh) {
          console.log(`[EXIT] TCP data received: ${data.length} bytes`);
          mapping.clientSeqNum = tcpSeqNum;
          mapping.clientAckNum = tcpAckNum;
          mapping.clientDataLen = data.length;
          
          if (mapping.serverConn && !mapping.serverConn.destroyed) {
            console.log(`[EXIT] Writing directly to server: ${data.length} bytes`);
            mapping.serverConn.write(data);
            mapping.bytesOut += data.length;
          } else {
            console.log(`[EXIT] Queuing data, serverConn not ready yet: ${data.length} bytes`);
            mapping.pendingData.push(data);
          }
        }
        return mapping;
      }
      
      if (mapping.tcpState === TCPState.FIN_WAIT_1) {
        console.log(`[EXIT] TCP ACK for FIN received`);
        mapping.tcpState = TCPState.FIN_WAIT_2;
        return mapping;
      }
    }
    
    if (isFin) {
      console.log(`[EXIT] TCP FIN received`);
      mapping.clientSeqNum = tcpSeqNum;
      
      this._sendTcpAck(packet.srcNode, dstIp, srcIp, dstPort, srcPort, 
        mapping.serverSeqNum, (tcpSeqNum + 1) >>> 0);
      
      if (mapping.serverConn) {
        mapping.serverConn.end();
      }
      
      mapping.tcpState = TCPState.CLOSED;
      setTimeout(() => this._closeTcpConnection(mapping), 1000);
      return mapping;
    }
    
    return null;
  }

  async _establishServerConnection(mapping) {
    return new Promise((resolve, reject) => {
      console.log(`[EXIT] Connecting to ${mapping.dstIp}:${mapping.dstPort}`);
      
      const conn = net.createConnection({
        host: mapping.dstIp,
        port: mapping.dstPort
      });
      
      conn.on('connect', () => {
        console.log(`[EXIT] Connected to ${mapping.dstIp}:${mapping.dstPort}`);
        mapping.serverConn = conn;
        
        console.log(`[EXIT] Flushing ${mapping.pendingData.length} pending data chunks`);
        console.log(`[EXIT] Socket connected: local=${conn.localAddress}:${conn.localPort} -> remote=${conn.remoteAddress}:${conn.remotePort}`);
        for (const data of mapping.pendingData) {
          console.log(`[EXIT] Sending to server: ${data.length} bytes`);
          console.log(`[EXIT] Data preview: ${data.toString('utf8').substring(0, 200).replace(/\r\n/g, '\\r\\n')}`);
          const result = conn.write(data);
          console.log(`[EXIT] Write result: ${result}, bufferSize=${conn.writableLength}`);
          mapping.bytesOut += data.length;
        }
        mapping.pendingData = [];
        
        resolve(conn);
      });
      
      conn.on('drain', () => {
        console.log(`[EXIT] Socket drained, ready for more writes`);
      });
      
      conn.on('data', (data) => {
        console.log(`[EXIT] Server data: ${data.length} bytes`);
        mapping.bytesIn += data.length;
        
        const ackNum = (mapping.clientSeqNum + mapping.clientDataLen) >>> 0;
        
        this.emit('internet-response', {
          srcNodeId: mapping.srcNodeId,
          srcIp: mapping.srcIp,
          srcPort: mapping.srcPort,
          dstIp: mapping.dstIp,
          dstPort: mapping.dstPort,
          data,
          protocol: 'tcp',
          tcpSeqNum: mapping.serverSeqNum,
          tcpAckNum: ackNum
        });
        
        mapping.serverSeqNum = (mapping.serverSeqNum + data.length) >>> 0;
      });
      
      conn.on('error', (err) => {
        console.error(`[EXIT] Server connection error: ${err.message}`);
        reject(err);
      });
      
      conn.on('end', () => {
        console.log(`[EXIT] Server sent FIN (end of data)`);
      });
      
      conn.on('close', (hadError) => {
        console.log(`[EXIT] Server connection closed, hadError=${hadError}`);
        if (mapping.tcpState === TCPState.ESTABLISHED) {
          this._sendTcpFin(mapping);
          mapping.tcpState = TCPState.FIN_WAIT_1;
        }
      });
    });
  }

  _sendTcpSynAck(srcNodeId, srcIp, dstIp, srcPort, dstPort, seqNum, clientSeqNum) {
    const ipPacket = buildTcpSynAckPacket(srcIp, dstIp, srcPort, dstPort, seqNum, clientSeqNum);
    
    this.emit('internet-response', {
      srcNodeId,
      srcIp: dstIp,
      srcPort: dstPort,
      dstIp: srcIp,
      dstPort: srcPort,
      data: ipPacket,
      protocol: 'raw'
    });
  }

  _sendTcpAck(srcNodeId, srcIp, dstIp, srcPort, dstPort, seqNum, ackNum) {
    const ipPacket = buildTcpAckPacket(srcIp, dstIp, srcPort, dstPort, seqNum, ackNum);
    
    this.emit('internet-response', {
      srcNodeId,
      srcIp: dstIp,
      srcPort: dstPort,
      dstIp: srcIp,
      dstPort: srcPort,
      data: ipPacket,
      protocol: 'raw'
    });
  }

  _sendTcpRst(srcNodeId, srcIp, dstIp, srcPort, dstPort, seqNum) {
    const ipPacket = buildTcpRstPacket(srcIp, dstIp, srcPort, dstPort, seqNum);
    
    this.emit('internet-response', {
      srcNodeId,
      srcIp: dstIp,
      srcPort: dstPort,
      dstIp: srcIp,
      dstPort: srcPort,
      data: ipPacket,
      protocol: 'raw'
    });
  }

  _sendTcpFin(mapping) {
    const ackNum = (mapping.clientSeqNum + mapping.clientDataLen) >>> 0;
    const ipPacket = buildTcpFinPacket(mapping.dstIp, mapping.srcIp, mapping.dstPort, mapping.srcPort, mapping.serverSeqNum, ackNum);
    
    this.emit('internet-response', {
      srcNodeId: mapping.srcNodeId,
      srcIp: mapping.srcIp,
      srcPort: mapping.srcPort,
      dstIp: mapping.dstIp,
      dstPort: mapping.dstPort,
      data: ipPacket,
      protocol: 'raw'
    });
  }

  _closeTcpConnection(mapping) {
    if (mapping.serverConn) {
      mapping.serverConn.destroy();
      mapping.serverConn = null;
    }
    mapping.tcpState = TCPState.CLOSED;
    this.forwarder.natTable.removeMapping(mapping.key);
  }

  _parseIPHeader(data) {
    if (data.length < 20) return null;
    
    const version = (data[0] >> 4) & 0x0f;
    if (version !== 4) return null;
    
    const headerLength = (data[0] & 0x0f) * 4;
    const protocol = data[9];
    const srcIp = `${data[12]}.${data[13]}.${data[14]}.${data[15]}`;
    const dstIp = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;
    
    let srcPort = 0;
    let dstPort = 0;
    let tcpSeqNum = 0;
    let tcpAckNum = 0;
    let tcpFlags = 0;
    let icmpType = 0;
    let icmpCode = 0;
    let icmpId = 0;
    let icmpSeq = 0;
    let transportData = data.subarray(headerLength);
    
    if (protocol === 17 && transportData.length >= 8) {
      srcPort = transportData.readUInt16BE(0);
      dstPort = transportData.readUInt16BE(2);
      transportData = transportData.subarray(8);
    } else if (protocol === 6 && transportData.length >= 20) {
      srcPort = transportData.readUInt16BE(0);
      dstPort = transportData.readUInt16BE(2);
      tcpSeqNum = transportData.readUInt32BE(4);
      tcpAckNum = transportData.readUInt32BE(8);
      tcpFlags = transportData.readUInt8(13);
      const tcpDataOffset = (transportData.readUInt8(12) >> 4) * 4;
      transportData = transportData.subarray(tcpDataOffset);
    } else if (protocol === 1 && transportData.length >= 8) {
      icmpType = transportData.readUInt8(0);
      icmpCode = transportData.readUInt8(1);
      icmpId = transportData.readUInt16BE(4);
      icmpSeq = transportData.readUInt16BE(6);
      transportData = transportData.subarray(8);
    }
    
    return {
      version,
      headerLength,
      protocol,
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      tcpSeqNum,
      tcpAckNum,
      tcpFlags,
      icmpType,
      icmpCode,
      icmpId,
      icmpSeq,
      data: transportData
    };
  }

  _handleIcmpEchoRequest(packet, ipHeader) {
    const { srcIp, dstIp, icmpId, icmpSeq, data } = ipHeader;
    
    const icmpReply = Buffer.alloc(8 + data.length);
    icmpReply.writeUInt8(0, 0);
    icmpReply.writeUInt8(0, 1);
    icmpReply.writeUInt16BE(0, 2);
    icmpReply.writeUInt16BE(icmpId, 4);
    icmpReply.writeUInt16BE(icmpSeq, 6);
    data.copy(icmpReply, 8);
    
    const checksum = this._calculateIcmpChecksum(icmpReply);
    icmpReply.writeUInt16BE(checksum, 2);
    
    console.log(`[EXIT] Sending ICMP Echo Reply to ${srcIp}, id=${icmpId}, seq=${icmpSeq}`);
    
    this.emit('internet-response', {
      srcNodeId: packet.srcNode,
      srcIp: srcIp,
      srcPort: 0,
      dstIp: dstIp,
      dstPort: 0,
      data: icmpReply,
      protocol: 'icmp'
    });
    
    return true;
  }

  _calculateIcmpChecksum(data) {
    let sum = 0;
    for (let i = 0; i < data.length; i += 2) {
      sum += (data[i] << 8) + (data[i + 1] || 0);
    }
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    return (~sum) & 0xffff;
  }

  stop() {
    this.forwarder.stop();
    this.emit('stopped');
  }

  getStats() {
    return {
      nodeId: this.nodeId,
      virtualIp: this.virtualIp,
      forwarder: this.forwarder.getStats()
    };
  }
}
