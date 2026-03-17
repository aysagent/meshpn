import { randomBytes } from 'crypto';

export const PacketType = {
  DATA: 0x01,
  CONTROL: 0x02,
  PING: 0x03,
  PONG: 0x04,
  ACK: 0x05,
  ROUTE_REQUEST: 0x06,
  ROUTE_RESPONSE: 0x07
};

export const DEFAULT_TTL = 32;
export const MAX_TTL = 64;

export class Packet {
  constructor(options = {}) {
    this.version = options.version || 1;
    this.type = options.type || PacketType.DATA;
    this.flowId = options.flowId || randomBytes(8).toString('hex');
    this.seq = options.seq || 0;
    this.hop = options.hop || 0;
    this.ttl = options.ttl ?? DEFAULT_TTL;
    this.srcNode = options.srcNode || null;
    this.dstNode = options.dstNode || null;
    this.route = options.route || [];
    this.visitedNodes = options.visitedNodes || [];
    this.timestamp = options.timestamp || Date.now();
    this.payload = options.payload || Buffer.alloc(0);
  }

  decrementTTL() {
    this.ttl--;
    return this.ttl > 0;
  }

  isTTLExpired() {
    return this.ttl <= 0;
  }

  addVisitedNode(nodeId) {
    if (!this.visitedNodes.includes(nodeId)) {
      this.visitedNodes.push(nodeId);
    }
    return this;
  }

  hasVisited(nodeId) {
    return this.visitedNodes.includes(nodeId);
  }

  getVisitedCount() {
    return this.visitedNodes.length;
  }

  serialize() {
    const header = Buffer.alloc(66);
    let offset = 0;
    
    header.writeUInt8(this.version, offset++);
    header.writeUInt8(this.type, offset++);
    header.writeUInt16BE(this.hop, offset);
    offset += 2;
    header.writeUInt8(this.ttl, offset++);
    header.writeUInt8(0, offset++);
    header.writeUInt32BE(this.seq, offset);
    offset += 4;
    
    const flowIdBuf = Buffer.from(this.flowId.padEnd(16, '\0').slice(0, 16));
    flowIdBuf.copy(header, offset);
    offset += 16;
    
    const srcBuf = Buffer.from((this.srcNode || '').padEnd(16, '\0').slice(0, 16));
    srcBuf.copy(header, offset);
    offset += 16;
    
    const dstBuf = Buffer.from((this.dstNode || '').padEnd(16, '\0').slice(0, 16));
    dstBuf.copy(header, offset);
    offset += 16;
    
    header.writeBigUInt64BE(BigInt(this.timestamp), offset);
    offset += 8;
    
    const routeJson = JSON.stringify(this.route);
    const routeBuf = Buffer.from(routeJson);
    const routeLen = Buffer.alloc(2);
    routeLen.writeUInt16BE(routeBuf.length, 0);
    
    const visitedJson = JSON.stringify(this.visitedNodes);
    const visitedBuf = Buffer.from(visitedJson);
    const visitedLen = Buffer.alloc(2);
    visitedLen.writeUInt16BE(visitedBuf.length, 0);
    
    const payloadLen = Buffer.alloc(4);
    payloadLen.writeUInt32BE(this.payload.length, 0);
    
    return Buffer.concat([
      header,
      routeLen,
      routeBuf,
      visitedLen,
      visitedBuf,
      payloadLen,
      this.payload
    ]);
  }

  static deserialize(buffer) {
    if (buffer.length < 66) {
      throw new Error('Buffer too short for packet header');
    }
    
    let offset = 0;
    
    const version = buffer.readUInt8(offset++);
    const type = buffer.readUInt8(offset++);
    const hop = buffer.readUInt16BE(offset);
    offset += 2;
    const ttl = buffer.readUInt8(offset++);
    offset++;
    const seq = buffer.readUInt32BE(offset);
    offset += 4;
    
    const flowId = buffer.subarray(offset, offset + 16).toString().replace(/\0/g, '');
    offset += 16;
    
    const srcNode = buffer.subarray(offset, offset + 16).toString().replace(/\0/g, '') || null;
    offset += 16;
    
    const dstNode = buffer.subarray(offset, offset + 16).toString().replace(/\0/g, '') || null;
    offset += 16;
    
    const timestamp = Number(buffer.readBigUInt64BE(offset));
    offset += 8;
    
    const routeLen = buffer.readUInt16BE(offset);
    offset += 2;
    
    const routeJson = buffer.subarray(offset, offset + routeLen).toString();
    const route = JSON.parse(routeJson);
    offset += routeLen;
    
    const visitedLen = buffer.readUInt16BE(offset);
    offset += 2;
    
    const visitedJson = buffer.subarray(offset, offset + visitedLen).toString();
    const visitedNodes = JSON.parse(visitedJson);
    offset += visitedLen;
    
    const payloadLen = buffer.readUInt32BE(offset);
    offset += 4;
    
    const payload = buffer.subarray(offset, offset + payloadLen);
    
    return new Packet({
      version,
      type,
      flowId,
      seq,
      hop,
      ttl,
      srcNode,
      dstNode,
      route,
      visitedNodes,
      timestamp,
      payload
    });
  }

  clone() {
    return new Packet({
      version: this.version,
      type: this.type,
      flowId: this.flowId,
      seq: this.seq,
      hop: this.hop,
      ttl: this.ttl,
      srcNode: this.srcNode,
      dstNode: this.dstNode,
      route: [...this.route],
      visitedNodes: [...this.visitedNodes],
      timestamp: this.timestamp,
      payload: Buffer.from(this.payload)
    });
  }

  incrementHop() {
    this.hop++;
    return this;
  }

  getNextHop() {
    if (this.hop < this.route.length) {
      return this.route[this.hop];
    }
    return null;
  }

  isLastHop() {
    return this.hop >= this.route.length - 1;
  }

  toJSON() {
    return {
      version: this.version,
      type: this.type,
      flowId: this.flowId,
      seq: this.seq,
      hop: this.hop,
      ttl: this.ttl,
      srcNode: this.srcNode,
      dstNode: this.dstNode,
      route: this.route,
      visitedNodes: this.visitedNodes,
      timestamp: this.timestamp,
      payloadLength: this.payload.length
    };
  }
}

export function createDataPacket(srcNode, dstNode, route, payload, flowId = null, ttl = DEFAULT_TTL) {
  return new Packet({
    type: PacketType.DATA,
    srcNode,
    dstNode,
    route,
    payload,
    flowId,
    ttl
  });
}

export function createPingPacket(srcNode) {
  return new Packet({
    type: PacketType.PING,
    srcNode,
    timestamp: Date.now()
  });
}

export function createPongPacket(srcNode, originalTimestamp) {
  return new Packet({
    type: PacketType.PONG,
    srcNode,
    payload: Buffer.from(originalTimestamp.toString())
  });
}

export function createAckPacket(srcNode, flowId, seq) {
  return new Packet({
    type: PacketType.ACK,
    srcNode,
    flowId,
    seq
  });
}

export function parseIPPacket(buffer) {
  if (buffer.length < 20) {
    return null;
  }
  
  const version = (buffer[0] >> 4) & 0x0f;
  if (version !== 4) {
    return { version, valid: false };
  }
  
  const headerLength = (buffer[0] & 0x0f) * 4;
  const totalLength = buffer.readUInt16BE(2);
  const protocol = buffer[9];
  
  const srcIp = `${buffer[12]}.${buffer[13]}.${buffer[14]}.${buffer[15]}`;
  const dstIp = `${buffer[16]}.${buffer[17]}.${buffer[18]}.${buffer[19]}`;
  
  return {
    version,
    valid: true,
    headerLength,
    totalLength,
    protocol,
    srcIp,
    dstIp
  };
}

export function buildIPPacket(srcIp, dstIp, protocol, payload) {
  const headerLength = 20;
  const totalLength = headerLength + payload.length;
  
  const header = Buffer.alloc(headerLength);
  
  header[0] = (4 << 4) | (headerLength / 4);
  header[1] = 0;
  header.writeUInt16BE(totalLength, 2);
  header.writeUInt16BE(0, 4);
  header.writeUInt16BE(0x4000, 6);
  header[8] = 64;
  header[9] = protocol;
  header.writeUInt16BE(0, 10);
  
  const srcParts = srcIp.split('.').map(Number);
  const dstParts = dstIp.split('.').map(Number);
  
  header[12] = srcParts[0];
  header[13] = srcParts[1];
  header[14] = srcParts[2];
  header[15] = srcParts[3];
  header[16] = dstParts[0];
  header[17] = dstParts[1];
  header[18] = dstParts[2];
  header[19] = dstParts[3];
  
  let checksum = 0;
  for (let i = 0; i < headerLength; i += 2) {
    checksum += header.readUInt16BE(i);
  }
  checksum = (checksum >> 16) + (checksum & 0xffff);
  checksum = ~checksum & 0xffff;
  header.writeUInt16BE(checksum, 10);
  
  return Buffer.concat([header, payload]);
}

function calculateTransportChecksum(srcIp, dstIp, protocol, transportData) {
  const srcParts = srcIp.split('.').map(Number);
  const dstParts = dstIp.split('.').map(Number);
  
  const pseudoHeaderLength = 12;
  const pseudoHeader = Buffer.alloc(pseudoHeaderLength);
  
  pseudoHeader[0] = srcParts[0];
  pseudoHeader[1] = srcParts[1];
  pseudoHeader[2] = srcParts[2];
  pseudoHeader[3] = srcParts[3];
  pseudoHeader[4] = dstParts[0];
  pseudoHeader[5] = dstParts[1];
  pseudoHeader[6] = dstParts[2];
  pseudoHeader[7] = dstParts[3];
  pseudoHeader[8] = 0;
  pseudoHeader[9] = protocol;
  pseudoHeader.writeUInt16BE(transportData.length, 10);
  
  const dataToChecksum = Buffer.concat([pseudoHeader, transportData]);
  
  let sum = 0;
  for (let i = 0; i < dataToChecksum.length - 1; i += 2) {
    sum += dataToChecksum.readUInt16BE(i);
  }
  if (dataToChecksum.length % 2 === 1) {
    sum += dataToChecksum[dataToChecksum.length - 1] << 8;
  }
  
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  
  return (~sum) & 0xffff;
}

export function buildUDPPacket(srcIp, dstIp, srcPort, dstPort, payload) {
  const UDP_HEADER_LENGTH = 8;
  const udpLength = UDP_HEADER_LENGTH + payload.length;
  
  const header = Buffer.alloc(UDP_HEADER_LENGTH);
  header.writeUInt16BE(srcPort, 0);
  header.writeUInt16BE(dstPort, 2);
  header.writeUInt16BE(udpLength, 4);
  header.writeUInt16BE(0, 6);
  
  const udpData = Buffer.concat([header, payload]);
  const checksum = calculateTransportChecksum(srcIp, dstIp, 17, udpData);
  udpData.writeUInt16BE(checksum || 0xffff, 6);
  
  return udpData;
}

export function buildTCPPacket(srcIp, dstIp, srcPort, dstPort, seqNum, ackNum, flags, payload, windowSize = 65535) {
  const TCP_HEADER_LENGTH = 20;
  
  const header = Buffer.alloc(TCP_HEADER_LENGTH);
  header.writeUInt16BE(srcPort, 0);
  header.writeUInt16BE(dstPort, 2);
  header.writeUInt32BE(seqNum >>> 0, 4);
  header.writeUInt32BE(ackNum >>> 0, 8);
  
  const dataOffset = (TCP_HEADER_LENGTH / 4) << 4;
  header.writeUInt8(dataOffset, 12);
  header.writeUInt8(flags, 13);
  header.writeUInt16BE(windowSize, 14);
  header.writeUInt16BE(0, 16);
  header.writeUInt16BE(0, 18);
  
  const tcpData = Buffer.concat([header, payload]);
  const checksum = calculateTransportChecksum(srcIp, dstIp, 6, tcpData);
  tcpData.writeUInt16BE(checksum, 16);
  
  return tcpData;
}

export const TCPFlags = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
};

export function buildIPPacketWithTransport(srcIp, dstIp, protocol, srcPort, dstPort, payload, tcpOptions = {}) {
  let transportData;
  
  if (protocol === 17) {
    transportData = buildUDPPacket(srcIp, dstIp, srcPort, dstPort, payload);
  } else if (protocol === 6) {
    const { seqNum = 0, ackNum = 0, flags = TCPFlags.ACK | TCPFlags.PSH, windowSize = 65535 } = tcpOptions;
    transportData = buildTCPPacket(srcIp, dstIp, srcPort, dstPort, seqNum, ackNum, flags, payload, windowSize);
  } else {
    transportData = payload;
  }
  
  return buildIPPacket(srcIp, dstIp, protocol, transportData);
}

export function buildTcpSynAckPacket(srcIp, dstIp, srcPort, dstPort, seqNum, clientSeqNum) {
  const ackNum = (clientSeqNum + 1) >>> 0;
  const flags = TCPFlags.SYN | TCPFlags.ACK;
  return buildIPPacketWithTransport(srcIp, dstIp, 6, srcPort, dstPort, Buffer.alloc(0), {
    seqNum,
    ackNum,
    flags,
    windowSize: 65535
  });
}

export function buildTcpAckPacket(srcIp, dstIp, srcPort, dstPort, seqNum, ackNum) {
  const flags = TCPFlags.ACK;
  return buildIPPacketWithTransport(srcIp, dstIp, 6, srcPort, dstPort, Buffer.alloc(0), {
    seqNum,
    ackNum,
    flags,
    windowSize: 65535
  });
}

export function buildTcpDataPacket(srcIp, dstIp, srcPort, dstPort, seqNum, ackNum, data) {
  const flags = TCPFlags.ACK | TCPFlags.PSH;
  return buildIPPacketWithTransport(srcIp, dstIp, 6, srcPort, dstPort, data, {
    seqNum,
    ackNum,
    flags,
    windowSize: 65535
  });
}

export function buildTcpFinPacket(srcIp, dstIp, srcPort, dstPort, seqNum, ackNum) {
  const flags = TCPFlags.FIN | TCPFlags.ACK;
  return buildIPPacketWithTransport(srcIp, dstIp, 6, srcPort, dstPort, Buffer.alloc(0), {
    seqNum,
    ackNum,
    flags,
    windowSize: 65535
  });
}

export function buildTcpRstPacket(srcIp, dstIp, srcPort, dstPort, seqNum) {
  const flags = TCPFlags.RST;
  return buildIPPacketWithTransport(srcIp, dstIp, 6, srcPort, dstPort, Buffer.alloc(0), {
    seqNum,
    ackNum: 0,
    flags,
    windowSize: 0
  });
}
