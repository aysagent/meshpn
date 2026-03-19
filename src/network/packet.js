export const PROTOCOLS = {
  ICMP: 1,
  TCP: 6,
  UDP: 17
};

export const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
};

export const PacketType = {
  DATA: 0x01,
  CONTROL: 0x02,
  PING: 0x03,
  PONG: 0x04,
  ACK: 0x05,
  ROUTE_REQUEST: 0x06,
  ROUTE_RESPONSE: 0x07,
  DATA_DIRECT: 0x08
};

export const DEFAULT_TTL = 32;
export const MAX_TTL = 64;

// Fast flowId generation using counter instead of slow randomBytes
let flowIdCounter = 0;
const flowIdPrefix = Date.now().toString(16).slice(-8);
function generateFlowId() {
  return flowIdPrefix + (flowIdCounter++).toString(16).padStart(8, '0');
}

export class Packet {
  constructor(options = {}) {
    this.version = options.version || 1;
    this.type = options.type || PacketType.DATA;
    this.flowId = options.flowId || generateFlowId();
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
    // Compact binary format (version 2):
    // Header (58 bytes): version(1) + type(1) + hop(2) + ttl(1) + routeCount(1) + seq(4) + flowId(16) + srcNode(16) + dstNode(16)
    // Route: 16 bytes per nodeId
    // Payload: 4 bytes length + data
    // Note: visitedNodes not sent over wire (used only locally for loop detection)
    
    const NODE_ID_SIZE = 16;
    const routeCount = this.route.length;
    const headerSize = 58;
    const routeSize = routeCount * NODE_ID_SIZE;
    const totalSize = headerSize + routeSize + 4 + this.payload.length;
    
    const buffer = Buffer.alloc(totalSize);
    let offset = 0;
    
    buffer.writeUInt8(2, offset++); // version 2 = compact format
    buffer.writeUInt8(this.type, offset++);
    buffer.writeUInt16BE(this.hop, offset);
    offset += 2;
    buffer.writeUInt8(this.ttl, offset++);
    buffer.writeUInt8(routeCount, offset++);
    buffer.writeUInt32BE(this.seq, offset);
    offset += 4;
    
    const flowIdBuf = Buffer.from(this.flowId.padEnd(NODE_ID_SIZE, '\0').slice(0, NODE_ID_SIZE));
    flowIdBuf.copy(buffer, offset);
    offset += NODE_ID_SIZE;
    
    const srcBuf = Buffer.from((this.srcNode || '').padEnd(NODE_ID_SIZE, '\0').slice(0, NODE_ID_SIZE));
    srcBuf.copy(buffer, offset);
    offset += NODE_ID_SIZE;
    
    const dstBuf = Buffer.from((this.dstNode || '').padEnd(NODE_ID_SIZE, '\0').slice(0, NODE_ID_SIZE));
    dstBuf.copy(buffer, offset);
    offset += NODE_ID_SIZE;
    
    // Write route as binary (16 bytes per nodeId)
    for (const nodeId of this.route) {
      const nodeBuf = Buffer.from((nodeId || '').padEnd(NODE_ID_SIZE, '\0').slice(0, NODE_ID_SIZE));
      nodeBuf.copy(buffer, offset);
      offset += NODE_ID_SIZE;
    }
    
    // Payload length and data
    buffer.writeUInt32BE(this.payload.length, offset);
    offset += 4;
    
    this.payload.copy(buffer, offset);
    
    return buffer;
  }

  static deserialize(buffer) {
    if (buffer.length < 6) {
      throw new Error('Buffer too short for packet header');
    }
    
    const version = buffer.readUInt8(0);
    
    if (version === 2) {
      return Packet._deserializeV2(buffer);
    } else {
      return Packet._deserializeV1(buffer);
    }
  }
  
  static _deserializeV2(buffer) {
    // Compact binary format (version 2)
    const NODE_ID_SIZE = 16;
    
    if (buffer.length < 58) {
      throw new Error('Buffer too short for v2 packet header');
    }
    
    let offset = 0;
    
    const version = buffer.readUInt8(offset++);
    const type = buffer.readUInt8(offset++);
    const hop = buffer.readUInt16BE(offset);
    offset += 2;
    const ttl = buffer.readUInt8(offset++);
    const routeCount = buffer.readUInt8(offset++);
    const seq = buffer.readUInt32BE(offset);
    offset += 4;
    
    const flowId = buffer.subarray(offset, offset + NODE_ID_SIZE).toString().replace(/\0/g, '');
    offset += NODE_ID_SIZE;
    
    const srcNode = buffer.subarray(offset, offset + NODE_ID_SIZE).toString().replace(/\0/g, '') || null;
    offset += NODE_ID_SIZE;
    
    const dstNode = buffer.subarray(offset, offset + NODE_ID_SIZE).toString().replace(/\0/g, '') || null;
    offset += NODE_ID_SIZE;
    
    // Read route
    const route = [];
    for (let i = 0; i < routeCount; i++) {
      const nodeId = buffer.subarray(offset, offset + NODE_ID_SIZE).toString().replace(/\0/g, '');
      route.push(nodeId);
      offset += NODE_ID_SIZE;
    }
    
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
      visitedNodes: [], // Not transmitted in v2
      timestamp: Date.now(),
      payload
    });
  }
  
  static _deserializeV1(buffer) {
    // Legacy JSON format (version 1)
    if (buffer.length < 66) {
      throw new Error('Buffer too short for v1 packet header');
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
  const ipId = buffer.readUInt16BE(4);
  const protocol = buffer[9];
  
  const srcIp = `${buffer[12]}.${buffer[13]}.${buffer[14]}.${buffer[15]}`;
  const dstIp = `${buffer[16]}.${buffer[17]}.${buffer[18]}.${buffer[19]}`;
  
  const result = {
    version,
    valid: true,
    headerLength,
    totalLength,
    ipId,
    protocol,
    srcIp,
    dstIp,
    srcPort: 0,
    dstPort: 0,
    data: Buffer.alloc(0)
  };

  const transportOffset = headerLength;

  if (protocol === PROTOCOLS.TCP && buffer.length >= transportOffset + 20) {
    result.srcPort = buffer.readUInt16BE(transportOffset);
    result.dstPort = buffer.readUInt16BE(transportOffset + 2);
    result.tcpSeq = buffer.readUInt32BE(transportOffset + 4);
    result.tcpAck = buffer.readUInt32BE(transportOffset + 8);
    const dataOffset = ((buffer[transportOffset + 12] >> 4) & 0x0f) * 4;
    result.tcpDataOffset = dataOffset;
    result.tcpFlags = buffer[transportOffset + 13];
    result.tcpFlagsSYN = !!(result.tcpFlags & TCP_FLAGS.SYN);
    result.tcpFlagsACK = !!(result.tcpFlags & TCP_FLAGS.ACK);
    result.tcpFlagsFIN = !!(result.tcpFlags & TCP_FLAGS.FIN);
    result.tcpFlagsRST = !!(result.tcpFlags & TCP_FLAGS.RST);
    result.tcpFlagsPSH = !!(result.tcpFlags & TCP_FLAGS.PSH);
    result.tcpWindow = buffer.readUInt16BE(transportOffset + 14);
    const payloadStart = transportOffset + dataOffset;
    if (buffer.length > payloadStart) {
      result.data = buffer.subarray(payloadStart);
    }
  } else if (protocol === PROTOCOLS.UDP && buffer.length >= transportOffset + 8) {
    result.srcPort = buffer.readUInt16BE(transportOffset);
    result.dstPort = buffer.readUInt16BE(transportOffset + 2);
    result.udpLength = buffer.readUInt16BE(transportOffset + 4);
    const payloadStart = transportOffset + 8;
    if (buffer.length > payloadStart) {
      result.data = buffer.subarray(payloadStart);
    }
  } else if (protocol === PROTOCOLS.ICMP && buffer.length >= transportOffset + 4) {
    result.icmpType = buffer[transportOffset];
    result.icmpCode = buffer[transportOffset + 1];
    // icmpData includes identifier (2 bytes) + sequence (2 bytes) + payload
    result.icmpData = buffer.subarray(transportOffset + 4);
    result.data = buffer.subarray(transportOffset + 8);
  }

  return result;
}

export function calculateIPChecksum(buffer) {
  let sum = 0;
  for (let i = 0; i < buffer.length; i += 2) {
    if (i + 1 < buffer.length) {
      sum += buffer.readUInt16BE(i);
    } else {
      sum += buffer[i] << 8;
    }
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
}

export function calculateTCPChecksum(srcIp, dstIp, tcpSegment) {
  const srcParts = srcIp.split('.').map(Number);
  const dstParts = dstIp.split('.').map(Number);
  
  const pseudoHeaderLen = 12;
  const totalLen = pseudoHeaderLen + tcpSegment.length;
  const paddedLen = totalLen % 2 === 0 ? totalLen : totalLen + 1;
  const buffer = Buffer.alloc(paddedLen);
  
  buffer[0] = srcParts[0]; buffer[1] = srcParts[1];
  buffer[2] = srcParts[2]; buffer[3] = srcParts[3];
  buffer[4] = dstParts[0]; buffer[5] = dstParts[1];
  buffer[6] = dstParts[2]; buffer[7] = dstParts[3];
  buffer[8] = 0;
  buffer[9] = PROTOCOLS.TCP;
  buffer.writeUInt16BE(tcpSegment.length, 10);
  tcpSegment.copy(buffer, 12);
  
  return calculateIPChecksum(buffer);
}

export function calculateUDPChecksum(srcIp, dstIp, udpDatagram) {
  const srcParts = srcIp.split('.').map(Number);
  const dstParts = dstIp.split('.').map(Number);
  
  const pseudoHeaderLen = 12;
  const totalLen = pseudoHeaderLen + udpDatagram.length;
  const paddedLen = totalLen % 2 === 0 ? totalLen : totalLen + 1;
  const buffer = Buffer.alloc(paddedLen);
  
  buffer[0] = srcParts[0]; buffer[1] = srcParts[1];
  buffer[2] = srcParts[2]; buffer[3] = srcParts[3];
  buffer[4] = dstParts[0]; buffer[5] = dstParts[1];
  buffer[6] = dstParts[2]; buffer[7] = dstParts[3];
  buffer[8] = 0;
  buffer[9] = PROTOCOLS.UDP;
  buffer.writeUInt16BE(udpDatagram.length, 10);
  udpDatagram.copy(buffer, 12);
  
  return calculateIPChecksum(buffer);
}

export function buildTCPSegment(srcPort, dstPort, seq, ack, flags, data = Buffer.alloc(0), windowSize = 65535) {
  const dataOffset = 5;
  const headerLen = dataOffset * 4;
  const segment = Buffer.alloc(headerLen + data.length);
  
  segment.writeUInt16BE(srcPort, 0);
  segment.writeUInt16BE(dstPort, 2);
  segment.writeUInt32BE(seq >>> 0, 4);
  segment.writeUInt32BE(ack >>> 0, 8);
  segment[12] = (dataOffset << 4);
  segment[13] = flags;
  segment.writeUInt16BE(windowSize, 14);
  segment.writeUInt16BE(0, 16);
  segment.writeUInt16BE(0, 18);
  
  if (data.length > 0) {
    data.copy(segment, headerLen);
  }
  
  return segment;
}

export function buildIPPacket(srcIp, dstIp, protocol, payload, id = null) {
  const srcParts = srcIp.split('.').map(Number);
  const dstParts = dstIp.split('.').map(Number);
  
  const headerLen = 20;
  const totalLen = headerLen + payload.length;
  const packet = Buffer.alloc(totalLen);
  
  packet[0] = 0x45;
  packet[1] = 0;
  packet.writeUInt16BE(totalLen, 2);
  packet.writeUInt16BE(id || (Math.random() * 0xffff) >>> 0, 4);
  packet.writeUInt16BE(0x4000, 6);
  packet[8] = 64;
  packet[9] = protocol;
  packet.writeUInt16BE(0, 10);
  
  packet[12] = srcParts[0]; packet[13] = srcParts[1];
  packet[14] = srcParts[2]; packet[15] = srcParts[3];
  packet[16] = dstParts[0]; packet[17] = dstParts[1];
  packet[18] = dstParts[2]; packet[19] = dstParts[3];
  
  const checksum = calculateIPChecksum(packet.subarray(0, 20));
  packet.writeUInt16BE(checksum, 10);
  
  payload.copy(packet, headerLen);
  
  return packet;
}

export function buildTCPPacket(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, data = Buffer.alloc(0)) {
  const tcpSegment = buildTCPSegment(srcPort, dstPort, seq, ack, flags, data);
  const checksum = calculateTCPChecksum(srcIp, dstIp, tcpSegment);
  tcpSegment.writeUInt16BE(checksum, 16);
  return buildIPPacket(srcIp, dstIp, PROTOCOLS.TCP, tcpSegment);
}

export function buildUDPDatagram(srcPort, dstPort, data) {
  const headerLen = 8;
  const totalLen = headerLen + data.length;
  const datagram = Buffer.alloc(totalLen);
  
  datagram.writeUInt16BE(srcPort, 0);
  datagram.writeUInt16BE(dstPort, 2);
  datagram.writeUInt16BE(totalLen, 4);
  datagram.writeUInt16BE(0, 6);
  
  if (data.length > 0) {
    data.copy(datagram, headerLen);
  }
  
  return datagram;
}

export function buildUDPPacket(srcIp, dstIp, srcPort, dstPort, data) {
  const udpDatagram = buildUDPDatagram(srcPort, dstPort, data);
  const checksum = calculateUDPChecksum(srcIp, dstIp, udpDatagram);
  udpDatagram.writeUInt16BE(checksum, 6);
  return buildIPPacket(srcIp, dstIp, PROTOCOLS.UDP, udpDatagram);
}

