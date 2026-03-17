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

