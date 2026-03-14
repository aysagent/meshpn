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

export class Packet {
  constructor(options = {}) {
    this.version = options.version || 1;
    this.type = options.type || PacketType.DATA;
    this.flowId = options.flowId || randomBytes(8).toString('hex');
    this.seq = options.seq || 0;
    this.hop = options.hop || 0;
    this.srcNode = options.srcNode || null;
    this.dstNode = options.dstNode || null;
    this.route = options.route || [];
    this.timestamp = options.timestamp || Date.now();
    this.payload = options.payload || Buffer.alloc(0);
  }

  serialize() {
    const header = Buffer.alloc(64);
    let offset = 0;
    
    header.writeUInt8(this.version, offset++);
    header.writeUInt8(this.type, offset++);
    header.writeUInt16BE(this.hop, offset);
    offset += 2;
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
    
    const payloadLen = Buffer.alloc(4);
    payloadLen.writeUInt32BE(this.payload.length, 0);
    
    return Buffer.concat([
      header,
      routeLen,
      routeBuf,
      payloadLen,
      this.payload
    ]);
  }

  static deserialize(buffer) {
    if (buffer.length < 64) {
      throw new Error('Buffer too short for packet header');
    }
    
    let offset = 0;
    
    const version = buffer.readUInt8(offset++);
    const type = buffer.readUInt8(offset++);
    const hop = buffer.readUInt16BE(offset);
    offset += 2;
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
    
    const payloadLen = buffer.readUInt32BE(offset);
    offset += 4;
    
    const payload = buffer.subarray(offset, offset + payloadLen);
    
    return new Packet({
      version,
      type,
      flowId,
      seq,
      hop,
      srcNode,
      dstNode,
      route,
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
      srcNode: this.srcNode,
      dstNode: this.dstNode,
      route: [...this.route],
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
      srcNode: this.srcNode,
      dstNode: this.dstNode,
      route: this.route,
      timestamp: this.timestamp,
      payloadLength: this.payload.length
    };
  }
}

export function createDataPacket(srcNode, dstNode, route, payload, flowId = null) {
  return new Packet({
    type: PacketType.DATA,
    srcNode,
    dstNode,
    route,
    payload,
    flowId
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
