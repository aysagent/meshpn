/**
 * Transport-level packet aggregation.
 *
 * Combines multiple small packets into a single large frame before
 * calling the underlying transport send (dc.send / ws.send).
 * This dramatically improves throughput on transports with high
 * per-message overhead (werift SCTP DataChannels: ~2 Mbit/s with
 * 1400-byte messages vs ~600 Mbit/s with 16KB messages).
 *
 * Frame format:
 *   [0xFE] [packetCount: uint16BE] [len1: uint16BE] [data1] [len2: uint16BE] [data2] ...
 *
 * Marker byte 0xFE distinguishes aggregated frames from:
 *   - Packet version 1/2 (0x01/0x02)
 *   - PacketBatcher batches (0xFF 0xFF)
 *
 * Max individual packet size: 65535 bytes (uint16).
 */

const FRAME_MARKER = 0xFE;
const MAX_FRAME_SIZE = 15000;
const FLUSH_INTERVAL_MS = 2;
const HEADER_SIZE = 3; // 1 byte marker + 2 bytes count
const DEFAULT_MAX_QUEUE = 500;

export class TransportSendBuffer {
  constructor(sendFn, opts = {}) {
    this.sendFn = sendFn;
    this.maxFrameSize = opts.maxFrameSize || MAX_FRAME_SIZE;
    this.flushIntervalMs = opts.flushIntervalMs ?? FLUSH_INTERVAL_MS;
    this.isReady = opts.isReady || (() => true);
    this.maxQueuePackets = opts.maxQueuePackets || DEFAULT_MAX_QUEUE;

    this.packets = [];
    this.currentSize = HEADER_SIZE;
    this.timer = null;
  }

  push(data) {
    if (this.packets.length >= this.maxQueuePackets) {
      return false;
    }

    const entrySize = 2 + data.length;

    if (this.currentSize + entrySize > this.maxFrameSize && this.packets.length > 0) {
      this._flush();
    }

    this.packets.push(data);
    this.currentSize += entrySize;

    if (this.currentSize >= this.maxFrameSize) {
      this._flush();
      return true;
    }

    if (!this.timer) {
      this.timer = setTimeout(() => {
        this.timer = null;
        this._flush();
      }, this.flushIntervalMs);
    }
    return true;
  }

  resume() {
    if (this.packets.length > 0) {
      this._flush();
    }
  }

  /** Для диагностики backpressure / дебага. */
  getQueueLength() {
    return this.packets.length;
  }

  flush() {
    this._flush();
  }

  _flush() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.packets.length === 0) return;

    if (!this.isReady()) {
      this._scheduleRetry();
      return;
    }

    if (this.currentSize <= this.maxFrameSize) {
      this._sendFrame(this.packets);
      this.packets = [];
      this.currentSize = HEADER_SIZE;
      return;
    }

    // Accumulated data exceeds one frame — drain in chunks
    while (this.packets.length > 0 && this.isReady()) {
      let batchSize = HEADER_SIZE;
      let count = 0;
      for (let i = 0; i < this.packets.length; i++) {
        const es = 2 + this.packets[i].length;
        if (batchSize + es > this.maxFrameSize && count > 0) break;
        batchSize += es;
        count++;
      }
      this._sendFrame(this.packets.splice(0, count));
    }

    this.currentSize = HEADER_SIZE;
    for (const p of this.packets) this.currentSize += 2 + p.length;

    if (this.packets.length > 0) {
      this._scheduleRetry();
    }
  }

  _sendFrame(packets) {
    if (packets.length === 1) {
      this.sendFn(packets[0]);
      return;
    }
    let size = HEADER_SIZE;
    for (const p of packets) size += 2 + p.length;

    const buf = Buffer.allocUnsafe(size);
    let offset = 0;
    buf[offset++] = FRAME_MARKER;
    buf.writeUInt16BE(packets.length, offset);
    offset += 2;
    for (const pkt of packets) {
      buf.writeUInt16BE(pkt.length, offset);
      offset += 2;
      pkt.copy(buf, offset);
      offset += pkt.length;
    }
    this.sendFn(buf);
  }

  _scheduleRetry() {
    if (!this.timer) {
      this.timer = setTimeout(() => {
        this.timer = null;
        this._flush();
      }, this.flushIntervalMs);
    }
  }

  stop() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.packets = [];
    this.currentSize = HEADER_SIZE;
  }
}

/**
 * Unpack a received frame.
 * Returns an array of individual packets, or null if the frame is malformed/truncated.
 * If the data is not an aggregated frame, returns [data] as-is.
 *
 * Callers MUST check for null and discard the message:
 *   const packets = unframe(buf);
 *   if (!packets) return; // malformed frame, already logged
 */
export function unframe(data) {
  if (data.length >= HEADER_SIZE && data[0] === FRAME_MARKER) {
    const count = data.readUInt16BE(1);
    const packets = [];
    let offset = HEADER_SIZE;

    for (let i = 0; i < count; i++) {
      if (offset + 2 > data.length) {
        console.warn(`[unframe] Truncated frame: expected length prefix at offset ${offset}, buf size ${data.length}`);
        return null;
      }
      const len = data.readUInt16BE(offset);
      offset += 2;
      if (offset + len > data.length) {
        console.warn(`[unframe] Truncated frame: expected ${len} bytes at offset ${offset}, buf size ${data.length}`);
        return null;
      }
      packets.push(data.subarray(offset, offset + len));
      offset += len;
    }

    return packets;
  }

  return [data];
}
