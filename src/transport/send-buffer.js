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

export class TransportSendBuffer {
  constructor(sendFn, opts = {}) {
    this.sendFn = sendFn;
    this.maxFrameSize = opts.maxFrameSize || MAX_FRAME_SIZE;
    this.flushIntervalMs = opts.flushIntervalMs ?? FLUSH_INTERVAL_MS;

    this.packets = [];
    this.currentSize = HEADER_SIZE;
    this.timer = null;
  }

  push(data) {
    const entrySize = 2 + data.length; // 2-byte length prefix + payload

    if (this.currentSize + entrySize > this.maxFrameSize && this.packets.length > 0) {
      this._flush();
    }

    this.packets.push(data);
    this.currentSize += entrySize;

    if (this.currentSize >= this.maxFrameSize) {
      this._flush();
      return;
    }

    if (!this.timer) {
      this.timer = setTimeout(() => {
        this.timer = null;
        this._flush();
      }, this.flushIntervalMs);
    }
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

    if (this.packets.length === 1) {
      this.sendFn(this.packets[0]);
      this.packets = [];
      this.currentSize = HEADER_SIZE;
      return;
    }

    const buf = Buffer.allocUnsafe(this.currentSize);
    let offset = 0;

    buf[offset++] = FRAME_MARKER;
    buf.writeUInt16BE(this.packets.length, offset);
    offset += 2;

    for (const pkt of this.packets) {
      buf.writeUInt16BE(pkt.length, offset);
      offset += 2;
      pkt.copy(buf, offset);
      offset += pkt.length;
    }

    this.packets = [];
    this.currentSize = HEADER_SIZE;

    this.sendFn(buf);
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
 * Returns an array of individual packets.
 * If the data is not an aggregated frame, returns [data] as-is.
 */
export function unframe(data) {
  if (data.length >= HEADER_SIZE && data[0] === FRAME_MARKER) {
    const count = data.readUInt16BE(1);
    const packets = [];
    let offset = HEADER_SIZE;

    for (let i = 0; i < count && offset < data.length; i++) {
      if (offset + 2 > data.length) break;
      const len = data.readUInt16BE(offset);
      offset += 2;
      if (offset + len > data.length) break;
      packets.push(data.subarray(offset, offset + len));
      offset += len;
    }

    return packets;
  }

  return [data];
}
