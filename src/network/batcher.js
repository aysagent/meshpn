// PacketBatcher - aggregates multiple packets into batches for efficient transmission
// Batch format: [4-byte total length][4-byte pkt1 len][pkt1][4-byte pkt2 len][pkt2]...

const MAX_BATCH_SIZE = 16384; // 16KB
const BATCH_TIMEOUT_MS = 5; // 5ms max delay

export class PacketBatcher {
  constructor(sendFn) {
    this.sendFn = sendFn;
    this.batches = new Map(); // peerId -> { packets: [], size: 0, timer: null }
  }

  add(peerId, packet) {
    let batch = this.batches.get(peerId);
    
    if (!batch) {
      batch = { packets: [], size: 0, timer: null };
      this.batches.set(peerId, batch);
    }

    const packetSize = 4 + packet.length; // 4 bytes for length prefix
    
    // If adding this packet would exceed max size, flush first
    if (batch.size > 0 && batch.size + packetSize > MAX_BATCH_SIZE) {
      this._flush(peerId, batch);
      batch = { packets: [], size: 0, timer: null };
      this.batches.set(peerId, batch);
    }

    batch.packets.push(packet);
    batch.size += packetSize;

    // Start timer if not already running
    if (!batch.timer) {
      batch.timer = setTimeout(() => {
        this._flush(peerId, batch);
      }, BATCH_TIMEOUT_MS);
    }

    // Flush immediately if we've reached max size
    if (batch.size >= MAX_BATCH_SIZE) {
      this._flush(peerId, batch);
    }

    return true;
  }

  _flush(peerId, batch) {
    if (batch.timer) {
      clearTimeout(batch.timer);
      batch.timer = null;
    }

    if (batch.packets.length === 0) {
      return;
    }

    // Single packet - send as-is (no batching overhead)
    if (batch.packets.length === 1) {
      this.sendFn(peerId, batch.packets[0]);
    } else {
      // Multiple packets - create batch
      const batchBuffer = this._createBatch(batch.packets);
      this.sendFn(peerId, batchBuffer);
    }

    batch.packets = [];
    batch.size = 0;
  }

  _createBatch(packets) {
    // Calculate total size: 4 bytes header + sum of (4 + packet.length) for each
    let totalSize = 4; // batch header (packet count)
    for (const pkt of packets) {
      totalSize += 4 + pkt.length;
    }

    const buffer = Buffer.alloc(totalSize);
    let offset = 0;

    // Write packet count as negative number to distinguish from single packet
    // Single packets start with positive type byte, batches start with 0xFFFFxxxx
    buffer.writeUInt32BE(0xFFFF0000 | packets.length, offset);
    offset += 4;

    for (const pkt of packets) {
      buffer.writeUInt32BE(pkt.length, offset);
      offset += 4;
      pkt.copy(buffer, offset);
      offset += pkt.length;
    }

    return buffer;
  }

  flushAll() {
    for (const [peerId, batch] of this.batches) {
      this._flush(peerId, batch);
    }
    this.batches.clear();
  }

  stop() {
    for (const [peerId, batch] of this.batches) {
      if (batch.timer) {
        clearTimeout(batch.timer);
      }
    }
    this.batches.clear();
  }
}

// Unbatch received data - returns array of packets
export function unbatch(data) {
  // Check if this is a batch (starts with 0xFFFF)
  if (data.length >= 4) {
    const header = data.readUInt32BE(0);
    if ((header & 0xFFFF0000) === 0xFFFF0000) {
      const packetCount = header & 0x0000FFFF;
      const packets = [];
      let offset = 4;

      for (let i = 0; i < packetCount && offset < data.length; i++) {
        if (offset + 4 > data.length) break;
        const pktLen = data.readUInt32BE(offset);
        offset += 4;
        if (offset + pktLen > data.length) break;
        packets.push(data.subarray(offset, offset + pktLen));
        offset += pktLen;
      }

      return packets;
    }
  }

  // Not a batch - return as single packet
  return [data];
}
