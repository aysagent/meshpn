import { parentPort } from 'worker_threads';
import { decrypt } from '../crypto/encrypt.js';
import { peelOnionLayer } from '../crypto/onion.js';
import { Packet, PacketType } from '../network/packet.js';

parentPort.on('message', (job) => {
  const { jobId, data, sessionKey, peerId, packetType: hintType } = job;

  try {
    const buf = Buffer.from(data);

    if (hintType === PacketType.DATA) {
      const key = Buffer.from(sessionKey);
      const packet = Packet.deserialize(buf);
      const layer = peelOnionLayer(packet.payload, key);

      const payloadBuf = layer.payload;
      const ab = payloadBuf.buffer.byteLength === payloadBuf.length
        ? payloadBuf.buffer
        : payloadBuf.buffer.slice(payloadBuf.byteOffset, payloadBuf.byteOffset + payloadBuf.length);

      parentPort.postMessage({
        jobId, peerId,
        packetType: PacketType.DATA,
        payload: ab,
        isExit: layer.isExit,
        nextHop: layer.nextHop,
        packetMeta: {
          flowId: packet.flowId, seq: packet.seq, hop: packet.hop, ttl: packet.ttl,
          srcNode: packet.srcNode, dstNode: packet.dstNode, route: packet.route,
        },
      }, [ab]);
    } else if (hintType === PacketType.DATA_DIRECT) {
      const key = Buffer.from(sessionKey);
      const packet = Packet.deserialize(buf);
      const payload = decrypt(packet.payload, key);

      const ab = payload.buffer.byteLength === payload.length
        ? payload.buffer
        : payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.length);

      parentPort.postMessage({
        jobId, peerId,
        packetType: PacketType.DATA_DIRECT,
        payload: ab,
        packetMeta: {
          flowId: packet.flowId, seq: packet.seq, hop: packet.hop, ttl: packet.ttl,
          srcNode: packet.srcNode, dstNode: packet.dstNode, route: packet.route,
        },
      }, [ab]);
    } else {
      parentPort.postMessage({ jobId, peerId, passthrough: true, data: job.data });
    }
  } catch (err) {
    parentPort.postMessage({ jobId, peerId, error: err.message });
  }
});
