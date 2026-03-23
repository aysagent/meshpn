import { parentPort } from 'worker_threads';
import { encrypt } from '../crypto/encrypt.js';
import { createOnionPacket } from '../crypto/onion.js';
import { Packet } from '../network/packet.js';

parentPort.on('message', (job) => {
  const { jobId, payload, routeWithKeys, packetMeta, directMode } = job;

  try {
    const payloadBuf = Buffer.from(payload);

    const keys = routeWithKeys.map(r => ({
      nodeId: r.nodeId,
      sessionKey: Buffer.from(r.sessionKey),
    }));

    let encrypted;
    if (directMode && keys.length === 1) {
      encrypted = encrypt(payloadBuf, keys[0].sessionKey);
    } else {
      encrypted = createOnionPacket(payloadBuf, keys);
    }

    const pkt = new Packet({ ...packetMeta, payload: encrypted });
    const serialized = pkt.serialize();

    const buf = serialized.buffer.byteLength === serialized.length
      ? serialized.buffer
      : serialized.buffer.slice(serialized.byteOffset, serialized.byteOffset + serialized.length);

    parentPort.postMessage(
      { jobId, serialized: buf, nextHop: packetMeta.route[0], payloadLen: payloadBuf.length },
      [buf],
    );
  } catch (err) {
    parentPort.postMessage({ jobId, error: err.message });
  }
});
