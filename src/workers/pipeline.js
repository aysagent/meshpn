import { Worker } from 'worker_threads';
import { fileURLToPath } from 'url';
import path from 'path';
import { encrypt, decrypt } from '../crypto/encrypt.js';
import { createOnionPacket, peelOnionLayer } from '../crypto/onion.js';
import { Packet, PacketType } from '../network/packet.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const MAX_PENDING = 2000;

export class WorkerPipeline {
  constructor(opts = {}) {
    this.enabled = opts.enabled !== false;
    this.txPoolSize = opts.txPool || 1;
    this.rxPoolSize = opts.rxPool || 1;

    this._jobId = 0;
    this._txPending = new Map();
    this._rxPending = new Map();
    this._txDropped = 0;
    this._rxDropped = 0;

    this.txWorkers = [];
    this.rxWorkers = [];
    this._txRR = 0;
    this._rxRR = 0;
    this._alive = false;

    if (this.enabled) {
      this._spawn();
    }
  }

  _spawn() {
    for (let i = 0; i < this.txPoolSize; i++) {
      this.txWorkers.push(this._createTxWorker(i));
    }
    for (let i = 0; i < this.rxPoolSize; i++) {
      this.rxWorkers.push(this._createRxWorker(i));
    }
    this._alive = true;
    console.log(`[Pipeline] Started: ${this.txPoolSize} TX + ${this.rxPoolSize} RX workers`);
  }

  _createTxWorker(index) {
    const w = new Worker(path.join(__dirname, 'tx-worker.js'));
    w.on('message', (msg) => this._onTxResult(msg));
    w.on('error', (err) => console.error('[Pipeline] TX worker error:', err.message));
    w.on('exit', (code) => {
      if (code !== 0 && this._alive) {
        console.error(`[Pipeline] TX worker crashed (code ${code}), flushing pending + respawn`);
        this._flushPending(this._txPending, 'TX worker crashed');
        this.txWorkers[index] = this._createTxWorker(index);
      }
    });
    return w;
  }

  _createRxWorker(index) {
    const w = new Worker(path.join(__dirname, 'rx-worker.js'));
    w.on('message', (msg) => this._onRxResult(msg));
    w.on('error', (err) => console.error('[Pipeline] RX worker error:', err.message));
    w.on('exit', (code) => {
      if (code !== 0 && this._alive) {
        console.error(`[Pipeline] RX worker crashed (code ${code}), flushing pending + respawn`);
        this._flushPending(this._rxPending, 'RX worker crashed');
        this.rxWorkers[index] = this._createRxWorker(index);
      }
    });
    return w;
  }

  _flushPending(map, reason) {
    for (const cb of map.values()) {
      try { cb(new Error(reason)); } catch {}
    }
    map.clear();
  }

  // ── TX ────────────────────────────────────────────

  submitTx(payload, routeWithKeys, packetMeta, directMode, callback) {
    if (!this._alive || this.txWorkers.length === 0) {
      return this._fallbackTx(payload, routeWithKeys, packetMeta, directMode, callback);
    }
    if (this._txPending.size >= MAX_PENDING) {
      this._txDropped++;
      return this._fallbackTx(payload, routeWithKeys, packetMeta, directMode, callback);
    }

    const jobId = this._jobId++;
    this._txPending.set(jobId, callback);

    const keys = routeWithKeys.map(r => ({
      nodeId: r.nodeId,
      sessionKey: r.sessionKey.buffer.slice(
        r.sessionKey.byteOffset,
        r.sessionKey.byteOffset + r.sessionKey.length,
      ),
    }));

    const ab = payload.buffer.byteLength === payload.length
      ? payload.buffer
      : payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.length);

    const worker = this.txWorkers[this._txRR++ % this.txWorkers.length];
    try {
      worker.postMessage(
        { jobId, payload: ab, routeWithKeys: keys, packetMeta, directMode },
        [ab],
      );
    } catch (err) {
      this._txPending.delete(jobId);
      this._fallbackTx(
        Buffer.from(ab), routeWithKeys, packetMeta, directMode, callback,
      );
    }
  }

  _onTxResult(msg) {
    const cb = this._txPending.get(msg.jobId);
    if (!cb) return;
    this._txPending.delete(msg.jobId);

    if (msg.error) {
      cb(new Error(msg.error));
    } else {
      cb(null, {
        serialized: Buffer.from(msg.serialized),
        nextHop: msg.nextHop,
        payloadLen: msg.payloadLen,
      });
    }
  }

  _fallbackTx(payload, routeWithKeys, packetMeta, directMode, callback) {
    try {
      let encrypted;
      if (directMode && routeWithKeys.length === 1) {
        encrypted = encrypt(payload, routeWithKeys[0].sessionKey);
      } else {
        encrypted = createOnionPacket(payload, routeWithKeys);
      }
      const pkt = new Packet({ ...packetMeta, payload: encrypted });
      const serialized = pkt.serialize();
      callback(null, { serialized, nextHop: packetMeta.route[0], payloadLen: payload.length });
    } catch (err) {
      callback(err);
    }
  }

  // ── RX ────────────────────────────────────────────

  submitRx(data, sessionKey, peerId, packetType, callback) {
    if (!this._alive || this.rxWorkers.length === 0) {
      return this._fallbackRx(data, sessionKey, peerId, packetType, callback);
    }
    if (this._rxPending.size >= MAX_PENDING) {
      this._rxDropped++;
      return this._fallbackRx(data, sessionKey, peerId, packetType, callback);
    }

    const jobId = this._jobId++;
    this._rxPending.set(jobId, callback);

    const dataAb = data.buffer.byteLength === data.length
      ? data.buffer
      : data.buffer.slice(data.byteOffset, data.byteOffset + data.length);

    const keyAb = sessionKey.buffer.byteLength === sessionKey.length
      ? sessionKey.buffer
      : sessionKey.buffer.slice(sessionKey.byteOffset, sessionKey.byteOffset + sessionKey.length);

    const worker = this.rxWorkers[this._rxRR++ % this.rxWorkers.length];
    try {
      worker.postMessage(
        { jobId, data: dataAb, sessionKey: keyAb, peerId, packetType },
        [dataAb],
      );
    } catch (err) {
      this._rxPending.delete(jobId);
      this._fallbackRx(Buffer.from(dataAb), sessionKey, peerId, packetType, callback);
    }
  }

  _onRxResult(msg) {
    const cb = this._rxPending.get(msg.jobId);
    if (!cb) return;
    this._rxPending.delete(msg.jobId);

    if (msg.error) {
      cb(new Error(msg.error));
      return;
    }
    if (msg.passthrough) {
      cb(null, { passthrough: true, data: Buffer.from(msg.data), peerId: msg.peerId });
      return;
    }

    const result = {
      peerId: msg.peerId,
      packetType: msg.packetType,
      payload: Buffer.from(msg.payload),
      packetMeta: msg.packetMeta,
    };
    if (msg.packetType === PacketType.DATA) {
      result.isExit = msg.isExit;
      result.nextHop = msg.nextHop;
    }
    cb(null, result);
  }

  _fallbackRx(data, sessionKey, peerId, packetType, callback) {
    try {
      const packet = Packet.deserialize(data);
      if (packetType === PacketType.DATA) {
        const layer = peelOnionLayer(packet.payload, sessionKey);
        callback(null, {
          peerId, packetType,
          payload: layer.payload,
          isExit: layer.isExit, nextHop: layer.nextHop,
          packetMeta: {
            flowId: packet.flowId, seq: packet.seq, hop: packet.hop, ttl: packet.ttl,
            srcNode: packet.srcNode, dstNode: packet.dstNode, route: packet.route,
          },
        });
      } else if (packetType === PacketType.DATA_DIRECT) {
        const payload = decrypt(packet.payload, sessionKey);
        callback(null, {
          peerId, packetType,
          payload,
          packetMeta: {
            flowId: packet.flowId, seq: packet.seq, hop: packet.hop, ttl: packet.ttl,
            srcNode: packet.srcNode, dstNode: packet.dstNode, route: packet.route,
          },
        });
      } else {
        callback(null, { passthrough: true, data, peerId });
      }
    } catch (err) {
      callback(err);
    }
  }

  // ── Lifecycle ─────────────────────────────────────

  getStats() {
    return {
      txPending: this._txPending.size,
      rxPending: this._rxPending.size,
      txDropped: this._txDropped,
      rxDropped: this._rxDropped,
    };
  }

  async terminate() {
    this._alive = false;
    this._flushPending(this._txPending, 'Pipeline terminated');
    this._flushPending(this._rxPending, 'Pipeline terminated');

    const all = [...this.txWorkers, ...this.rxWorkers].map(w => w.terminate());
    await Promise.all(all);
    this.txWorkers = [];
    this.rxWorkers = [];
    console.log('[Pipeline] All workers terminated');
  }
}
