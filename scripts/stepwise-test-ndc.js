#!/usr/bin/env node
/**
 * Stepwise VPN Speed Debug — node-datachannel (libdatachannel) edition.
 *
 * Identical step logic to stepwise-test.js but uses node-datachannel
 * instead of werift for the WebRTC transport layer.
 *
 * Usage:
 *   Server: node scripts/stepwise-test-ndc.js server --step N [--stun-only] [--pkt-size 1400]
 *   Client: node scripts/stepwise-test-ndc.js client <ip> --step N [--relay] [--unordered] [--stun-only] [--pkt-size 1400]
 *
 * Steps:
 *   1  Raw DataChannel echo (1400-byte packets)
 *   2  + Packet serialize/deserialize
 *   3  + encrypt/decrypt (AES-256-GCM)
 *   4  + Onion routing (binary layer wrap/unwrap)
 *   5  + Full pipeline (Packet + Onion + serialize)
 *   6  + Batching (PacketBatcher + unbatch)
 *   7  + TransportSendBuffer aggregation
 *
 * Flags:
 *   --relay      Force TURN relay (iceTransportPolicy: 'relay')
 *   --unordered  Use unordered + unreliable DataChannel (like UDP)
 *   --stun-only  No TURN servers
 *   --pkt-size N Packet size in bytes (default 1400)
 */

import { PeerConnection, setSctpSettings } from 'node-datachannel';
import { WebSocketServer, WebSocket } from 'ws';
import { randomBytes } from 'crypto';
import http from 'http';

import { Packet, PacketType } from '../src/network/packet.js';
import { encrypt, decrypt } from '../src/crypto/encrypt.js';
import { createOnionPacket, peelOnionLayer } from '../src/crypto/onion.js';
import { PacketBatcher, unbatch } from '../src/network/batcher.js';
import { TransportSendBuffer, unframe } from '../src/transport/send-buffer.js';

setSctpSettings({
  recvBufferSize: 4 * 1024 * 1024,
  sendBufferSize: 4 * 1024 * 1024,
  maxChunksOnQueue: 16384,
  initialCongestionWindow: 65535,
  delayedSackTime: 2,
});

const SIGNAL_PORT = 9996;
const TEST_DURATION = 10_000;

const args = process.argv.slice(2);
const role = args[0];
const STUN_ONLY = args.includes('--stun-only');
const FORCE_RELAY = args.includes('--relay');
const UNORDERED = args.includes('--unordered');
const stepIdx = args.indexOf('--step');
const STEP = stepIdx !== -1 ? parseInt(args[stepIdx + 1], 10) : 1;
const pktIdx = args.indexOf('--pkt-size');
const PACKET_SIZE = pktIdx !== -1 ? parseInt(args[pktIdx + 1], 10) : 1400;
const serverIp = role === 'client' ? args[1] : null;

const STEP_NAMES = {
  1: 'Raw DataChannel',
  2: '+ Packet serialize/deserialize',
  3: '+ encrypt/decrypt (AES-256-GCM)',
  4: '+ Onion wrap/unwrap',
  5: '+ Full pipeline (Packet+Onion)',
  6: '+ Batching (old PacketBatcher)',
  7: '+ TransportSendBuffer aggregation',
};

if (!role || (role === 'client' && !serverIp) || !STEP_NAMES[STEP]) {
  console.log('Usage:');
  console.log('  Server: node scripts/stepwise-test-ndc.js server --step N [--stun-only] [--pkt-size 1400]');
  console.log('  Client: node scripts/stepwise-test-ndc.js client <ip> --step N [--relay] [--unordered] [--stun-only] [--pkt-size 1400]');
  console.log('\nSteps:');
  for (const [k, v] of Object.entries(STEP_NAMES)) console.log(`  ${k}  ${v}`);
  console.log('\nFlags:');
  console.log('  --relay      Force TURN relay');
  console.log('  --unordered  Unordered + unreliable DataChannel');
  process.exit(1);
}

function buildIceServers(forceRelay) {
  if (forceRelay) return ['turn:meshuser:meshpass@62.84.120.30:3478'];
  if (STUN_ONLY) return ['stun:stun.l.google.com:19302'];
  return ['stun:stun.l.google.com:19302', 'turn:meshuser:meshpass@62.84.120.30:3478'];
}

let sharedKey = null;
const SRC_NODE = 'ClientNodeAAAABB';
const DST_NODE = 'ServerNodeBBBBCC';

// --- Processing functions per step (identical to stepwise-test.js) ---

function clientProcess(payload) {
  if (STEP === 1 || STEP === 7) return payload;

  if (STEP === 2) {
    const pkt = new Packet({ type: PacketType.DATA_DIRECT, srcNode: SRC_NODE, dstNode: DST_NODE, payload });
    return pkt.serialize();
  }
  if (STEP === 3) return encrypt(payload, sharedKey);
  if (STEP === 4) return createOnionPacket(payload, [{ nodeId: DST_NODE, sessionKey: sharedKey }]);

  if (STEP === 5 || STEP === 6) {
    const encrypted = createOnionPacket(payload, [{ nodeId: DST_NODE, sessionKey: sharedKey }]);
    const pkt = new Packet({ type: PacketType.DATA, srcNode: SRC_NODE, dstNode: DST_NODE, route: [DST_NODE], payload: encrypted });
    return pkt.serialize();
  }
}

function serverProcess(data) {
  if (STEP === 1 || STEP === 7) return data;

  if (STEP === 2) {
    const pkt = Packet.deserialize(data);
    const echo = new Packet({ type: PacketType.DATA_DIRECT, srcNode: DST_NODE, dstNode: SRC_NODE, payload: pkt.payload });
    return echo.serialize();
  }
  if (STEP === 3) {
    const plain = decrypt(data, sharedKey);
    return encrypt(plain, sharedKey);
  }
  if (STEP === 4) {
    const layer = peelOnionLayer(data, sharedKey);
    return encrypt(layer.payload, sharedKey);
  }
  if (STEP === 5 || STEP === 6) {
    const pkt = Packet.deserialize(data);
    const layer = peelOnionLayer(pkt.payload, sharedKey);
    const encPayload = encrypt(layer.payload, sharedKey);
    const echo = new Packet({ type: PacketType.DATA_DIRECT, srcNode: DST_NODE, dstNode: SRC_NODE, payload: encPayload });
    return echo.serialize();
  }
}

function clientReceiveProcess(data) {
  if (STEP === 1 || STEP === 7) return data.length;
  if (STEP === 2) { Packet.deserialize(data); return data.length; }
  if (STEP === 3) { decrypt(data, sharedKey); return data.length; }
  if (STEP === 4) { decrypt(data, sharedKey); return data.length; }
  if (STEP === 5 || STEP === 6) {
    const pkt = Packet.deserialize(data);
    decrypt(pkt.payload, sharedKey);
    return data.length;
  }
}

// --- Main test class ---

class StepTestNdc {
  constructor() {
    this.pc = null;
    this.dc = null;
    this.ws = null;
    this.batcher = null;
    this._serverSendBuf = null;

    this.uploadBytes = 0;
    this.uploadPkts = 0;
    this.downloadBytes = 0;
    this.downloadPkts = 0;
    this.startTime = 0;
    this._done = false;
  }

  async run() {
    console.log(`\n===== STEPWISE VPN SPEED TEST (node-datachannel) =====`);
    console.log(`Step ${STEP}: ${STEP_NAMES[STEP]}`);
    console.log(`ICE: ${STUN_ONLY ? 'STUN only' : FORCE_RELAY ? 'TURN relay only' : 'STUN + TURN'}`);
    console.log(`Role: ${role}`);
    console.log(`Packet size: ${PACKET_SIZE} bytes`);
    console.log(`DataChannel: ${UNORDERED ? 'unordered + unreliable' : 'ordered + reliable'}`);
    console.log(`Duration: ${TEST_DURATION / 1000}s\n`);

    if (role === 'server') await this.startServer();
    else await this.startClient();
  }

  async startServer() {
    const httpServer = http.createServer();
    const wss = new WebSocketServer({ server: httpServer });

    wss.on('connection', (ws) => {
      console.log('Client connected');
      this.ws = ws;
      this._peerReady = false;
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'config' && !this._peerReady) {
          this._peerReady = true;
          const relay = !!msg.relay;
          if (relay) console.log('Client requested TURN relay mode');
          this.setupPeer(true, relay);
          return;
        }
        this.handleSignal(msg);
      });
    });

    httpServer.listen(SIGNAL_PORT, () => {
      console.log(`Signal server on port ${SIGNAL_PORT}`);
    });
  }

  async startClient() {
    const url = `ws://${serverIp}:${SIGNAL_PORT}`;
    console.log(`Connecting to ${url}...`);
    this.ws = new WebSocket(url);
    this.ws.on('open', () => {
      console.log('Connected to signal server');
      this.ws.send(JSON.stringify({ type: 'config', relay: FORCE_RELAY, unordered: UNORDERED }));
      this.setupPeer(false);
    });
    this.ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      this.handleSignal(msg);
    });
    this.ws.on('error', (err) => console.error('WS error:', err.message));
  }

  setupPeer(isInitiator, relayOverride) {
    const useRelay = FORCE_RELAY || relayOverride;
    const pcConfig = {
      iceServers: buildIceServers(useRelay),
      maxMessageSize: 65536,
    };
    if (useRelay) pcConfig.iceTransportPolicy = 'relay';

    this.pc = new PeerConnection(`ndc-step-${role}`, pcConfig);

    this.pc.onLocalDescription((sdp, type) => {
      this.signal({ type: type.toLowerCase(), sdp });
    });

    this.pc.onLocalCandidate((candidate, mid) => {
      this.signal({ type: 'candidate', candidate, mid });
    });

    this.pc.onStateChange((state) => {
      console.log(`Connection state: ${state}`);
      if (state === 'connected') this._logCandidatePair();
    });

    this.pc.onGatheringStateChange((state) => {
      console.log(`Gathering state: ${state}`);
    });

    if (isInitiator) {
      if (STEP >= 3) {
        sharedKey = randomBytes(32);
        this.signal({ type: 'key', key: sharedKey.toString('hex') });
      }
      const dcOpts = {};
      if (UNORDERED) {
        dcOpts.unordered = true;
        dcOpts.maxRetransmits = 0;
      }
      const dc = this.pc.createDataChannel('step-test', dcOpts);
      this._setupDC(dc);
    } else {
      this.pc.onDataChannel((dc) => {
        this._setupDC(dc);
      });
    }
  }

  _setupDC(dc) {
    this.dc = dc;

    dc.onOpen(() => {
      console.log('DataChannel open');
      if (role === 'client') this.runTest();
      else console.log('Waiting for data...');
    });

    dc.onClosed(() => {
      console.log('DataChannel closed');
      if (!this._done) {
        this._done = true;
        this.printResults();
      }
    });
    dc.onError((err) => console.error('DataChannel error:', err));

    if (role === 'server') {
      if (STEP === 6) {
        this.batcher = new PacketBatcher((_, data) => {
          try { dc.sendMessageBinary(Buffer.isBuffer(data) ? data : Buffer.from(data)); } catch {}
        });
      }
      if (STEP === 7) {
        this._serverSendBuf = new TransportSendBuffer((frame) => {
          try { dc.sendMessageBinary(Buffer.isBuffer(frame) ? frame : Buffer.from(frame)); } catch {}
        });
      }

      dc.onMessage((raw) => {
        const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);

        if (STEP === 7) {
          for (const pkt of unframe(buf)) {
            try {
              const echo = serverProcess(pkt);
              this._serverSendBuf.push(echo);
            } catch {}
          }
        } else if (STEP === 6) {
          for (const pkt of unbatch(buf)) {
            try {
              const echo = serverProcess(pkt);
              this.batcher.add('client', echo);
            } catch {}
          }
        } else {
          try {
            const echo = serverProcess(buf);
            dc.sendMessageBinary(Buffer.isBuffer(echo) ? echo : Buffer.from(echo));
          } catch {}
        }
      });
    }

    if (role === 'client') {
      dc.onMessage((raw) => {
        const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);

        if (STEP === 7) {
          for (const pkt of unframe(buf)) {
            try {
              clientReceiveProcess(pkt);
              this.downloadBytes += pkt.length;
              this.downloadPkts++;
            } catch {}
          }
        } else if (STEP === 6) {
          for (const pkt of unbatch(buf)) {
            try {
              clientReceiveProcess(pkt);
              this.downloadBytes += pkt.length;
              this.downloadPkts++;
            } catch {}
          }
        } else {
          try {
            clientReceiveProcess(buf);
            this.downloadBytes += buf.length;
            this.downloadPkts++;
          } catch {}
        }
      });
    }
  }

  runTest() {
    console.log('\nTest running...\n');
    this.startTime = Date.now();
    this._done = false;
    const payload = randomBytes(PACKET_SIZE);

    let batcher = null;
    if (STEP === 6) {
      batcher = new PacketBatcher((_, data) => {
        try { this.dc.sendMessageBinary(Buffer.isBuffer(data) ? data : Buffer.from(data)); } catch {}
      });
    }
    let sendBuf = null;
    if (STEP === 7) {
      sendBuf = new TransportSendBuffer((frame) => {
        try { this.dc.sendMessageBinary(Buffer.isBuffer(frame) ? frame : Buffer.from(frame)); } catch {}
      });
    }

    let lastLog = Date.now();

    const sendBatch = () => {
      if (this._done) return;

      const now = Date.now();
      const elapsed = now - this.startTime;

      if (elapsed >= TEST_DURATION) {
        this._done = true;
        if (batcher) batcher.flushAll();
        if (sendBuf) sendBuf.flush();
        console.log('Test complete, waiting for remaining echoes...');
        setTimeout(() => this.printResults(), 1000);
        return;
      }

      if (now - lastLog >= 2000) {
        const sec = elapsed / 1000;
        const upMbps = ((this.uploadBytes * 8) / sec / 1e6).toFixed(2);
        const dnMbps = ((this.downloadBytes * 8) / sec / 1e6).toFixed(2);
        const buffered = typeof this.dc.bufferedAmount === 'function' ? this.dc.bufferedAmount() : 0;
        console.log(`[${sec.toFixed(1)}s] up: ${upMbps} Mbit/s (${this.uploadPkts} pkts) | dn: ${dnMbps} Mbit/s (${this.downloadPkts} pkts) | buf: ${buffered}`);
        lastLog = now;
      }

      let sent = 0;
      while (sent < 100) {
        if (typeof this.dc.isOpen === 'function' && !this.dc.isOpen()) break;
        const buffered = typeof this.dc.bufferedAmount === 'function' ? this.dc.bufferedAmount() : 0;
        if (buffered > 1024 * 1024) break;
        try {
          const processed = clientProcess(payload);
          const toSend = Buffer.isBuffer(processed) ? processed : Buffer.from(processed);
          if (STEP === 7) {
            sendBuf.push(toSend);
          } else if (STEP === 6) {
            batcher.add('server', toSend);
          } else {
            this.dc.sendMessageBinary(toSend);
          }
          this.uploadBytes += processed.length;
          this.uploadPkts++;
          sent++;
        } catch (e) {
          if (!this._done) console.error('Send error:', e.message);
          break;
        }
      }

      setTimeout(sendBatch, 1);
    };

    sendBatch();

    setTimeout(() => {
      if (!this._done) {
        this._done = true;
        console.log('Safety timeout reached');
        this.printResults();
      }
    }, TEST_DURATION + 5000);
  }

  printResults() {
    const duration = (Date.now() - this.startTime) / 1000;
    const fmt = (bytes, sec) => {
      const bps = (bytes * 8) / sec;
      if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbit/s`;
      if (bps >= 1e3) return `${(bps / 1e3).toFixed(2)} Kbit/s`;
      return `${bps.toFixed(0)} bit/s`;
    };
    const fmtB = (b) => {
      if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(2)} MB`;
      if (b >= 1024) return `${(b / 1024).toFixed(2)} KB`;
      return `${b} B`;
    };

    console.log(`\n======= STEP ${STEP}: ${STEP_NAMES[STEP]} (NDC) =======`);
    console.log(`Duration: ${duration.toFixed(1)}s`);
    console.log(`Packet size: ${PACKET_SIZE} bytes`);
    console.log(`DataChannel: ${UNORDERED ? 'unordered + unreliable' : 'ordered + reliable'}`);
    console.log(`--- Upload (client -> server) ---`);
    console.log(`  Total:   ${fmtB(this.uploadBytes)}`);
    console.log(`  Speed:   ${fmt(this.uploadBytes, duration)}`);
    console.log(`  Packets: ${this.uploadPkts} (${(this.uploadPkts / duration).toFixed(0)} pkt/s)`);
    console.log(`--- Download (server -> client, echo) ---`);
    console.log(`  Total:   ${fmtB(this.downloadBytes)}`);
    console.log(`  Speed:   ${fmt(this.downloadBytes, duration)}`);
    console.log(`  Packets: ${this.downloadPkts} (${(this.downloadPkts / duration).toFixed(0)} pkt/s)`);
    console.log(`${'='.repeat(50)}\n`);

    setTimeout(() => process.exit(0), 1000);
  }

  _logCandidatePair() {
    try {
      const pair = this.pc.getSelectedCandidatePair();
      const l = pair.local;
      const r = pair.remote;
      const isRelay = l.type === 'relay' || r.type === 'relay';
      const tag = isRelay ? 'RELAY (TURN)' : 'DIRECT P2P';
      console.log(`Path: ${l.type} ${l.address}:${l.port} (${l.transportType}) <-> ${r.type} ${r.address}:${r.port} (${r.transportType}) [${tag}]`);
    } catch {}
  }

  handleSignal(msg) {
    if (msg.type === 'key') {
      sharedKey = Buffer.from(msg.key, 'hex');
      console.log('Received shared key');
    } else if (msg.type === 'offer') {
      this.pc.setRemoteDescription(msg.sdp, 'Offer');
    } else if (msg.type === 'answer') {
      this.pc.setRemoteDescription(msg.sdp, 'Answer');
    } else if (msg.type === 'candidate') {
      this.pc.addRemoteCandidate(msg.candidate, msg.mid || '0');
    }
  }

  signal(msg) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }
}

const test = new StepTestNdc();
test.run().catch((err) => {
  console.error(err);
  process.exit(1);
});
