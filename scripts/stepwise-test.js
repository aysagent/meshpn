#!/usr/bin/env node
/**
 * Stepwise VPN Speed Debug
 *
 * Each step adds one layer of the VPN stack on top of raw WebRTC.
 * Compare speeds between steps to find the bottleneck.
 *
 * Usage:
 *   Server: node scripts/stepwise-test.js server --step N [--stun-only]
 *   Client: node scripts/stepwise-test.js client <server-ip> --step N [--stun-only]
 *
 * Steps:
 *   1  Raw DataChannel echo (1400-byte packets)
 *   2  + Packet serialize/deserialize
 *   3  + encrypt/decrypt (AES-256-GCM)
 *   4  + Onion routing (binary layer wrap/unwrap)
 *   5  + Full pipeline (Packet + Onion + serialize)
 *   6  + Batching (PacketBatcher + unbatch)
 */

import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate } from 'werift';
import { WebSocketServer, WebSocket } from 'ws';
import { randomBytes } from 'crypto';
import http from 'http';

import { Packet, PacketType } from '../src/network/packet.js';
import { encrypt, decrypt } from '../src/crypto/encrypt.js';
import { createOnionPacket, peelOnionLayer } from '../src/crypto/onion.js';
import { PacketBatcher, unbatch } from '../src/network/batcher.js';

const SIGNAL_PORT = 9997;
const TEST_DURATION = 10_000;
const PACKET_SIZE = 1400;

const TURN_SERVERS = [
  { urls: 'turn:62.84.120.30:3478', username: 'meshuser', credential: 'meshpass' }
];
const STUN_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

const args = process.argv.slice(2);
const role = args[0];
const STUN_ONLY = args.includes('--stun-only');
const stepIdx = args.indexOf('--step');
const STEP = stepIdx !== -1 ? parseInt(args[stepIdx + 1], 10) : 1;
const serverIp = role === 'client' ? args[1] : null;

const STEP_NAMES = {
  1: 'Raw DataChannel',
  2: '+ Packet serialize/deserialize',
  3: '+ encrypt/decrypt (AES-256-GCM)',
  4: '+ Onion wrap/unwrap',
  5: '+ Full pipeline (Packet+Onion)',
  6: '+ Batching',
};

if (!role || (role === 'client' && !serverIp) || !STEP_NAMES[STEP]) {
  console.log('Usage:');
  console.log('  Server: node scripts/stepwise-test.js server --step N [--stun-only]');
  console.log('  Client: node scripts/stepwise-test.js client <ip> --step N [--stun-only]');
  console.log('\nSteps:');
  for (const [k, v] of Object.entries(STEP_NAMES)) console.log(`  ${k}  ${v}`);
  process.exit(1);
}

// Shared key for encryption steps (exchanged via signalling)
let sharedKey = null;
const SRC_NODE = 'ClientNodeAAAABB';  // 16 chars to match NODE_ID_SIZE
const DST_NODE = 'ServerNodeBBBBCC';  // 16 chars to match NODE_ID_SIZE

// --- Processing functions per step ---

function clientProcess(payload) {
  if (STEP === 1) return payload;

  if (STEP === 2) {
    const pkt = new Packet({ type: PacketType.DATA_DIRECT, srcNode: SRC_NODE, dstNode: DST_NODE, payload });
    return pkt.serialize();
  }

  if (STEP === 3) {
    return encrypt(payload, sharedKey);
  }

  if (STEP === 4) {
    return createOnionPacket(payload, [{ nodeId: DST_NODE, sessionKey: sharedKey }]);
  }

  if (STEP >= 5) {
    const encrypted = createOnionPacket(payload, [{ nodeId: DST_NODE, sessionKey: sharedKey }]);
    const pkt = new Packet({ type: PacketType.DATA, srcNode: SRC_NODE, dstNode: DST_NODE, route: [DST_NODE], payload: encrypted });
    return pkt.serialize();
  }
}

function serverProcess(data) {
  if (STEP === 1) return data;

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

  if (STEP >= 5) {
    const pkt = Packet.deserialize(data);
    const layer = peelOnionLayer(pkt.payload, sharedKey);
    const encPayload = encrypt(layer.payload, sharedKey);
    const echo = new Packet({ type: PacketType.DATA_DIRECT, srcNode: DST_NODE, dstNode: SRC_NODE, payload: encPayload });
    return echo.serialize();
  }
}

function clientReceiveProcess(data) {
  if (STEP === 1) return data.length;
  if (STEP === 2) { Packet.deserialize(data); return data.length; }
  if (STEP === 3) { decrypt(data, sharedKey); return data.length; }
  if (STEP === 4) { decrypt(data, sharedKey); return data.length; }
  if (STEP >= 5) {
    const pkt = Packet.deserialize(data);
    decrypt(pkt.payload, sharedKey);
    return data.length;
  }
}

// --- Main test class ---

class StepTest {
  constructor() {
    this.pc = null;
    this.dc = null;
    this.ws = null;
    this.batcher = null;

    this.uploadBytes = 0;
    this.uploadPkts = 0;
    this.downloadBytes = 0;
    this.downloadPkts = 0;
    this.startTime = 0;
  }

  async run() {
    console.log(`\n===== STEPWISE VPN SPEED TEST =====`);
    console.log(`Step ${STEP}: ${STEP_NAMES[STEP]}`);
    console.log(`ICE: ${STUN_ONLY ? 'STUN only' : 'STUN + TURN'}`);
    console.log(`Role: ${role}`);
    console.log(`Packet size: ${PACKET_SIZE} bytes`);
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
      ws.on('message', async (data) => {
        const msg = JSON.parse(data.toString());
        await this.handleSignal(msg);
      });
      this.setupPeer(true);
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
      this.setupPeer(false);
    });
    this.ws.on('message', async (data) => {
      const msg = JSON.parse(data.toString());
      await this.handleSignal(msg);
    });
    this.ws.on('error', (err) => console.error('WS error:', err.message));
  }

  setupPeer(isInitiator) {
    const iceServers = STUN_ONLY ? [...STUN_SERVERS] : [...STUN_SERVERS, ...TURN_SERVERS];
    this.pc = new RTCPeerConnection({ iceServers });

    this.pc.onicecandidate = (e) => {
      if (e.candidate) this.signal({ type: 'candidate', candidate: e.candidate });
    };

    this.pc.oniceconnectionstatechange = () => {
      const s = this.pc.iceConnectionState;
      console.log(`ICE: ${s}`);
      if (s === 'connected' || s === 'completed') this.logCandidatePair();
    };

    if (isInitiator) {
      if (STEP >= 3) {
        sharedKey = randomBytes(32);
        this.signal({ type: 'key', key: sharedKey.toString('hex') });
      }
      this.dc = this.pc.createDataChannel('step-test', { ordered: true });
      this.setupDC();
      this.pc.createOffer().then((o) => {
        this.pc.setLocalDescription(o);
        this.signal({ type: 'offer', sdp: o.sdp });
      });
    } else {
      this.pc.ondatachannel = (e) => {
        this.dc = e.channel;
        this.setupDC();
      };
    }
  }

  setupDC() {
    this.dc.onopen = () => {
      console.log('DataChannel open');
      if (role === 'client') this.runTest();
      else console.log('Waiting for data...');
    };

    if (role === 'server') {
      if (STEP === 6) {
        this.batcher = new PacketBatcher((_, data) => {
          try { this.dc.send(data); } catch {}
        });
      }

      this.dc.onmessage = (event) => {
        const raw = event.data instanceof ArrayBuffer ? Buffer.from(event.data) : event.data;

        if (STEP === 6) {
          const packets = unbatch(raw);
          for (const pkt of packets) {
            try {
              const echo = serverProcess(pkt);
              this.batcher.add('client', echo);
            } catch {}
          }
        } else {
          try {
            const echo = serverProcess(raw);
            this.dc.send(echo);
          } catch (err) {
            // skip
          }
        }
      };
    }

    if (role === 'client') {
      this.dc.onmessage = (event) => {
        const raw = event.data instanceof ArrayBuffer ? Buffer.from(event.data) : event.data;

        if (STEP === 6) {
          const packets = unbatch(raw);
          for (const pkt of packets) {
            try {
              clientReceiveProcess(pkt);
              this.downloadBytes += pkt.length;
              this.downloadPkts++;
            } catch {}
          }
        } else {
          try {
            clientReceiveProcess(raw);
            this.downloadBytes += raw.length;
            this.downloadPkts++;
          } catch {}
        }
      };
    }

    this.dc.onclose = () => console.log('DataChannel closed');
  }

  runTest() {
    console.log('\nTest running...\n');
    this.startTime = Date.now();
    this._done = false;
    const payload = randomBytes(PACKET_SIZE);

    let batcher = null;
    if (STEP === 6) {
      batcher = new PacketBatcher((_, data) => {
        try { this.dc.send(data); } catch {}
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
        console.log('Test complete, waiting for remaining echoes...');
        setTimeout(() => this.printResults(), 1000);
        return;
      }

      // Progress log every 2 seconds
      if (now - lastLog >= 2000) {
        const sec = elapsed / 1000;
        const upMbps = ((this.uploadBytes * 8) / sec / 1e6).toFixed(2);
        const dnMbps = ((this.downloadBytes * 8) / sec / 1e6).toFixed(2);
        console.log(`[${sec.toFixed(1)}s] up: ${upMbps} Mbit/s (${this.uploadPkts} pkts) | dn: ${dnMbps} Mbit/s (${this.downloadPkts} pkts) | buf: ${this.dc.bufferedAmount}`);
        lastLog = now;
      }

      // Send a small batch, then yield via setTimeout to let timers & I/O run
      let sent = 0;
      while (sent < 20) {
        if (this.dc.bufferedAmount > 256 * 1024) break;
        try {
          const processed = clientProcess(payload);
          if (STEP === 6) {
            batcher.add('server', processed);
          } else {
            this.dc.send(processed);
          }
          this.uploadBytes += processed.length;
          this.uploadPkts++;
          sent++;
        } catch (e) {
          console.error('Send error:', e.message);
          break;
        }
      }

      setTimeout(sendBatch, 1);
    };

    sendBatch();
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

    console.log(`\n======= STEP ${STEP}: ${STEP_NAMES[STEP]} =======`);
    console.log(`Duration: ${duration.toFixed(1)}s`);
    console.log(`--- Upload (client -> server) ---`);
    console.log(`  Total:   ${fmtB(this.uploadBytes)}`);
    console.log(`  Speed:   ${fmt(this.uploadBytes, duration)}`);
    console.log(`  Packets: ${this.uploadPkts} (${(this.uploadPkts / duration).toFixed(0)} pkt/s)`);
    console.log(`--- Download (server -> client, echo) ---`);
    console.log(`  Total:   ${fmtB(this.downloadBytes)}`);
    console.log(`  Speed:   ${fmt(this.downloadBytes, duration)}`);
    console.log(`  Packets: ${this.downloadPkts} (${(this.downloadPkts / duration).toFixed(0)} pkt/s)`);
    console.log(`${'='.repeat(45)}\n`);

    setTimeout(() => process.exit(0), 1000);
  }

  logCandidatePair() {
    try {
      const ice = this.pc.sctp?.dtlsTransport?.iceTransport;
      if (!ice) return;
      const l = ice.localCandidate;
      const r = ice.remoteCandidate;
      if (l && r) {
        const tag = (l.type === 'relay' || r.type === 'relay') ? 'RELAY (TURN)' : 'DIRECT P2P';
        console.log(`Path: ${l.type} ${l.host}:${l.port} <-> ${r.type} ${r.host}:${r.port} [${tag}]`);
      }
    } catch {}
  }

  async handleSignal(msg) {
    if (msg.type === 'key') {
      sharedKey = Buffer.from(msg.key, 'hex');
      console.log('Received shared key');
    } else if (msg.type === 'offer') {
      await this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp, 'offer'));
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      this.signal({ type: 'answer', sdp: answer.sdp });
    } else if (msg.type === 'answer') {
      await this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp, 'answer'));
    } else if (msg.type === 'candidate') {
      await this.pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
    }
  }

  signal(msg) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }
}

const test = new StepTest();
test.run().catch((err) => {
  console.error(err);
  process.exit(1);
});
