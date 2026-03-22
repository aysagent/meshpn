#!/usr/bin/env node
/**
 * WebRTC echo throughput test using node-datachannel (libdatachannel).
 * Direct comparison with stepwise-test.js --step 1 (werift).
 *
 * Usage:
 *   Server: node scripts/test-ndc-throughput.js server [--stun-only]
 *   Client: node scripts/test-ndc-throughput.js client <server-ip> [--stun-only]
 */

import { PeerConnection, setSctpSettings } from 'node-datachannel';
import { WebSocketServer, WebSocket } from 'ws';
import { randomBytes } from 'crypto';
import http from 'http';

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
const pktIdx = args.indexOf('--pkt-size');
const PACKET_SIZE = pktIdx !== -1 ? parseInt(args[pktIdx + 1], 10) : 1400;
const serverIp = role === 'client' ? args[1] : null;

if (!role || (role === 'client' && !serverIp)) {
  console.log('Usage:');
  console.log('  Server: node scripts/test-ndc-throughput.js server [--stun-only] [--pkt-size N]');
  console.log('  Client: node scripts/test-ndc-throughput.js client <ip> [--stun-only] [--pkt-size N]');
  process.exit(1);
}

const iceServers = STUN_ONLY
  ? ['stun:stun.l.google.com:19302']
  : ['stun:stun.l.google.com:19302', 'turn:meshuser:meshpass@62.84.120.30:3478'];

class NdcTest {
  constructor() {
    this.pc = null;
    this.dc = null;
    this.ws = null;

    this.uploadBytes = 0;
    this.uploadPkts = 0;
    this.downloadBytes = 0;
    this.downloadPkts = 0;
    this.startTime = 0;
    this._done = false;
  }

  async run() {
    console.log(`\n===== NDC (node-datachannel) ECHO TEST =====`);
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
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        this.handleSignal(msg);
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
    this.ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      this.handleSignal(msg);
    });
    this.ws.on('error', (err) => console.error('WS error:', err.message));
  }

  setupPeer(isInitiator) {
    this.pc = new PeerConnection(`peer-${role}`, { iceServers, maxMessageSize: 65536 });

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
      const dc = this.pc.createDataChannel('echo-test');
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
      else console.log('Waiting for data (echo mode)...');
    });

    dc.onClosed(() => {
      console.log('DataChannel closed');
    });

    dc.onError((err) => {
      console.error('DataChannel error:', err);
    });

    if (role === 'server') {
      dc.onMessage((data) => {
        try {
          if (typeof data === 'string') {
            dc.sendMessage(data);
          } else {
            dc.sendMessageBinary(data);
          }
        } catch {}
      });
    }

    if (role === 'client') {
      dc.onMessage((data) => {
        const len = typeof data === 'string' ? data.length : data.byteLength;
        this.downloadBytes += len;
        this.downloadPkts++;
      });
    }
  }

  runTest() {
    console.log('\nTest running...\n');
    this.startTime = Date.now();
    this._done = false;
    const payload = randomBytes(PACKET_SIZE);

    let lastLog = Date.now();

    const sendBatch = () => {
      if (this._done) return;

      const now = Date.now();
      const elapsed = now - this.startTime;

      if (elapsed >= TEST_DURATION) {
        this._done = true;
        console.log('Test complete, waiting for remaining echoes...');
        setTimeout(() => this.printResults(), 1000);
        return;
      }

      if (now - lastLog >= 2000) {
        const sec = elapsed / 1000;
        const upMbps = ((this.uploadBytes * 8) / sec / 1e6).toFixed(2);
        const dnMbps = ((this.downloadBytes * 8) / sec / 1e6).toFixed(2);
        console.log(`[${sec.toFixed(1)}s] up: ${upMbps} Mbit/s (${this.uploadPkts} pkts) | dn: ${dnMbps} Mbit/s (${this.downloadPkts} pkts)`);
        lastLog = now;
      }

      let sent = 0;
      while (sent < 100) {
        const buffered = typeof this.dc.bufferedAmount === 'function' ? this.dc.bufferedAmount() : 0;
        if (buffered > 1024 * 1024) break;
        try {
          this.dc.sendMessageBinary(payload);
          this.uploadBytes += payload.length;
          this.uploadPkts++;
          sent++;
        } catch {
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

    console.log(`\n======= node-datachannel ECHO TEST =======`);
    console.log(`Duration: ${duration.toFixed(1)}s`);
    console.log(`Packet size: ${PACKET_SIZE} bytes`);
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
    if (msg.type === 'offer') {
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

const test = new NdcTest();
test.run().catch((err) => {
  console.error(err);
  process.exit(1);
});
