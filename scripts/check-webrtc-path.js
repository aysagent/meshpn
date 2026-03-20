#!/usr/bin/env node
/**
 * WebRTC Path Diagnostic Script
 *
 * Connects to a WebRTC server and reports which path is used (direct P2P vs TURN relay).
 * Run server on exit node, client on your machine.
 *
 * Usage:
 *   Server: node scripts/check-webrtc-path.js server [--stun-only]
 *   Client: node scripts/check-webrtc-path.js client <server-ip> [--stun-only]
 *
 * Options:
 *   --stun-only   Use only STUN (no TURN) - tests if direct P2P is possible
 */

import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate } from 'werift';
import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';

const TURN_SERVERS = [
  { urls: 'turn:62.84.120.30:3478', username: 'meshuser', credential: 'meshpass' }
];

const STUN_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

const SIGNAL_PORT = 9998; // Different from throughput test to avoid conflict
const TEST_DURATION = 3000; // 3 seconds

const STUN_ONLY = process.argv.includes('--stun-only');

class WebRTCPathCheck {
  constructor(role, signalServer) {
    this.role = role;
    this.signalServer = signalServer;
    this.pc = null;
    this.dc = null;
    this.ws = null;
    this.candidatePairLogged = false;
  }

  async start() {
    console.log(`\n=== WebRTC Path Diagnostic ===`);
    console.log(`Mode: ${STUN_ONLY ? 'STUN only (no TURN)' : 'STUN + TURN'}`);
    console.log(`Role: ${this.role}\n`);

    if (this.role === 'server') {
      await this.startSignalServer();
    } else {
      await this.connectToSignalServer();
    }
  }

  async startSignalServer() {
    const server = http.createServer();
    const wss = new WebSocketServer({ server });

    wss.on('connection', (ws) => {
      console.log('Client connected');
      this.ws = ws;
      ws.on('message', async (data) => {
        const msg = JSON.parse(data.toString());
        await this.handleSignal(msg);
      });
      this.createPeerConnection(true);
    });

    server.listen(SIGNAL_PORT, () => {
      console.log(`Signal server on port ${SIGNAL_PORT}`);
      console.log(`Run: node scripts/check-webrtc-path.js client <this-ip> ${STUN_ONLY ? '--stun-only' : ''}\n`);
    });
  }

  async connectToSignalServer() {
    const url = `ws://${this.signalServer}:${SIGNAL_PORT}`;
    console.log(`Connecting to ${url}...`);

    this.ws = new WebSocket(url);
    this.ws.on('open', () => {
      console.log('Connected');
      this.createPeerConnection(false);
    });
    this.ws.on('message', async (data) => {
      const msg = JSON.parse(data.toString());
      await this.handleSignal(msg);
    });
    this.ws.on('error', (err) => console.error('WebSocket error:', err.message));
  }

  createPeerConnection(isInitiator) {
    const iceServers = STUN_ONLY ? [...STUN_SERVERS] : [...STUN_SERVERS, ...TURN_SERVERS];
    this.pc = new RTCPeerConnection({ iceServers });

    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendSignal({ type: 'candidate', candidate: event.candidate });
      }
    };

    this.pc.oniceconnectionstatechange = () => {
      const state = this.pc.iceConnectionState;
      console.log(`ICE state: ${state}`);

      if ((state === 'connected' || state === 'completed') && !this.candidatePairLogged) {
        this.candidatePairLogged = true;
        this.printPathInfo();
        this.runQuickTest();
      }
    };

    if (isInitiator) {
      this.dc = this.pc.createDataChannel('check', { ordered: true });
      this.setupDataChannel();
      this.pc.createOffer().then((offer) => {
        this.pc.setLocalDescription(offer);
        this.sendSignal({ type: 'offer', sdp: offer.sdp });
      });
    } else {
      this.pc.ondatachannel = (event) => {
        this.dc = event.channel;
        this.setupDataChannel();
      };
    }
  }

  setupDataChannel() {
    this.dc.onopen = () => console.log('Data channel open');
    this.dc.onmessage = () => {};
    this.dc.onclose = () => {
      console.log('\nDone.');
      process.exit(0);
    };
  }

  printPathInfo() {
    console.log('\n' + '='.repeat(50));
    console.log('SELECTED CONNECTION PATH');
    console.log('='.repeat(50));

    try {
      const ice = this.pc.sctp?.dtlsTransport?.iceTransport;
      if (ice) {
        const local = ice.localCandidate;
        const remote = ice.remoteCandidate;

        if (local && remote) {
          console.log(`\nLocal:  ${local.type} ${local.host}:${local.port}`);
          console.log(`Remote: ${remote.type} ${remote.host}:${remote.port}`);

          if (local.type === 'relay' || remote.type === 'relay') {
            console.log('\n*** CONNECTION VIA TURN RELAY ***');
            console.log('   All traffic goes through TURN server.');
            console.log('   This typically limits throughput (1-2 Mbit/s).');
            console.log('   Try --stun-only to test direct P2P.');
          } else {
            console.log('\n*** DIRECT P2P CONNECTION ***');
            console.log('   No relay - better throughput expected.');
          }
        } else {
          console.log('(Could not get candidate details)');
        }
      } else {
        console.log('(ICE transport not available)');
      }
    } catch (err) {
      console.log('Error:', err.message);
    }
    console.log('='.repeat(50) + '\n');
  }

  runQuickTest() {
    if (this.role !== 'client') return;

    console.log('Running 3-second throughput test...');
    const testData = Buffer.alloc(16384, 0x42);
    let sent = 0;
    const start = Date.now();

    const send = () => {
      if (Date.now() - start >= TEST_DURATION) {
        const duration = (Date.now() - start) / 1000;
        const mbit = (sent * 8) / duration / 1e6;
        console.log(`Upload: ${(sent / 1024 / 1024).toFixed(2)} MB in ${duration.toFixed(1)}s = ${mbit.toFixed(1)} Mbit/s`);
        this.dc.close();
        return;
      }
      try {
        while (this.dc.bufferedAmount < 512 * 1024) {
          this.dc.send(testData);
          sent += testData.length;
        }
      } catch {}
      setImmediate(send);
    };
    send();
  }

  async handleSignal(msg) {
    if (msg.type === 'offer') {
      await this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp, 'offer'));
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      this.sendSignal({ type: 'answer', sdp: answer.sdp });
    } else if (msg.type === 'answer') {
      await this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp, 'answer'));
    } else if (msg.type === 'candidate') {
      await this.pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
    }
  }

  sendSignal(msg) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }
}

const args = process.argv.slice(2);
const role = args[0] || 'server';
const signalServer = args[1] || 'localhost';

if (role !== 'server' && role !== 'client') {
  console.log('Usage:');
  console.log('  Server: node scripts/check-webrtc-path.js server [--stun-only]');
  console.log('  Client: node scripts/check-webrtc-path.js client <server-ip> [--stun-only]');
  process.exit(1);
}

const check = new WebRTCPathCheck(role, signalServer);
check.start().catch((err) => {
  console.error(err);
  process.exit(1);
});
