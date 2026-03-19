#!/usr/bin/env node
/**
 * WebRTC Raw Throughput Test
 * 
 * This script tests the raw WebRTC DataChannel throughput without any
 * VPN overhead (no onion routing, no serialization, no encryption).
 * 
 * Run on two machines:
 * 1. Server: node scripts/test-webrtc-throughput.js server
 * 2. Client: node scripts/test-webrtc-throughput.js client <server-ip>
 */

import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate } from 'werift';
import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';

const TURN_SERVERS = [
  {
    urls: 'turn:62.84.120.30:3478',
    username: 'meshuser',
    credential: 'meshpass'
  }
];

const STUN_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' }
];

const TEST_DURATION = 10000; // 10 seconds
const CHUNK_SIZE = 16384; // 16KB chunks

class ThroughputTest {
  constructor(role, signalServer) {
    this.role = role;
    this.signalServer = signalServer;
    this.pc = null;
    this.dc = null;
    this.ws = null;
    
    this.stats = {
      bytesSent: 0,
      bytesReceived: 0,
      messagesSent: 0,
      messagesReceived: 0,
      startTime: 0,
      endTime: 0
    };
  }
  
  async start() {
    console.log(`Starting ${this.role} mode...`);
    
    if (this.role === 'server') {
      await this.startSignalServer();
    } else {
      await this.connectToSignalServer();
    }
  }
  
  async startSignalServer() {
    // Simple HTTP server for signaling
    const server = http.createServer();
    const wss = new WebSocketServer({ server });
    
    wss.on('connection', (ws) => {
      console.log('Client connected to signal server');
      this.ws = ws;
      
      ws.on('message', async (data) => {
        const msg = JSON.parse(data.toString());
        await this.handleSignal(msg);
      });
      
      // Create offer
      this.createPeerConnection(true);
    });
    
    server.listen(9999, () => {
      console.log('Signal server listening on port 9999');
      console.log('Run client with: node scripts/test-webrtc-throughput.js client <this-ip>');
    });
  }
  
  async connectToSignalServer() {
    const url = `ws://${this.signalServer}:9999`;
    console.log(`Connecting to signal server at ${url}...`);
    
    this.ws = new WebSocket(url);
    
    this.ws.on('open', () => {
      console.log('Connected to signal server');
      this.createPeerConnection(false);
    });
    
    this.ws.on('message', async (data) => {
      const msg = JSON.parse(data.toString());
      await this.handleSignal(msg);
    });
    
    this.ws.on('error', (err) => {
      console.error('WebSocket error:', err.message);
    });
  }
  
  createPeerConnection(isInitiator) {
    console.log(`Creating peer connection (initiator: ${isInitiator})...`);
    
    this.pc = new RTCPeerConnection({
      iceServers: [...STUN_SERVERS, ...TURN_SERVERS]
    });
    
    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendSignal({ type: 'candidate', candidate: event.candidate });
      }
    };
    
    this.pc.oniceconnectionstatechange = () => {
      console.log('ICE state:', this.pc.iceConnectionState);
    };
    
    if (isInitiator) {
      // Server creates data channel
      this.dc = this.pc.createDataChannel('throughput-test', {
        ordered: false,
        maxRetransmits: 0
      });
      this.setupDataChannel();
      
      this.pc.createOffer().then(offer => {
        this.pc.setLocalDescription(offer);
        this.sendSignal({ type: 'offer', sdp: offer.sdp });
      });
    } else {
      // Client waits for data channel
      this.pc.ondatachannel = (event) => {
        this.dc = event.channel;
        this.setupDataChannel();
      };
    }
  }
  
  setupDataChannel() {
    console.log('Data channel created');
    
    this.dc.onopen = () => {
      console.log('Data channel opened!');
      
      // Both sides start sending
      this.startTest();
    };
    
    this.dc.onclose = () => {
      console.log('Data channel closed');
      this.printResults();
    };
    
    this.dc.onmessage = (event) => {
      const data = event.data;
      this.stats.bytesReceived += data.byteLength || data.length;
      this.stats.messagesReceived++;
    };
    
    this.dc.onerror = (err) => {
      console.error('Data channel error:', err);
    };
  }
  
  startTest() {
    console.log(`\nStarting throughput test (${TEST_DURATION/1000}s)...`);
    console.log(`Chunk size: ${CHUNK_SIZE} bytes`);
    
    this.stats.startTime = Date.now();
    const testData = Buffer.alloc(CHUNK_SIZE, 0x42);
    
    const sendLoop = () => {
      if (Date.now() - this.stats.startTime >= TEST_DURATION) {
        this.stats.endTime = Date.now();
        console.log('\nTest complete!');
        this.printResults();
        
        // Close after a brief delay to let remaining data arrive
        setTimeout(() => {
          this.dc.close();
          this.pc.close();
          process.exit(0);
        }, 2000);
        return;
      }
      
      // Send as fast as possible while buffer allows
      while (this.dc.bufferedAmount < 1024 * 1024) { // 1MB buffer limit
        try {
          this.dc.send(testData);
          this.stats.bytesSent += testData.length;
          this.stats.messagesSent++;
        } catch (err) {
          break;
        }
      }
      
      // Check again soon
      setImmediate(sendLoop);
    };
    
    sendLoop();
  }
  
  printResults() {
    const duration = (this.stats.endTime - this.stats.startTime) / 1000;
    
    const formatRate = (bytes, seconds) => {
      const bps = bytes * 8 / seconds;
      if (bps >= 1000000) return `${(bps / 1000000).toFixed(2)} Mbit/s`;
      if (bps >= 1000) return `${(bps / 1000).toFixed(2)} Kbit/s`;
      return `${bps.toFixed(0)} bit/s`;
    };
    
    const formatBytes = (bytes) => {
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      return `${bytes} B`;
    };
    
    console.log('\n========== WEBRTC RAW THROUGHPUT RESULTS ==========');
    console.log(`Duration: ${duration.toFixed(2)}s`);
    console.log('');
    console.log('--- UPLOAD (sent) ---');
    console.log(`Total:    ${formatBytes(this.stats.bytesSent)}`);
    console.log(`Rate:     ${formatRate(this.stats.bytesSent, duration)}`);
    console.log(`Messages: ${this.stats.messagesSent}`);
    console.log('');
    console.log('--- DOWNLOAD (received) ---');
    console.log(`Total:    ${formatBytes(this.stats.bytesReceived)}`);
    console.log(`Rate:     ${formatRate(this.stats.bytesReceived, duration)}`);
    console.log(`Messages: ${this.stats.messagesReceived}`);
    console.log('====================================================\n');
  }
  
  async handleSignal(msg) {
    if (msg.type === 'offer') {
      console.log('Received offer');
      await this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp, 'offer'));
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      this.sendSignal({ type: 'answer', sdp: answer.sdp });
    } else if (msg.type === 'answer') {
      console.log('Received answer');
      await this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp, 'answer'));
    } else if (msg.type === 'candidate') {
      console.log('Received ICE candidate');
      await this.pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
    }
  }
  
  sendSignal(msg) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }
}

// Main
const args = process.argv.slice(2);
const role = args[0] || 'server';
const signalServer = args[1] || 'localhost';

if (role !== 'server' && role !== 'client') {
  console.log('Usage:');
  console.log('  Server: node scripts/test-webrtc-throughput.js server');
  console.log('  Client: node scripts/test-webrtc-throughput.js client <server-ip>');
  process.exit(1);
}

const test = new ThroughputTest(role, signalServer);
test.start().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
