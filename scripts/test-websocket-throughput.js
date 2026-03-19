#!/usr/bin/env node
/**
 * Raw WebSocket (TCP) Throughput Test
 * 
 * Tests raw WebSocket throughput to compare with WebRTC.
 * WebSocket uses TCP, so this shows the baseline TCP performance.
 * 
 * Run on two machines:
 * 1. Server: node scripts/test-websocket-throughput.js server
 * 2. Client: node scripts/test-websocket-throughput.js client <server-ip>
 */

import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';

const PORT = 9997;
const TEST_DURATION = 10000; // 10 seconds
const CHUNK_SIZE = 16384; // 16KB chunks

class WebSocketThroughputTest {
  constructor(role, serverIp) {
    this.role = role;
    this.serverIp = serverIp;
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
    console.log(`Chunk size: ${CHUNK_SIZE} bytes`);
    
    if (this.role === 'server') {
      await this.startServer();
    } else {
      await this.startClient();
    }
  }
  
  async startServer() {
    const server = http.createServer();
    const wss = new WebSocketServer({ server });
    
    wss.on('connection', (ws) => {
      console.log('Client connected!');
      this.ws = ws;
      
      ws.on('message', (data) => {
        this.stats.bytesReceived += data.length;
        this.stats.messagesReceived++;
      });
      
      ws.on('close', () => {
        console.log('Client disconnected');
        this.printResults();
      });
      
      // Start bidirectional test
      this.startTest();
    });
    
    server.listen(PORT, () => {
      console.log(`WebSocket server listening on port ${PORT}`);
      console.log(`Run client with: node scripts/test-websocket-throughput.js client <this-ip>`);
    });
  }
  
  async startClient() {
    const url = `ws://${this.serverIp}:${PORT}`;
    console.log(`Connecting to ${url}...`);
    
    this.ws = new WebSocket(url);
    
    this.ws.on('open', () => {
      console.log('Connected!');
      this.startTest();
    });
    
    this.ws.on('message', (data) => {
      this.stats.bytesReceived += data.length;
      this.stats.messagesReceived++;
    });
    
    this.ws.on('close', () => {
      console.log('Connection closed');
      this.printResults();
      process.exit(0);
    });
    
    this.ws.on('error', (err) => {
      console.error('WebSocket error:', err.message);
    });
  }
  
  startTest() {
    console.log(`\nStarting throughput test (${TEST_DURATION/1000}s)...`);
    
    this.stats.startTime = Date.now();
    const testData = Buffer.alloc(CHUNK_SIZE, 0x42);
    
    const sendLoop = () => {
      if (Date.now() - this.stats.startTime >= TEST_DURATION) {
        this.stats.endTime = Date.now();
        console.log('\nTest complete!');
        this.printResults();
        
        setTimeout(() => {
          this.ws.close();
          process.exit(0);
        }, 2000);
        return;
      }
      
      // Send while buffer allows (16MB limit for WebSocket)
      while (this.ws.bufferedAmount < 16 * 1024 * 1024) {
        try {
          this.ws.send(testData);
          this.stats.bytesSent += testData.length;
          this.stats.messagesSent++;
        } catch (err) {
          break;
        }
      }
      
      setImmediate(sendLoop);
    };
    
    sendLoop();
  }
  
  printResults() {
    const duration = (this.stats.endTime - this.stats.startTime) / 1000;
    if (duration <= 0) return;
    
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
    
    console.log('\n========== WEBSOCKET (TCP) THROUGHPUT RESULTS ==========');
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
    console.log('=========================================================\n');
  }
}

// Main
const args = process.argv.slice(2);
const role = args[0] || 'server';
const serverIp = args[1] || 'localhost';

if (role !== 'server' && role !== 'client') {
  console.log('Usage:');
  console.log('  Server: node scripts/test-websocket-throughput.js server');
  console.log('  Client: node scripts/test-websocket-throughput.js client <server-ip>');
  process.exit(1);
}

const test = new WebSocketThroughputTest(role, serverIp);
test.start().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
