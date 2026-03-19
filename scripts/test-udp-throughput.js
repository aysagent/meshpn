#!/usr/bin/env node
/**
 * Raw UDP Throughput Test
 * 
 * Tests raw UDP throughput without WebRTC overhead.
 * This helps identify if the bottleneck is in werift or in the network.
 * 
 * Run on two machines:
 * 1. Server: node scripts/test-udp-throughput.js server
 * 2. Client: node scripts/test-udp-throughput.js client <server-ip>
 */

import dgram from 'dgram';

const PORT = 9998;
const TEST_DURATION = 10000; // 10 seconds
const CHUNK_SIZE = 1400; // MTU-safe size

class UDPThroughputTest {
  constructor(role, serverIp) {
    this.role = role;
    this.serverIp = serverIp;
    this.socket = dgram.createSocket('udp4');
    
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
    this.socket.on('message', (msg, rinfo) => {
      this.stats.bytesReceived += msg.length;
      this.stats.messagesReceived++;
      
      // Echo back to test bidirectional
      this.socket.send(msg, rinfo.port, rinfo.address);
      this.stats.bytesSent += msg.length;
      this.stats.messagesSent++;
    });
    
    this.socket.bind(PORT, () => {
      console.log(`UDP server listening on port ${PORT}`);
      console.log('Waiting for client...');
      console.log('Run client with: node scripts/test-udp-throughput.js client <this-ip>');
      
      this.stats.startTime = Date.now();
      
      // Print stats every second
      const statsInterval = setInterval(() => {
        const elapsed = (Date.now() - this.stats.startTime) / 1000;
        const rxRate = (this.stats.bytesReceived * 8 / elapsed / 1000000).toFixed(2);
        const txRate = (this.stats.bytesSent * 8 / elapsed / 1000000).toFixed(2);
        process.stdout.write(`\rRX: ${rxRate} Mbit/s | TX: ${txRate} Mbit/s | Packets: ${this.stats.messagesReceived}`);
      }, 1000);
      
      // Stop after test duration from first packet
      let testStarted = false;
      this.socket.on('message', () => {
        if (!testStarted) {
          testStarted = true;
          console.log('\nTest started!');
          setTimeout(() => {
            clearInterval(statsInterval);
            this.stats.endTime = Date.now();
            this.printResults();
            process.exit(0);
          }, TEST_DURATION);
        }
      });
    });
  }
  
  async startClient() {
    console.log(`Connecting to ${this.serverIp}:${PORT}...`);
    
    this.socket.on('message', (msg) => {
      this.stats.bytesReceived += msg.length;
      this.stats.messagesReceived++;
    });
    
    this.socket.bind(() => {
      console.log('Starting throughput test...');
      this.stats.startTime = Date.now();
      
      const testData = Buffer.alloc(CHUNK_SIZE, 0x42);
      
      const sendLoop = () => {
        if (Date.now() - this.stats.startTime >= TEST_DURATION) {
          this.stats.endTime = Date.now();
          console.log('\nTest complete!');
          
          // Wait a bit for remaining packets
          setTimeout(() => {
            this.printResults();
            process.exit(0);
          }, 1000);
          return;
        }
        
        // Send multiple packets per tick
        for (let i = 0; i < 100; i++) {
          this.socket.send(testData, PORT, this.serverIp, (err) => {
            if (!err) {
              this.stats.bytesSent += testData.length;
              this.stats.messagesSent++;
            }
          });
        }
        
        setImmediate(sendLoop);
      };
      
      sendLoop();
    });
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
    
    console.log('\n========== RAW UDP THROUGHPUT RESULTS ==========');
    console.log(`Duration: ${duration.toFixed(2)}s`);
    console.log(`Role: ${this.role}`);
    console.log('');
    console.log('--- SENT ---');
    console.log(`Total:    ${formatBytes(this.stats.bytesSent)}`);
    console.log(`Rate:     ${formatRate(this.stats.bytesSent, duration)}`);
    console.log(`Messages: ${this.stats.messagesSent}`);
    console.log('');
    console.log('--- RECEIVED ---');
    console.log(`Total:    ${formatBytes(this.stats.bytesReceived)}`);
    console.log(`Rate:     ${formatRate(this.stats.bytesReceived, duration)}`);
    console.log(`Messages: ${this.stats.messagesReceived}`);
    console.log('================================================\n');
  }
}

// Main
const args = process.argv.slice(2);
const role = args[0] || 'server';
const serverIp = args[1] || 'localhost';

if (role !== 'server' && role !== 'client') {
  console.log('Usage:');
  console.log('  Server: node scripts/test-udp-throughput.js server');
  console.log('  Client: node scripts/test-udp-throughput.js client <server-ip>');
  process.exit(1);
}

const test = new UDPThroughputTest(role, serverIp);
test.start().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
