import { EventEmitter } from 'events';

class PerformanceMetrics extends EventEmitter {
  constructor(config = {}) {
    super();
    this.enabled = config.enabled !== false;
    /** Печать блока PERFORMANCE METRICS по таймеру (по умолчанию выключена). */
    this.periodicReport = config.periodicReport === true;
    this.reportInterval = config.reportInterval || 5000;
    this.reportTimer = null;
    
    this.counters = {
      // Client side
      tunPacketsRead: 0,
      tunBytesRead: 0,
      onionEncrypted: 0,
      onionEncryptedBytes: 0,
      onionEncryptedOutputBytes: 0,
      packetsSerialized: 0,
      packetsSerializedBytes: 0,
      webrtcSent: 0,
      webrtcSentBytes: 0,
      webrtcSendFailed: 0,
      
      // Exit side
      webrtcReceived: 0,
      webrtcReceivedBytes: 0,
      packetsDeserialized: 0,
      onionDecrypted: 0,
      onionDecryptedBytes: 0,
      natProcessed: 0,
      natProcessedBytes: 0,
      tcpConnectionsCreated: 0,
      tcpDataSent: 0,
      tcpDataReceived: 0,
      
      // Response path
      responsesSent: 0,
      responseBytes: 0,
      
      // Errors
      errors: 0
    };
    
    this.timings = {
      onionEncryptTotal: 0,
      onionEncryptCount: 0,
      onionDecryptTotal: 0,
      onionDecryptCount: 0,
      serializeTotal: 0,
      serializeCount: 0,
      deserializeTotal: 0,
      deserializeCount: 0,
      natProcessTotal: 0,
      natProcessCount: 0
    };
    
    this.sizeRatios = {
      onionExpansion: [],
      serializeExpansion: []
    };
    
    this.lastReport = Date.now();
    this.lastCounters = { ...this.counters };
  }

  /**
   * Применить настройки из конфига (до metrics.start()).
   * @param {object} cfg
   * @param {boolean} [cfg.enabled]
   * @param {boolean} [cfg.periodicReport] — true = раз в reportInterval печатать отчёт
   * @param {number} [cfg.reportInterval]
   */
  configure(cfg = {}) {
    if ('enabled' in cfg) {
      this.enabled = cfg.enabled !== false;
    }
    if ('periodicReport' in cfg) {
      this.periodicReport = cfg.periodicReport === true;
    }
    if (cfg.reportInterval != null && cfg.reportInterval > 0) {
      this.reportInterval = cfg.reportInterval;
    }
    if (this.reportTimer) {
      clearInterval(this.reportTimer);
      this.reportTimer = null;
    }
  }
  
  start() {
    if (!this.enabled) return;

    if (this.periodicReport) {
      this.reportTimer = setInterval(() => {
        this.report();
      }, this.reportInterval);
      console.log(`[METRICS] Periodic report every ${this.reportInterval}ms`);
    } else {
      console.log('[METRICS] Periodic report disabled (set metrics.periodicReport: true to enable)');
    }
  }
  
  stop() {
    if (this.reportTimer) {
      clearInterval(this.reportTimer);
      this.reportTimer = null;
    }
  }
  
  // Measurement methods
  
  recordTunRead(bytes) {
    if (!this.enabled) return;
    this.counters.tunPacketsRead++;
    this.counters.tunBytesRead += bytes;
  }
  
  recordOnionEncrypt(inputBytes, outputBytes, timeMs) {
    if (!this.enabled) return;
    this.counters.onionEncrypted++;
    this.counters.onionEncryptedBytes += inputBytes;
    this.counters.onionEncryptedOutputBytes += outputBytes;
    this.timings.onionEncryptTotal += timeMs;
    this.timings.onionEncryptCount++;
    
    if (inputBytes > 0) {
      this.sizeRatios.onionExpansion.push(outputBytes / inputBytes);
      if (this.sizeRatios.onionExpansion.length > 100) {
        this.sizeRatios.onionExpansion.shift();
      }
    }
  }
  
  recordSerialize(payloadBytes, outputBytes, timeMs) {
    if (!this.enabled) return;
    this.counters.packetsSerialized++;
    this.counters.packetsSerializedBytes += outputBytes;
    this.timings.serializeTotal += timeMs;
    this.timings.serializeCount++;
    
    if (payloadBytes > 0) {
      this.sizeRatios.serializeExpansion.push(outputBytes / payloadBytes);
      if (this.sizeRatios.serializeExpansion.length > 100) {
        this.sizeRatios.serializeExpansion.shift();
      }
    }
  }
  
  recordWebRTCSend(bytes, success) {
    if (!this.enabled) return;
    if (success) {
      this.counters.webrtcSent++;
      this.counters.webrtcSentBytes += bytes;
    } else {
      this.counters.webrtcSendFailed++;
    }
  }
  
  recordWebRTCReceive(bytes) {
    if (!this.enabled) return;
    this.counters.webrtcReceived++;
    this.counters.webrtcReceivedBytes += bytes;
  }
  
  recordDeserialize(bytes, timeMs) {
    if (!this.enabled) return;
    this.counters.packetsDeserialized++;
    this.timings.deserializeTotal += timeMs;
    this.timings.deserializeCount++;
  }
  
  recordOnionDecrypt(inputBytes, outputBytes, timeMs) {
    if (!this.enabled) return;
    this.counters.onionDecrypted++;
    this.counters.onionDecryptedBytes += outputBytes;
    this.timings.onionDecryptTotal += timeMs;
    this.timings.onionDecryptCount++;
  }
  
  recordNATProcess(bytes, timeMs) {
    if (!this.enabled) return;
    this.counters.natProcessed++;
    this.counters.natProcessedBytes += bytes;
    this.timings.natProcessTotal += timeMs;
    this.timings.natProcessCount++;
  }
  
  recordTCPConnection() {
    if (!this.enabled) return;
    this.counters.tcpConnectionsCreated++;
  }
  
  recordTCPData(sent, received) {
    if (!this.enabled) return;
    this.counters.tcpDataSent += sent;
    this.counters.tcpDataReceived += received;
  }
  
  recordResponse(bytes) {
    if (!this.enabled) return;
    this.counters.responsesSent++;
    this.counters.responseBytes += bytes;
  }
  
  recordError() {
    if (!this.enabled) return;
    this.counters.errors++;
  }
  
  // Reporting
  
  report() {
    const now = Date.now();
    const elapsed = (now - this.lastReport) / 1000;
    
    const formatBytes = (bytes) => {
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      return `${bytes} B`;
    };
    
    const formatRate = (bytes, seconds) => {
      const bps = bytes * 8 / seconds;
      if (bps >= 1000000) return `${(bps / 1000000).toFixed(2)} Mbit/s`;
      if (bps >= 1000) return `${(bps / 1000).toFixed(2)} Kbit/s`;
      return `${bps.toFixed(0)} bit/s`;
    };
    
    const avgTime = (total, count) => count > 0 ? (total / count).toFixed(3) : '0';
    const avgRatio = (arr) => arr.length > 0 ? (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(2) : 'N/A';
    
    // Calculate deltas
    const deltaTunBytes = this.counters.tunBytesRead - this.lastCounters.tunBytesRead;
    const deltaWebRTCSentBytes = this.counters.webrtcSentBytes - this.lastCounters.webrtcSentBytes;
    const deltaWebRTCRecvBytes = this.counters.webrtcReceivedBytes - this.lastCounters.webrtcReceivedBytes;
    const deltaResponseBytes = this.counters.responseBytes - this.lastCounters.responseBytes;
    
    const deltaTunPackets = this.counters.tunPacketsRead - this.lastCounters.tunPacketsRead;
    const deltaWebRTCSent = this.counters.webrtcSent - this.lastCounters.webrtcSent;
    const deltaWebRTCRecv = this.counters.webrtcReceived - this.lastCounters.webrtcReceived;
    const deltaFailed = this.counters.webrtcSendFailed - this.lastCounters.webrtcSendFailed;
    
    console.log('\n========== PERFORMANCE METRICS ==========');
    console.log(`Elapsed: ${elapsed.toFixed(1)}s`);
    console.log('');
    console.log('--- THROUGHPUT ---');
    console.log(`TUN Read:      ${formatRate(deltaTunBytes, elapsed)} (${deltaTunPackets} pkts)`);
    console.log(`WebRTC Send:   ${formatRate(deltaWebRTCSentBytes, elapsed)} (${deltaWebRTCSent} pkts, ${deltaFailed} failed)`);
    console.log(`WebRTC Recv:   ${formatRate(deltaWebRTCRecvBytes, elapsed)} (${deltaWebRTCRecv} pkts)`);
    console.log(`Responses:     ${formatRate(deltaResponseBytes, elapsed)}`);
    console.log('');
    console.log('--- SIZE EXPANSION ---');
    console.log(`Onion:         ${avgRatio(this.sizeRatios.onionExpansion)}x`);
    console.log(`Serialize:     ${avgRatio(this.sizeRatios.serializeExpansion)}x`);
    console.log('');
    console.log('--- TIMING (avg ms) ---');
    console.log(`Onion Encrypt: ${avgTime(this.timings.onionEncryptTotal, this.timings.onionEncryptCount)} ms`);
    console.log(`Onion Decrypt: ${avgTime(this.timings.onionDecryptTotal, this.timings.onionDecryptCount)} ms`);
    console.log(`Serialize:     ${avgTime(this.timings.serializeTotal, this.timings.serializeCount)} ms`);
    console.log(`Deserialize:   ${avgTime(this.timings.deserializeTotal, this.timings.deserializeCount)} ms`);
    console.log(`NAT Process:   ${avgTime(this.timings.natProcessTotal, this.timings.natProcessCount)} ms`);
    console.log('');
    console.log('--- TOTALS ---');
    console.log(`TCP Connections: ${this.counters.tcpConnectionsCreated}`);
    console.log(`TCP Data: sent ${formatBytes(this.counters.tcpDataSent)}, recv ${formatBytes(this.counters.tcpDataReceived)}`);
    console.log(`Errors: ${this.counters.errors}`);
    console.log('==========================================\n');
    
    // Save for next delta
    this.lastReport = now;
    this.lastCounters = { ...this.counters };
    
    // Reset timing samples
    this.timings.onionEncryptTotal = 0;
    this.timings.onionEncryptCount = 0;
    this.timings.onionDecryptTotal = 0;
    this.timings.onionDecryptCount = 0;
    this.timings.serializeTotal = 0;
    this.timings.serializeCount = 0;
    this.timings.deserializeTotal = 0;
    this.timings.deserializeCount = 0;
    this.timings.natProcessTotal = 0;
    this.timings.natProcessCount = 0;
  }
  
  getStats() {
    return {
      counters: { ...this.counters },
      timings: { ...this.timings },
      sizeRatios: {
        onionExpansion: this.sizeRatios.onionExpansion.length > 0 
          ? this.sizeRatios.onionExpansion.reduce((a, b) => a + b, 0) / this.sizeRatios.onionExpansion.length 
          : null,
        serializeExpansion: this.sizeRatios.serializeExpansion.length > 0
          ? this.sizeRatios.serializeExpansion.reduce((a, b) => a + b, 0) / this.sizeRatios.serializeExpansion.length
          : null
      }
    };
  }
}

// Global singleton (periodicReport по умолчанию false)
const metrics = new PerformanceMetrics({ enabled: true, periodicReport: false });

export { PerformanceMetrics, metrics };
