import { EventEmitter } from 'events';
import dgram from 'dgram';
import net from 'net';
import dns from 'dns';
import { promisify } from 'util';

const dnsResolve = promisify(dns.resolve4);

export class NATTable extends EventEmitter {
  constructor(config = {}) {
    super();
    this.entries = new Map();
    this.reverseMap = new Map();
    this.portStart = config.portStart || 40000;
    this.portEnd = config.portEnd || 60000;
    this.nextPort = this.portStart;
    this.timeout = config.timeout || 300000;
    this.cleanupInterval = null;
  }

  start() {
    this.cleanupInterval = setInterval(() => {
      this._cleanup();
    }, 60000);
  }

  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.entries.clear();
    this.reverseMap.clear();
  }

  createMapping(srcNodeId, srcIp, srcPort, dstIp, dstPort, protocol) {
    const key = `${srcNodeId}:${srcIp}:${srcPort}:${dstIp}:${dstPort}:${protocol}`;
    
    let entry = this.entries.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
      return entry;
    }
    
    const natPort = this._allocatePort();
    
    entry = {
      key,
      srcNodeId,
      srcIp,
      srcPort,
      dstIp,
      dstPort,
      protocol,
      natPort,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      bytesIn: 0,
      bytesOut: 0
    };
    
    this.entries.set(key, entry);
    this.reverseMap.set(`${dstIp}:${dstPort}:${natPort}:${protocol}`, entry);
    
    this.emit('mapping-created', entry);
    
    return entry;
  }

  findMapping(key) {
    const entry = this.entries.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
    }
    return entry;
  }

  findReverseMapping(dstIp, dstPort, natPort, protocol) {
    const key = `${dstIp}:${dstPort}:${natPort}:${protocol}`;
    const entry = this.reverseMap.get(key);
    if (entry) {
      entry.lastUsed = Date.now();
    }
    return entry;
  }

  removeMapping(key) {
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      this.reverseMap.delete(`${entry.dstIp}:${entry.dstPort}:${entry.natPort}:${entry.protocol}`);
      this.emit('mapping-removed', entry);
    }
  }

  _allocatePort() {
    const port = this.nextPort;
    this.nextPort++;
    if (this.nextPort > this.portEnd) {
      this.nextPort = this.portStart;
    }
    return port;
  }

  _cleanup() {
    const now = Date.now();
    const expired = [];
    
    for (const [key, entry] of this.entries) {
      if (now - entry.lastUsed > this.timeout) {
        expired.push(key);
      }
    }
    
    for (const key of expired) {
      this.removeMapping(key);
    }
    
    if (expired.length > 0) {
      this.emit('cleanup', expired.length);
    }
  }

  getStats() {
    return {
      totalMappings: this.entries.size,
      portRange: `${this.portStart}-${this.portEnd}`,
      nextPort: this.nextPort
    };
  }
}

export class ExitNodeForwarder extends EventEmitter {
  constructor(config = {}) {
    super();
    this.natTable = new NATTable(config.nat || {});
    this.udpSockets = new Map();
    this.tcpConnections = new Map();
    this.publicIp = config.publicIp || null;
    this.enabled = false;
  }

  async start() {
    this.natTable.start();
    this.enabled = true;
    
    if (!this.publicIp) {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        this.publicIp = data.ip;
      } catch {
        console.warn('Could not determine public IP');
      }
    }
    
    this.emit('started', { publicIp: this.publicIp });
  }

  stop() {
    this.enabled = false;
    this.natTable.stop();
    
    for (const socket of this.udpSockets.values()) {
      socket.close();
    }
    this.udpSockets.clear();
    
    for (const conn of this.tcpConnections.values()) {
      conn.destroy();
    }
    this.tcpConnections.clear();
    
    this.emit('stopped');
  }

  async forwardUDP(srcNodeId, srcIp, srcPort, dstIp, dstPort, payload) {
    if (!this.enabled) {
      return null;
    }
    
    const mapping = this.natTable.createMapping(
      srcNodeId, srcIp, srcPort, dstIp, dstPort, 'udp'
    );
    
    let socket = this.udpSockets.get(mapping.natPort);
    
    if (!socket) {
      socket = dgram.createSocket('udp4');
      
      socket.on('message', (msg, rinfo) => {
        this._handleUDPResponse(mapping.natPort, msg, rinfo);
      });
      
      socket.on('error', (err) => {
        this.emit('error', { type: 'udp', error: err });
      });
      
      await new Promise((resolve, reject) => {
        socket.bind(mapping.natPort, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      
      this.udpSockets.set(mapping.natPort, socket);
    }
    
    return new Promise((resolve, reject) => {
      socket.send(payload, dstPort, dstIp, (err) => {
        if (err) {
          reject(err);
        } else {
          mapping.bytesOut += payload.length;
          resolve(mapping);
        }
      });
    });
  }

  _handleUDPResponse(natPort, data, rinfo) {
    for (const entry of this.natTable.entries.values()) {
      if (entry.natPort === natPort && 
          entry.dstIp === rinfo.address && 
          entry.dstPort === rinfo.port &&
          entry.protocol === 'udp') {
        
        entry.bytesIn += data.length;
        entry.lastUsed = Date.now();
        
        this.emit('response', {
          srcNodeId: entry.srcNodeId,
          srcIp: entry.srcIp,
          srcPort: entry.srcPort,
          data,
          protocol: 'udp'
        });
        
        return;
      }
    }
  }

  async forwardTCP(srcNodeId, srcIp, srcPort, dstIp, dstPort, payload) {
    if (!this.enabled) {
      return null;
    }
    
    const mapping = this.natTable.createMapping(
      srcNodeId, srcIp, srcPort, dstIp, dstPort, 'tcp'
    );
    
    const connKey = mapping.key;
    let conn = this.tcpConnections.get(connKey);
    
    if (!conn || conn.destroyed) {
      conn = await this._createTCPConnection(mapping);
      this.tcpConnections.set(connKey, conn);
    }
    
    return new Promise((resolve, reject) => {
      conn.write(payload, (err) => {
        if (err) {
          reject(err);
        } else {
          mapping.bytesOut += payload.length;
          resolve(mapping);
        }
      });
    });
  }

  async _createTCPConnection(mapping) {
    return new Promise((resolve, reject) => {
      const conn = net.createConnection({
        host: mapping.dstIp,
        port: mapping.dstPort,
        localPort: mapping.natPort
      });
      
      conn.on('connect', () => {
        resolve(conn);
      });
      
      conn.on('data', (data) => {
        mapping.bytesIn += data.length;
        mapping.lastUsed = Date.now();
        
        this.emit('response', {
          srcNodeId: mapping.srcNodeId,
          srcIp: mapping.srcIp,
          srcPort: mapping.srcPort,
          data,
          protocol: 'tcp'
        });
      });
      
      conn.on('error', (err) => {
        this.emit('error', { type: 'tcp', mapping, error: err });
        reject(err);
      });
      
      conn.on('close', () => {
        this.tcpConnections.delete(mapping.key);
        this.natTable.removeMapping(mapping.key);
      });
    });
  }

  async resolveDNS(hostname) {
    try {
      const addresses = await dnsResolve(hostname);
      return addresses[0];
    } catch (err) {
      this.emit('error', { type: 'dns', hostname, error: err });
      return null;
    }
  }

  getStats() {
    return {
      enabled: this.enabled,
      publicIp: this.publicIp,
      nat: this.natTable.getStats(),
      activeUdpSockets: this.udpSockets.size,
      activeTcpConnections: this.tcpConnections.size
    };
  }
}

export class ExitNode extends EventEmitter {
  constructor(config = {}) {
    super();
    this.forwarder = new ExitNodeForwarder(config);
    this.nodeId = config.nodeId;
    this.virtualIp = config.virtualIp;
  }

  async start() {
    this.forwarder.on('response', (response) => {
      this.emit('internet-response', response);
    });
    
    this.forwarder.on('error', (error) => {
      this.emit('error', error);
    });
    
    await this.forwarder.start();
    this.emit('started');
  }

  async processPacket(packet, payload) {
    const ipHeader = this._parseIPHeader(payload);
    if (!ipHeader) {
      return null;
    }
    
    const { dstIp, protocol, srcPort, dstPort, data } = ipHeader;
    
    if (protocol === 17) {
      return await this.forwarder.forwardUDP(
        packet.srcNode,
        packet.srcIp || '10.200.0.1',
        srcPort,
        dstIp,
        dstPort,
        data
      );
    } else if (protocol === 6) {
      return await this.forwarder.forwardTCP(
        packet.srcNode,
        packet.srcIp || '10.200.0.1',
        srcPort,
        dstIp,
        dstPort,
        data
      );
    }
    
    return null;
  }

  _parseIPHeader(data) {
    if (data.length < 20) return null;
    
    const version = (data[0] >> 4) & 0x0f;
    if (version !== 4) return null;
    
    const headerLength = (data[0] & 0x0f) * 4;
    const protocol = data[9];
    const dstIp = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;
    
    let srcPort = 0;
    let dstPort = 0;
    let transportData = data.subarray(headerLength);
    
    if ((protocol === 6 || protocol === 17) && transportData.length >= 4) {
      srcPort = transportData.readUInt16BE(0);
      dstPort = transportData.readUInt16BE(2);
      transportData = transportData.subarray(protocol === 6 ? 20 : 8);
    }
    
    return {
      version,
      headerLength,
      protocol,
      dstIp,
      srcPort,
      dstPort,
      data: transportData
    };
  }

  stop() {
    this.forwarder.stop();
    this.emit('stopped');
  }

  getStats() {
    return {
      nodeId: this.nodeId,
      virtualIp: this.virtualIp,
      forwarder: this.forwarder.getStats()
    };
  }
}
