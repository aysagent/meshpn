import { EventEmitter } from 'events';
import { spawn, execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const LINUX_TUN_PATH = '/dev/net/tun';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UTUN_HELPER_PATH = path.join(__dirname, '../../helpers/utun-helper');

export class TunInterface extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = config;
    this.name = null;
    this.virtualIp = config.virtualIp;
    this.netmask = config.netmask || '255.255.0.0';
    this.mtu = config.mtu || 1400;
    this.fd = null;
    this.socket = null;
    this.helperProcess = null;
    this.readBuffer = Buffer.alloc(0);
    this.platform = os.platform();
    this.running = false;
  }

  _findFreeUtunIndex() {
    try {
      const interfaces = execSync('ifconfig -l', { encoding: 'utf8' }).trim().split(' ');
      const usedIndices = interfaces
        .filter(name => name.startsWith('utun'))
        .map(name => parseInt(name.replace('utun', ''), 10))
        .filter(idx => !isNaN(idx));
      
      let freeIndex = 0;
      while (usedIndices.includes(freeIndex)) {
        freeIndex++;
      }
      return freeIndex;
    } catch {
      return 0;
    }
  }

  _findFreeTunName() {
    try {
      const interfaces = execSync('ip link show', { encoding: 'utf8' });
      const usedIndices = [];
      const regex = /tun(\d+):/g;
      let match;
      while ((match = regex.exec(interfaces)) !== null) {
        usedIndices.push(parseInt(match[1], 10));
      }
      
      let freeIndex = 0;
      while (usedIndices.includes(freeIndex)) {
        freeIndex++;
      }
      return `tun${freeIndex}`;
    } catch {
      return 'tun0';
    }
  }

  async open() {
    if (this.platform === 'linux') {
      await this._openLinux();
    } else if (this.platform === 'darwin') {
      await this._openMacOS();
    } else {
      throw new Error(`Unsupported platform: ${this.platform}`);
    }
    
    this.running = true;
    this.emit('open', this.name);
  }

  async _openLinux() {
    if (this.config.tunName) {
      this.name = this.config.tunName;
    } else {
      this.name = this._findFreeTunName();
    }
    
    return new Promise((resolve, reject) => {
      try {
        fs.open(LINUX_TUN_PATH, 'r+', (err, fd) => {
          if (err) {
            reject(new Error(`Failed to open ${LINUX_TUN_PATH}: ${err.message}`));
            return;
          }
          
          this.fd = fd;
          
          this._configureLinuxTun(fd)
            .then(() => resolve())
            .catch(reject);
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  async _configureLinuxTun(fd) {
    try {
      execSync(`ip tuntap add dev ${this.name} mode tun`, { stdio: 'ignore' });
    } catch {
      // Interface might already exist
    }
    
    execSync(`ip addr add ${this.virtualIp}/16 dev ${this.name}`);
    execSync(`ip link set dev ${this.name} mtu ${this.mtu}`);
    execSync(`ip link set dev ${this.name} up`);
    
    this._startReadLoop();
  }

  async _openMacOS() {
    return new Promise((resolve, reject) => {
      console.log('Creating utun interface via helper...');
      
      if (!fs.existsSync(UTUN_HELPER_PATH)) {
        reject(new Error(`utun-helper not found at ${UTUN_HELPER_PATH}. Run: cd helpers && make`));
        return;
      }
      
      this.helperProcess = spawn(UTUN_HELPER_PATH, [], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      let interfaceNameReceived = false;
      
      this.helperProcess.stderr.once('data', (data) => {
        const output = data.toString().trim();
        if (output.startsWith('ERROR:')) {
          reject(new Error(`utun-helper: ${output}`));
          return;
        }
        
        this.name = output;
        interfaceNameReceived = true;
        console.log(`Created utun interface: ${this.name}`);
        
        this._configureMacOSTun();
        resolve();
      });
      
      this.helperProcess.stdout.on('data', (data) => {
        if (!this.running) return;
        this._processHelperData(data);
      });
      
      this.helperProcess.on('error', (err) => {
        console.error(`utun-helper error: ${err.message}`);
        if (!interfaceNameReceived) {
          reject(err);
        } else {
          this.emit('error', err);
        }
      });
      
      this.helperProcess.on('close', (code) => {
        if (this.running) {
          console.log(`utun-helper exited with code ${code}`);
          this.running = false;
          this.emit('close');
        }
      });
      
      setTimeout(() => {
        if (!interfaceNameReceived) {
          this.helperProcess.kill();
          reject(new Error('Timeout waiting for utun interface name'));
        }
      }, 5000);
    });
  }
  
  _processHelperData(data) {
    this.readBuffer = Buffer.concat([this.readBuffer, data]);
    
    while (this.readBuffer.length >= 4) {
      const packetLen = this.readBuffer.readUInt32BE(0);
      
      if (packetLen > this.mtu + 100) {
        console.error(`Invalid packet length from helper: ${packetLen}`);
        this.readBuffer = Buffer.alloc(0);
        break;
      }
      
      if (this.readBuffer.length < 4 + packetLen) {
        break;
      }
      
      const packet = this.readBuffer.subarray(4, 4 + packetLen);
      this.readBuffer = this.readBuffer.subarray(4 + packetLen);
      
      if (packet.length > 0) {
        this.emit('packet', Buffer.from(packet));
      }
    }
  }

  _configureMacOSTun() {
    try {
      execSync(`ifconfig ${this.name} ${this.virtualIp} ${this.virtualIp} netmask ${this.netmask} mtu ${this.mtu} up`);
    } catch (err) {
      console.warn(`Warning: Could not configure ${this.name}:`, err.message);
      console.log('You may need to run with sudo or configure the interface manually.');
    }
  }

  _startReadLoop() {
    if (this.fd === null) return;
    
    const buffer = Buffer.alloc(this.mtu + 4);
    
    const readPacket = () => {
      if (!this.running || this.fd === null) return;
      
      fs.read(this.fd, buffer, 0, buffer.length, null, (err, bytesRead) => {
        if (err) {
          if (this.running) {
            this.emit('error', err);
          }
          return;
        }
        
        if (bytesRead > 0) {
          const packet = Buffer.alloc(bytesRead);
          buffer.copy(packet, 0, 0, bytesRead);
          this.emit('packet', packet);
        }
        
        setImmediate(readPacket);
      });
    };
    
    readPacket();
  }

  write(packet) {
    if (!this.running) {
      return false;
    }
    
    if (this.platform === 'linux' && this.fd !== null) {
      return this._writeLinux(packet);
    } else if (this.platform === 'darwin') {
      return this._writeMacOS(packet);
    }
    
    return false;
  }

  _writeLinux(packet) {
    try {
      fs.writeSync(this.fd, packet);
      return true;
    } catch (err) {
      this.emit('error', err);
      return false;
    }
  }

  _writeMacOS(packet) {
    if (!this.helperProcess || !this.helperProcess.stdin.writable) {
      return false;
    }
    
    try {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(packet.length, 0);
      
      this.helperProcess.stdin.write(header);
      this.helperProcess.stdin.write(packet);
      return true;
    } catch (err) {
      this.emit('error', err);
      return false;
    }
  }

  async close() {
    this.running = false;
    
    if (this.helperProcess) {
      try {
        this.helperProcess.stdin.end();
        this.helperProcess.kill('SIGTERM');
      } catch {
        // Ignore close errors
      }
      this.helperProcess = null;
    }
    
    if (this.fd !== null && this.platform === 'linux') {
      fs.closeSync(this.fd);
      this.fd = null;
    }
    
    try {
      if (this.platform === 'linux') {
        execSync(`ip link delete ${this.name}`, { stdio: 'ignore' });
      }
    } catch {
      // Interface might already be deleted
    }
    
    this.emit('close');
  }

  getStats() {
    return {
      name: this.name,
      virtualIp: this.virtualIp,
      mtu: this.mtu,
      running: this.running,
      platform: this.platform
    };
  }
}

export class TunManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = config;
    this.tun = null;
    this.virtualIp = null;
  }

  async setup(virtualIp) {
    this.virtualIp = virtualIp;
    
    this.tun = new TunInterface({
      ...this.config,
      virtualIp
    });
    
    this.tun.on('packet', (packet) => {
      this.emit('outbound-packet', packet);
    });
    
    this.tun.on('error', (err) => {
      this.emit('error', err);
    });
    
    try {
      await this.tun.open();
      console.log(`TUN interface ${this.tun.name} configured with IP ${virtualIp}`);
    } catch (err) {
      console.error('Failed to open TUN interface:', err.message);
      console.log('The VPN will run in proxy mode without TUN.');
      this.tun = null;
    }
    
    return this.tun !== null;
  }

  injectPacket(packet) {
    if (this.tun) {
      return this.tun.write(packet);
    }
    return false;
  }

  async shutdown() {
    if (this.tun) {
      await this.tun.close();
      this.tun = null;
    }
  }

  isRunning() {
    return this.tun !== null && this.tun.running;
  }
}
