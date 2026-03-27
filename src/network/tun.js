import { EventEmitter } from 'events';
import { spawn, execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UTUN_HELPER_PATH = path.join(__dirname, '../../helpers/utun-helper');
const TUN_HELPER_LINUX_PATH = path.join(__dirname, '../../helpers/tun-helper');

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
    this.isExit = config.isExit === true;

    // For Linux default route management
    // Read from config.tun or from top-level config
    const tunConfig = config.tun || {};
    this.originalRoutes = [];
    this.excludedIPs = tunConfig.excludeFromVPN || config.excludeFromVPN || [];
    this.defaultRouteEnabled = tunConfig.defaultRoute !== undefined 
      ? tunConfig.defaultRoute 
      : config.defaultRoute !== false;
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
    const tunName = this.config.tunName || 'tun0';
    
    return new Promise((resolve, reject) => {
      console.log('Creating TUN interface via helper...');
      
      if (!fs.existsSync(TUN_HELPER_LINUX_PATH)) {
        reject(new Error(`tun-helper not found at ${TUN_HELPER_LINUX_PATH}. Run: cd helpers && make`));
        return;
      }
      
      this.helperProcess = spawn(TUN_HELPER_LINUX_PATH, [tunName], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      let interfaceNameReceived = false;
      
      this.helperProcess.stderr.once('data', (data) => {
        const output = data.toString().trim();
        if (output.startsWith('ERROR:')) {
          reject(new Error(`tun-helper: ${output}`));
          return;
        }
        
        this.name = output;
        interfaceNameReceived = true;
        console.log(`Created TUN interface: ${this.name}`);
        
        this._configureLinuxTun();
        resolve();
      });
      
      this.helperProcess.stdout.on('data', (data) => {
        if (!this.running) return;
        this._processHelperData(data);
      });
      
      this.helperProcess.on('error', (err) => {
        console.error(`tun-helper error: ${err.message}`);
        if (!interfaceNameReceived) {
          reject(err);
        } else {
          this.emit('error', err);
        }
      });
      
      this.helperProcess.on('close', (code) => {
        if (this.running) {
          console.log(`tun-helper exited with code ${code}`);
          this.running = false;
          this.emit('close');
        }
      });
      
      setTimeout(() => {
        if (!interfaceNameReceived) {
          this.helperProcess.kill();
          reject(new Error('Timeout waiting for TUN interface name'));
        }
      }, 5000);
    });
  }

  _configureLinuxTun() {
    try {
      execSync(`ip addr add ${this.virtualIp}/16 dev ${this.name} 2>/dev/null || true`, { stdio: 'ignore' });
      execSync(`ip link set dev ${this.name} mtu ${this.mtu}`);
      execSync(`ip link set dev ${this.name} up`);
      
      const networkPrefix = this.virtualIp.split('.').slice(0, 2).join('.');
      try {
        execSync(`ip route add ${networkPrefix}.0.0/16 dev ${this.name} 2>/dev/null`, { stdio: 'ignore' });
        console.log(`Added route for ${networkPrefix}.0.0/16 via ${this.name}`);
      } catch {
        console.log(`Route for ${networkPrefix}.0.0/16 may already exist`);
      }
      
      // Client VPN: steer public DNS via TUN + resolv.conf. Exit node keeps host DNS and no DNS /32 routes on tun.
      if (!this.isExit) {
        this._configureDNS();
      }

      // Setup default route through VPN
      this._setupDefaultRoute();
    } catch (err) {
      console.warn(`Warning: Could not configure ${this.name}:`, err.message);
      console.log('You may need to run with sudo.');
    }
  }

  _configureDNS() {
    const dnsServers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'];
    
    try {
      // Add routes to DNS servers through TUN
      for (const dns of dnsServers) {
        try {
          execSync(`ip route add ${dns}/32 dev ${this.name} 2>/dev/null`, { stdio: 'ignore' });
        } catch {
          // Route may already exist
        }
      }
      console.log(`Added routes for DNS servers via ${this.name}`);
      
      // Backup original resolv.conf
      try {
        if (fs.existsSync('/etc/resolv.conf') && !fs.existsSync('/etc/resolv.conf.vpn-backup')) {
          execSync('cp /etc/resolv.conf /etc/resolv.conf.vpn-backup', { stdio: 'ignore' });
        }
      } catch {
        // Backup may fail, continue anyway
      }
      
      // Configure DNS resolvers
      const resolvConf = dnsServers.map(dns => `nameserver ${dns}`).join('\n') + '\n';
      fs.writeFileSync('/etc/resolv.conf', resolvConf);
      console.log('DNS configured through VPN:', dnsServers.join(', '));
    } catch (err) {
      console.warn('Could not configure DNS:', err.message);
    }
  }

  _restoreDNS() {
    try {
      if (fs.existsSync('/etc/resolv.conf.vpn-backup')) {
        execSync('cp /etc/resolv.conf.vpn-backup /etc/resolv.conf', { stdio: 'ignore' });
        execSync('rm /etc/resolv.conf.vpn-backup', { stdio: 'ignore' });
        console.log('DNS configuration restored');
      }
    } catch {
      // Restore may fail
    }
  }

  _setupDefaultRoute() {
    if (!this.defaultRouteEnabled) {
      console.log('Default route through VPN disabled in config');
      return;
    }

    try {
      // Get current default routes
      const routeOutput = execSync('ip route show default', { encoding: 'utf8' });
      const routes = routeOutput.trim().split('\n').filter(r => r.length > 0);
      
      // Save original routes for restoration
      this.originalRoutes = routes;
      console.log(`Saved ${routes.length} original default route(s)`);

      // Get gateway and interface from first default route
      const match = routes[0]?.match(/via\s+(\S+)\s+dev\s+(\S+)/);
      if (!match) {
        console.warn('Could not parse default route, skipping default route setup');
        return;
      }
      
      const [, gateway, iface] = match;
      
      // Add routes for excluded IPs (TURN servers, signalling, etc.) via original gateway
      const excludeIPs = [
        ...this.excludedIPs,
        '62.84.120.30',  // Default TURN server
      ];
      
      // Also try to get signalling server IP from environment
      const sigServer = process.env.SIGNALLING_SERVER;
      if (sigServer) {
        const sigMatch = sigServer.match(/(\d+\.\d+\.\d+\.\d+)/);
        if (sigMatch) {
          excludeIPs.push(sigMatch[1]);
        }
      }
      
      for (const ip of excludeIPs) {
        try {
          execSync(`ip route add ${ip}/32 via ${gateway} dev ${iface} 2>/dev/null`, { stdio: 'ignore' });
          console.log(`Excluded ${ip} from VPN (via ${gateway})`);
        } catch {
          // Route may already exist
        }
      }
      
      // Remove original default routes
      for (const route of routes) {
        try {
          execSync(`ip route del ${route}`, { stdio: 'ignore' });
        } catch {
          // May fail
        }
      }
      
      // Add default route via TUN
      execSync(`ip route add default dev ${this.name}`);
      console.log(`Default route set through ${this.name}`);
      
      // Add backup route with high metric
      try {
        execSync(`ip route add default via ${gateway} dev ${iface} metric 1000`, { stdio: 'ignore' });
      } catch {
        // May fail
      }
      
    } catch (err) {
      console.warn('Could not setup default route:', err.message);
    }
  }

  _restoreDefaultRoute() {
    if (this.originalRoutes.length === 0) {
      return;
    }

    try {
      // Remove VPN default route
      try {
        execSync(`ip route del default dev ${this.name} 2>/dev/null`, { stdio: 'ignore' });
      } catch {
        // May not exist
      }
      
      // Remove backup route
      try {
        execSync('ip route del default metric 1000 2>/dev/null', { stdio: 'ignore' });
      } catch {
        // May not exist
      }
      
      // Restore original routes
      for (const route of this.originalRoutes) {
        try {
          execSync(`ip route add ${route}`, { stdio: 'ignore' });
        } catch {
          // May already exist
        }
      }
      
      console.log('Default route restored');
      this.originalRoutes = [];
    } catch (err) {
      console.warn('Could not restore default route:', err.message);
    }
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
      
      const networkPrefix = this.virtualIp.split('.').slice(0, 2).join('.');
      try {
        execSync(`route add -net ${networkPrefix}.0.0/16 -interface ${this.name}`, { stdio: 'ignore' });
        console.log(`Added route for ${networkPrefix}.0.0/16 via ${this.name}`);
      } catch {
        console.log(`Route for ${networkPrefix}.0.0/16 may already exist`);
      }
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
    
    // Both Linux and macOS now use helper process
    if (this.helperProcess && this.helperProcess.stdin.writable) {
      return this._writeViaHelper(packet);
    }
    
    return false;
  }

  _writeViaHelper(packet) {
    try {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(packet.length, 0);
      
      // Single write instead of two separate writes
      const combined = Buffer.concat([header, packet]);
      this.helperProcess.stdin.write(combined);
      return true;
    } catch (err) {
      this.emit('error', err);
      return false;
    }
  }


  async close() {
    this.running = false;
    
    // Restore DNS and routes on Linux
    if (this.platform === 'linux') {
      this._restoreDefaultRoute();
      this._restoreDNS();
    }
    
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

  getInterfaceName() {
    return this.tun ? this.tun.name : null;
  }
}
