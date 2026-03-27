import { EventEmitter } from 'events';
import { spawn, execSync } from 'child_process';
import { promises as dnsPromises } from 'dns';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

/**
 * Hostnames / URL-like strings from mesh config (signalling, TURN, ICE).
 * @param {object} config
 * @returns {string[]}
 */
function _collectInfraHostsFromMeshConfig(config) {
  const hosts = new Set();

  const pushHost = (h) => {
    if (h && typeof h === 'string') hosts.add(h.trim());
  };

  const addUrlLike = (s) => {
    if (!s || typeof s !== 'string') return;
    const t = s.trim();
    if (/^(wss?|https?):\/\//i.test(t)) {
      try {
        const u = new URL(t);
        if (u.hostname) pushHost(u.hostname);
      } catch {
        // ignore
      }
      return;
    }
    const m = t.match(/^(?:turn|turns|stun|stuns):([^:[\s]+)(?::\d+)?/i);
    if (m) {
      pushHost(m[1]);
    }
  };

  if (!config || typeof config !== 'object') {
    return [];
  }

  if (config.signallingServer) addUrlLike(config.signallingServer);
  if (config.dataServer) addUrlLike(config.dataServer);

  if (Array.isArray(config.turnServers)) {
    for (const entry of config.turnServers) {
      if (!entry?.urls) continue;
      const urls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
      for (const u of urls) addUrlLike(u);
    }
  }

  if (Array.isArray(config.iceServers)) {
    for (const entry of config.iceServers) {
      if (!entry?.urls) continue;
      const urls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
      for (const u of urls) addUrlLike(u);
    }
  }

  return [...hosts];
}

/**
 * Resolves infra hosts to IPv4 for ip route exclude rules.
 * @param {object} meshVpnConfig
 * @returns {Promise<string[]>}
 */
export async function collectInfraIPv4FromMeshConfigAsync(meshVpnConfig) {
  const hosts = _collectInfraHostsFromMeshConfig(meshVpnConfig);
  const ips = new Set();

  for (const h of hosts) {
    if (!h) continue;
    if (IPV4_RE.test(h)) {
      ips.add(h);
      continue;
    }
    if (h === 'localhost') {
      ips.add('127.0.0.1');
      continue;
    }
    try {
      const { address } = await dnsPromises.lookup(h, { family: 4 });
      ips.add(address);
    } catch (err) {
      console.warn(`[TUN] Could not resolve infra host "${h}": ${err.message}`);
    }
  }

  return [...ips];
}

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
    /** Full mesh node config: used to add /32 routes for signalling/TURN/ICE before switching default to tun. */
    this.meshVpnConfig = config.meshVpnConfig || null;

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

        void (async () => {
          try {
            await this._configureLinuxTunAsync();
          } catch (err) {
            console.warn(`Warning: Could not configure ${this.name}:`, err.message);
            console.log('You may need to run with sudo.');
          }
          resolve();
        })();
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

  async _configureLinuxTunAsync() {
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

    let infraIpv4 = [];
    if (this.meshVpnConfig) {
      infraIpv4 = await collectInfraIPv4FromMeshConfigAsync(this.meshVpnConfig);
    }

    // Full-tunnel clients: DNS via TUN + resolv.conf. Exit keeps host DNS; no full tunnel => do not touch resolv.
    if (!this.isExit && this.defaultRouteEnabled) {
      this._configureDNS();
    }

    this._setupDefaultRoute(infraIpv4);
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

  /**
   * @param {string[]} infraIpv4  Resolved IPv4 for signalling/TURN/ICE from mesh config
   */
  _setupDefaultRoute(infraIpv4 = []) {
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

      const excludeSet = new Set();
      for (const ip of this.excludedIPs) {
        if (ip && IPV4_RE.test(String(ip).trim())) {
          excludeSet.add(String(ip).trim());
        }
      }
      excludeSet.add('62.84.120.30');

      for (const ip of infraIpv4) {
        if (ip && IPV4_RE.test(ip)) excludeSet.add(ip);
      }

      const sigServer = process.env.SIGNALLING_SERVER;
      if (sigServer) {
        const sigMatch = sigServer.match(/(\d+\.\d+\.\d+\.\d+)/);
        if (sigMatch) excludeSet.add(sigMatch[1]);
      }

      const sshConn = process.env.SSH_CONNECTION;
      if (sshConn) {
        const clientIp = sshConn.trim().split(/\s+/)[0];
        if (IPV4_RE.test(clientIp)) {
          excludeSet.add(clientIp);
          console.log(`[TUN] Excluding SSH client IP from tunnel: ${clientIp}`);
        }
      }

      for (const ip of excludeSet) {
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
