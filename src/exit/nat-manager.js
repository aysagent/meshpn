import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const BACKUP_DIR = path.join(os.homedir(), '.mesh-vpn-backup');

export class NATManager {
  constructor(config = {}) {
    this.config = config;
    this.platform = os.platform();
    this.enabled = false;
    this.tunInterface = null;
    this.externalInterface = null;
    this.backupCreated = false;
  }

  _detectExternalInterface() {
    try {
      if (this.platform === 'linux') {
        const output = execSync('ip route | grep default | head -1', { encoding: 'utf8' });
        const match = output.match(/dev\s+(\S+)/);
        return match ? match[1] : null;
      } else if (this.platform === 'darwin') {
        const output = execSync('route -n get default 2>/dev/null', { encoding: 'utf8' });
        const match = output.match(/interface:\s*(\S+)/);
        return match ? match[1] : null;
      }
    } catch (err) {
      console.warn('[NAT] Could not detect external interface:', err.message);
    }
    return null;
  }

  _ensureBackupDir() {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
    }
  }

  _saveBackup() {
    this._ensureBackupDir();

    try {
      if (this.platform === 'linux') {
        const ipForward = execSync('cat /proc/sys/net/ipv4/ip_forward', { encoding: 'utf8' }).trim();
        fs.writeFileSync(path.join(BACKUP_DIR, 'ip_forward'), ipForward);

        try {
          const iptables = execSync('sudo iptables-save 2>/dev/null', { encoding: 'utf8' });
          fs.writeFileSync(path.join(BACKUP_DIR, 'iptables.rules'), iptables);
        } catch {
          console.warn('[NAT] Could not save iptables rules');
        }

      } else if (this.platform === 'darwin') {
        const ipForward = execSync('sysctl -n net.inet.ip.forwarding', { encoding: 'utf8' }).trim();
        fs.writeFileSync(path.join(BACKUP_DIR, 'ip_forward'), ipForward);

        try {
          const pfNat = execSync('sudo pfctl -sn 2>/dev/null', { encoding: 'utf8' });
          fs.writeFileSync(path.join(BACKUP_DIR, 'pf_nat.rules'), pfNat);
        } catch {
          fs.writeFileSync(path.join(BACKUP_DIR, 'pf_nat.rules'), '');
        }

        try {
          const pfRules = execSync('sudo pfctl -sr 2>/dev/null', { encoding: 'utf8' });
          fs.writeFileSync(path.join(BACKUP_DIR, 'pf_filter.rules'), pfRules);
        } catch {
          fs.writeFileSync(path.join(BACKUP_DIR, 'pf_filter.rules'), '');
        }

        try {
          const pfInfo = execSync('sudo pfctl -s info 2>/dev/null', { encoding: 'utf8' });
          const status = pfInfo.includes('Status: Enabled') ? 'enabled' : 'disabled';
          fs.writeFileSync(path.join(BACKUP_DIR, 'pf_status'), status);
        } catch {
          fs.writeFileSync(path.join(BACKUP_DIR, 'pf_status'), 'disabled');
        }
      }

      fs.writeFileSync(path.join(BACKUP_DIR, 'interface'), this.externalInterface || '');
      fs.writeFileSync(path.join(BACKUP_DIR, 'tun_interface'), this.tunInterface || '');

      this.backupCreated = true;
      console.log(`[NAT] Backup saved to ${BACKUP_DIR}`);

    } catch (err) {
      console.error('[NAT] Failed to save backup:', err.message);
    }
  }

  async enable(tunInterface, externalInterface = null) {
    if (this.enabled) {
      console.log('[NAT] Already enabled');
      return true;
    }

    this.tunInterface = tunInterface;
    this.externalInterface = externalInterface || this._detectExternalInterface();

    if (!this.externalInterface) {
      console.error('[NAT] Could not detect external interface. Please specify it in config.');
      return false;
    }

    console.log(`[NAT] Enabling NAT: ${this.tunInterface} -> ${this.externalInterface}`);

    this._saveBackup();

    try {
      if (this.platform === 'linux') {
        await this._enableLinux();
      } else if (this.platform === 'darwin') {
        await this._enableMacOS();
      } else {
        console.error(`[NAT] Unsupported platform: ${this.platform}`);
        return false;
      }

      this.enabled = true;
      console.log('[NAT] NAT enabled successfully');
      return true;

    } catch (err) {
      console.error('[NAT] Failed to enable NAT:', err.message);
      return false;
    }
  }

  async _enableLinux() {
    execSync('sudo sysctl -w net.ipv4.ip_forward=1', { stdio: 'ignore' });
    console.log('[NAT] IP forwarding enabled');

    try {
      execSync(`sudo iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -o ${this.externalInterface} -j MASQUERADE 2>/dev/null`);
      console.log('[NAT] MASQUERADE rule already exists');
    } catch {
      execSync(`sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -o ${this.externalInterface} -j MASQUERADE`);
      console.log('[NAT] MASQUERADE rule added');
    }

    try {
      execSync('sudo iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null');
    } catch {
      execSync('sudo iptables -A FORWARD -i tun+ -j ACCEPT');
      console.log('[NAT] FORWARD tun+ input rule added');
    }

    try {
      execSync('sudo iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null');
    } catch {
      execSync('sudo iptables -A FORWARD -o tun+ -j ACCEPT');
      console.log('[NAT] FORWARD tun+ output rule added');
    }
  }

  async _enableMacOS() {
    execSync('sudo sysctl -w net.inet.ip.forwarding=1', { stdio: 'ignore' });
    console.log('[NAT] IP forwarding enabled');

    const natRule = `nat on ${this.externalInterface} from 10.200.0.0/16 to any -> (${this.externalInterface})`;
    const passRules = [
      `pass in on ${this.tunInterface} from 10.200.0.0/16 to any`,
      `pass out on ${this.externalInterface} from any to any`,
      `pass in on ${this.externalInterface} from any to any`,
      `pass out on ${this.tunInterface} from any to 10.200.0.0/16`
    ].join('\n');
    
    const tempFile = `/tmp/mesh-vpn-pf-${process.pid}.conf`;

    let existingNat = '';
    let existingRules = '';
    
    try {
      existingNat = execSync('sudo pfctl -sn 2>/dev/null', { encoding: 'utf8' }).trim();
    } catch {}
    
    try {
      existingRules = execSync('sudo pfctl -sr 2>/dev/null', { encoding: 'utf8' }).trim();
    } catch {}

    const fullConfig = [
      existingNat,
      natRule,
      existingRules,
      passRules
    ].filter(s => s).join('\n');

    fs.writeFileSync(tempFile, fullConfig + '\n');

    try {
      execSync('sudo pfctl -e 2>/dev/null', { stdio: 'ignore' });
    } catch {
      // pf already enabled
    }

    try {
      execSync(`sudo pfctl -f ${tempFile}`, { stdio: 'pipe' });
      console.log('[NAT] pf rules loaded (NAT + pass)');
    } catch (err) {
      console.error('[NAT] Failed to load pf rules:', err.message);
      console.error('[NAT] Config file content:');
      console.error(fullConfig);
      throw err;
    } finally {
      try { fs.unlinkSync(tempFile); } catch {}
    }
  }

  async disable() {
    if (!this.enabled && !this.backupCreated) {
      console.log('[NAT] Not enabled, nothing to disable');
      return true;
    }

    console.log('[NAT] Disabling NAT...');

    try {
      if (this.platform === 'linux') {
        await this._disableLinux();
      } else if (this.platform === 'darwin') {
        await this._disableMacOS();
      }

      this.enabled = false;
      console.log('[NAT] NAT disabled, settings restored');
      return true;

    } catch (err) {
      console.error('[NAT] Failed to disable NAT:', err.message);
      return false;
    }
  }

  async _disableLinux() {
    const extIface = this.externalInterface || this._readBackupFile('interface');

    if (extIface) {
      try {
        execSync(`sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/16 -o ${extIface} -j MASQUERADE 2>/dev/null`);
        console.log('[NAT] MASQUERADE rule removed');
      } catch {
        // Rule might not exist
      }
    }

    try {
      execSync('sudo iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null');
      console.log('[NAT] FORWARD tun+ input rule removed');
    } catch {}

    try {
      execSync('sudo iptables -D FORWARD -o tun+ -j ACCEPT 2>/dev/null');
      console.log('[NAT] FORWARD tun+ output rule removed');
    } catch {}

    const originalForward = this._readBackupFile('ip_forward');
    if (originalForward !== null) {
      execSync(`sudo sysctl -w net.ipv4.ip_forward=${originalForward}`, { stdio: 'ignore' });
      console.log(`[NAT] IP forwarding restored to: ${originalForward}`);
    }
  }

  async _disableMacOS() {
    const backupNat = this._readBackupFile('pf_nat.rules');
    const backupFilter = this._readBackupFile('pf_filter.rules');
    
    if (backupNat !== null) {
      const tempFile = `/tmp/mesh-vpn-pf-restore-${process.pid}.conf`;
      try {
        fs.writeFileSync(tempFile, backupNat || '');
        execSync(`sudo pfctl -N -f ${tempFile} 2>/dev/null`, { stdio: 'ignore' });
        console.log('[NAT] pf NAT rules restored from backup');
      } catch {
        try {
          execSync('sudo pfctl -F nat 2>/dev/null', { stdio: 'ignore' });
          console.log('[NAT] pf NAT rules flushed');
        } catch {}
      } finally {
        try { fs.unlinkSync(tempFile); } catch {}
      }
    } else {
      try {
        execSync('sudo pfctl -F nat 2>/dev/null', { stdio: 'ignore' });
        console.log('[NAT] pf NAT rules flushed');
      } catch {}
    }

    if (backupFilter !== null) {
      const tempFile = `/tmp/mesh-vpn-pf-filter-restore-${process.pid}.conf`;
      try {
        fs.writeFileSync(tempFile, backupFilter || '');
        execSync(`sudo pfctl -f ${tempFile} 2>/dev/null`, { stdio: 'ignore' });
        console.log('[NAT] pf filter rules restored from backup');
      } catch {
        try {
          execSync('sudo pfctl -F rules 2>/dev/null', { stdio: 'ignore' });
          console.log('[NAT] pf filter rules flushed');
        } catch {}
      } finally {
        try { fs.unlinkSync(tempFile); } catch {}
      }
    }

    const originalForward = this._readBackupFile('ip_forward');
    if (originalForward !== null) {
      execSync(`sudo sysctl -w net.inet.ip.forwarding=${originalForward}`, { stdio: 'ignore' });
      console.log(`[NAT] IP forwarding restored to: ${originalForward}`);
    }

    const pfStatus = this._readBackupFile('pf_status');
    if (pfStatus === 'disabled') {
      try {
        execSync('sudo pfctl -d 2>/dev/null');
        console.log('[NAT] pf disabled (restored to original state)');
      } catch {}
    }
  }

  _readBackupFile(filename) {
    const filePath = path.join(BACKUP_DIR, filename);
    try {
      if (fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf8').trim();
      }
    } catch {}
    return null;
  }

  cleanup() {
    try {
      if (fs.existsSync(BACKUP_DIR)) {
        const files = fs.readdirSync(BACKUP_DIR);
        for (const file of files) {
          fs.unlinkSync(path.join(BACKUP_DIR, file));
        }
        fs.rmdirSync(BACKUP_DIR);
        console.log('[NAT] Backup files cleaned up');
      }
    } catch (err) {
      console.warn('[NAT] Could not clean up backup files:', err.message);
    }
  }
}
