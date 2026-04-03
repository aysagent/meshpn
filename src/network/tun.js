import { EventEmitter } from 'events';
import { spawn, execSync, execFileSync } from 'child_process';
import { promises as dnsPromises } from 'dns';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { applyLooseRpFilterForVpn, restoreRpFilterBackup } from './linux-rp-filter.js';

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

/** Не вешать /32 на uplink: loopback из `localhost` в signalling и link-local ломают маршрутизацию. */
function isIpv4UplinkBypassSafe(ip) {
  if (!ip || !IPV4_RE.test(ip)) {
    return false;
  }
  const [a, b] = ip.split('.').map(Number);
  if (a === 127) {
    return false;
  }
  if (a === 169 && b === 254) {
    /* link-local иначе не вешаем пачкой; исключение — IMDS облаков (иначе full tunnel уводит в tun). */
    return ip === '169.254.169.254';
  }
  if (a === 0 && b === 0) {
    return false;
  }
  return true;
}

/** Table 100: uplink-only для fwmark (SSH). Остальной IPv4 — `main` (split /1 → tun), без глобального `from all lookup 100`. */
const LINUX_RT_TABLE_MESHVPN = 100;
const LINUX_FWMARK_BYPASS_MAIN = 0x1;
/** Lower number = higher priority in `ip rule`. */
const LINUX_IP_RULE_PREF_FWMARK_MAIN = 100;
/** Старые установки (глобальный lookup 100): удалять при настройке/restore. */
const LINUX_IP_RULE_PREF_LOOKUP_MESHVPN_LEGACY = 101;
/**
 * `ip rule to INFRA_IP/32 pref 50 lookup 100` — bypass для TURN/signalling при split-default.
 * Работает на уровне policy rules (до routing table), поэтому не зависит от per-socket route cache:
 * добавление 0.0.0.0/1 в main table не влияет на уже открытые UDP-сокеты WebRTC/TURN.
 */
const LINUX_IP_RULE_PREF_INFRA_TO = 50;
const IPTABLES_CHAIN_MESHVPN = 'MESHVPN-BYPASS';

/** Без shell строка `… 2>/dev/null` попадает в argv ip и ломает команду; при отсутствии правила ip завершается с ошибкой. */
function flushIpRulePref(pref, maxAttempts = 6) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      execFileSync('ip', ['rule', 'del', 'pref', String(pref)], { stdio: 'ignore' });
    } catch {
      break;
    }
  }
}

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
 * Извлекает hostname из `SIGNALLING_SERVER` / похожих URL (ws/wss/http/https) или `turn:host:…`.
 * @param {string} s
 * @returns {string|null}
 */
function _hostnameFromEnvUrlLike(s) {
  if (!s || typeof s !== 'string') return null;
  const t = s.trim();
  if (/^(wss?|https?):\/\//i.test(t)) {
    try {
      const u = new URL(t);
      return u.hostname || null;
    } catch {
      return null;
    }
  }
  const m = t.match(/^(?:turn|turns|stun|stuns):([^:[\s]+)(?::\d+)?/i);
  return m ? m[1].trim() : null;
}

/**
 * Resolves infra hosts to IPv4 for ip route exclude rules (table meshvpn).
 * Hostnames use `resolve4` so **all** A records are added (public STUN pools use many IPs;
 * a single `lookup` left part of ICE traffic on default via tun).
 *
 * Учитывает домены в `signallingServer` / `dataServer` / TURN/ICE (как раньше), плюс
 * **`excludeFromVPN`** (литералы IPv4 и имена) и опционально **`SIGNALLING_SERVER`** из окружения.
 *
 * @param {object} meshVpnConfig
 * @param {object} [options]
 * @param {string[]|undefined} [options.excludeFromVPN]  IPv4 или hostname из `tun.excludeFromVPN`
 * @param {string|null|undefined} [options.signallingServerEnv]  по умолчанию `process.env.SIGNALLING_SERVER`
 * @returns {Promise<string[]>}
 */
export async function collectInfraIPv4FromMeshConfigAsync(meshVpnConfig, options = {}) {
  const excludeFromVPN = options.excludeFromVPN;
  const signallingServerEnv =
    options.signallingServerEnv !== undefined
      ? options.signallingServerEnv
      : process.env.SIGNALLING_SERVER;

  const hostSet = new Set(_collectInfraHostsFromMeshConfig(meshVpnConfig));
  const ips = new Set();

  if (Array.isArray(excludeFromVPN)) {
    for (const raw of excludeFromVPN) {
      const entry = raw != null ? String(raw).trim() : '';
      if (!entry) continue;
      if (IPV4_RE.test(entry)) {
        ips.add(entry);
        continue;
      }
      hostSet.add(entry);
    }
  }

  if (signallingServerEnv && typeof signallingServerEnv === 'string') {
    const t = signallingServerEnv.trim();
    const ipOnly = t.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (ipOnly) {
      ips.add(ipOnly[1]);
    } else {
      const h = _hostnameFromEnvUrlLike(t);
      if (h) {
        if (IPV4_RE.test(h)) ips.add(h);
        else hostSet.add(h);
      }
    }
  }

  for (const h of hostSet) {
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
      const addrs = await dnsPromises.resolve4(h);
      for (const a of addrs) {
        if (IPV4_RE.test(a)) ips.add(a);
      }
    } catch {
      try {
        const { address } = await dnsPromises.lookup(h, { family: 4 });
        ips.add(address);
      } catch (err) {
        console.warn(`[TUN] Could not resolve infra host "${h}": ${err.message}`);
      }
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
    /** Full mesh node config: infra IPv4 for /32 in main (bypass tun table). */
    this.meshVpnConfig = config.meshVpnConfig || null;

    /* TunManager передаёт поля из JSON `tun` развёрнутыми в корень; поддерживаем и `config.tun`. */
    const nestedTun = config.tun && typeof config.tun === 'object' ? { ...config.tun } : {};
    const tunConfig = { ...nestedTun };
    for (const k of [
      'defaultRoute',
      'excludeFromVPN',
      'deferPolicyRoutingDelayMs',
      'dnsViaVpn',
      'deferDnsAfterPolicyMs',
      'linuxSplitDefault',
      'linuxSplitDefaultDelayAfterPeerMs',
      'linuxFlushRouteCache',
      'logRouteDiag',
      'logRouteDiagSs',
    ]) {
      if (config[k] !== undefined) {
        tunConfig[k] = config[k];
      }
    }

    this.excludedIPs = tunConfig.excludeFromVPN || config.excludeFromVPN || [];
    /** @type {boolean} */
    this._linuxPolicyRoutingActive = false;
    this.defaultRouteEnabled = tunConfig.defaultRoute !== undefined 
      ? tunConfig.defaultRoute 
      : config.defaultRoute !== false;
    /** @type {boolean} */
    this._policyRoutingDeferred = false;
    /** Infra /32 + table 100 уже на фазе A; split-default отдельно после peer-connected. */
    this._infraAppliedEarly = false;
    /** Ожидается только добавление 0.0.0.0/1 и 128.0.0.0/1. */
    this._splitDefaultOnlyDeferred = false;
    /** @type {string[]|null} */
    this._deferredInfraIpv4 = null;
    /** @type {string|null} */
    this._deferredNetworkPrefix = null;
    /** @type {string[]|null} IPv4 /32, добавленные в main как infra bypass (снять в restore). */
    this._linuxMainInfraRoutes = null;
    /** @type {Record<string, string>|null} снимок rp_filter до policy routing */
    this._linuxRpFilterBackup = null;
    /** false — не ставить 0.0.0.0/1 и 128.0.0.0/1 в main (диагностика обрыва ICE при full tunnel). */
    this.linuxSplitDefault = tunConfig.linuxSplitDefault !== false;
    /** мс после первого вызова фазы B — только отложить split /1 (при ранней infra); 0 = сразу. */
    this.linuxSplitDefaultDelayAfterPeerMs =
      typeof tunConfig.linuxSplitDefaultDelayAfterPeerMs === 'number' &&
      tunConfig.linuxSplitDefaultDelayAfterPeerMs > 0
        ? tunConfig.linuxSplitDefaultDelayAfterPeerMs
        : 0;
    /** После policy routing вызывать `ip route flush cache` (по умолчанию true); false — если ICE падает при корректном `ip route get` к TURN. */
    this.linuxFlushRouteCache = tunConfig.linuxFlushRouteCache !== false;
    /** true — печатать в лог [TUN-DIAG] вывод `ip route get` / `ip rule` (после фазы B и при обрыве WebRTC на клиенте). */
    this.logRouteDiag = tunConfig.logRouteDiag === true;
    /** Дополнительно к logRouteDiag: короткий вывод `ss -uap` (UDP сокеты процесса не видны, но слушающие — да). */
    this.logRouteDiagSs = tunConfig.logRouteDiagSs === true;
    /** Подмена resolv.conf + /32 на публичные DNS; false — только маршруты (диагностика обрыва ICE). */
    this.dnsViaVpn = tunConfig.dnsViaVpn !== false;
    /** мс после успешных маршрутов до _configureDNS; 0 = сразу */
    this.deferDnsAfterPolicyMs =
      typeof tunConfig.deferDnsAfterPolicyMs === 'number' && tunConfig.deferDnsAfterPolicyMs >= 0
        ? tunConfig.deferDnsAfterPolicyMs
        : 0;
    /** @type {ReturnType<typeof setTimeout>|null} */
    this._deferDnsTimer = null;
    /** @type {ReturnType<typeof setTimeout>|null} */
    this._splitDefaultDelayTimer = null;
    /** Последний список infra IPv4 после успешной фазы B — для снимка при disconnect. */
    this._diagInfraSnapshot = [];
  }

  /**
   * Снимок маршрутизации для отладки (копипаста логов). Только Linux, только при logRouteDiag.
   * @param {string} reason
   */
  logRoutingDiag(reason) {
    if (!this.logRouteDiag || this.platform !== 'linux' || !this.name) {
      return;
    }
    const lines = [];
    const push = (label, text) => {
      const t = (text || '').trim().replace(/\n/g, '\n[TUN-DIAG]   ');
      lines.push(`[TUN-DIAG] ${label}: ${t || '(пусто)'}`);
    };

    const targets = new Set(['8.8.8.8', '1.1.1.1']);
    for (const ip of this._diagInfraSnapshot || []) {
      if (ip && IPV4_RE.test(ip)) {
        targets.add(ip);
      }
    }

    for (const ip of targets) {
      try {
        const out = execFileSync('ip', ['route', 'get', ip], { encoding: 'utf8' });
        push(`ip route get ${ip}`, out);
      } catch (e) {
        push(`ip route get ${ip}`, `(ошибка: ${e.message})`);
      }
    }

    try {
      const rules = execFileSync('ip', ['rule', 'list'], { encoding: 'utf8' });
      const ruleLines = rules.trim().split('\n').filter(Boolean);
      push(
        'ip rule list (первые 40 строк)',
        ruleLines.slice(0, 40).join('\n'),
      );
    } catch (e) {
      push('ip rule list', `(ошибка: ${e.message})`);
    }

    try {
      const main = execFileSync('ip', ['route', 'show', 'table', 'main'], { encoding: 'utf8' });
      const ml = main.trim().split('\n').filter(Boolean);
      push(
        'ip route show table main (первые 35 строк)',
        ml.slice(0, 35).join('\n'),
      );
    } catch (e) {
      push('ip route show table main', `(ошибка: ${e.message})`);
    }

    if (this.logRouteDiagSs) {
      try {
        const ssOut = execFileSync('ss', ['-uap'], { encoding: 'utf8', maxBuffer: 512 * 1024 });
        const ssLines = ssOut.trim().split('\n').filter(Boolean);
        push(
          'ss -uap (первые 30 строк)',
          ssLines.slice(0, 30).join('\n'),
        );
      } catch (e) {
        push('ss -uap', `(ошибка: ${e.message})`);
      }
    }

    console.log(`[TUN-DIAG] --- reason=${reason} tun=${this.name} ---`);
    for (const L of lines) {
      console.log(L);
    }
    console.log('[TUN-DIAG] --- конец снимка ---');
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

  /**
   * Linux-only: создать tun0 и применить ВСЕ маршруты (включая split-default) к DOWN-интерфейсу
   * ДО подключения к signalling. Маршруты хранятся ядром как DEAD и активируются атомарно
   * при `ip link set tun0 up` (в assignIpAndBringUp). IP не назначается — нужен virtualIp от сервера.
   */
  async openEarly() {
    const tunName = this.config.tunName || 'tun0';
    return new Promise((resolve, reject) => {
      if (!fs.existsSync(TUN_HELPER_LINUX_PATH)) {
        reject(new Error(`tun-helper not found at ${TUN_HELPER_LINUX_PATH}. Run: cd helpers && make`));
        return;
      }
      this.helperProcess = spawn(TUN_HELPER_LINUX_PATH, [tunName], { stdio: ['pipe', 'pipe', 'pipe'] });
      let interfaceNameReceived = false;
      this.helperProcess.stderr.once('data', (data) => {
        const output = data.toString().trim();
        if (output.startsWith('ERROR:')) {
          reject(new Error(`tun-helper: ${output}`));
          return;
        }
        this.name = output;
        interfaceNameReceived = true;
        console.log(`[TUN] Created TUN interface (early): ${this.name}`);
        this.helperProcess.stdout.on('data', (d) => {
          if (!this.running) return;
          this._processHelperData(d);
        });
        void (async () => {
          try {
            await this._applyEarlyLinuxRouting();
          } catch (err) {
            console.warn(`[TUN] Early routing failed: ${err.message}`);
          }
          resolve();
        })();
      });
      this.helperProcess.on('error', (err) => {
        if (!interfaceNameReceived) reject(err);
        else this.emit('error', err);
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

  /**
   * Применить ip rules + split-default на DOWN tun0 до получения virtualIp.
   * Маршруты к DOWN-интерфейсу ядро хранит как DEAD — не используются до `ip link set up`.
   */
  async _applyEarlyLinuxRouting() {
    const vnet = this.meshVpnConfig?.virtualNetwork || '10.200.0.0/16';
    const networkPrefix = vnet.split('/')[0].split('.').slice(0, 2).join('.');
    const infraIpv4 = await collectInfraIPv4FromMeshConfigAsync(this.meshVpnConfig || {}, {
      excludeFromVPN: this.excludedIPs,
    });
    const ok = this._setupLinuxPolicyRouting(infraIpv4, networkPrefix, {
      applySplitDefault: false, // split-default добавляем только после ip link set up
      flushCache: false,
    });
    if (ok && this._linuxPolicyRoutingActive) {
      this._infraAppliedEarly = true;
      this._splitDefaultOnlyDeferred = true; // будет добавлен в assignIpAndBringUp
      this._policyRoutingDeferred = false;
      this._deferredInfraIpv4 = infraIpv4;
      this._deferredNetworkPrefix = networkPrefix;
      console.log('[TUN] Ранний routing: ip rules + infra /32 на DOWN tun0; split-default — после ip link up');
    }
  }

  /**
   * Назначить IP и поднять tun0 после получения virtualIp от signalling.
   * ip rules (TURN bypass) уже активны с openEarly(). split-default добавляем здесь —
   * после ip link set up интерфейс UP, маршрут принимается ядром без ошибок.
   */
  async assignIpAndBringUp(virtualIp) {
    this.virtualIp = virtualIp;
    try {
      execFileSync('ip', ['addr', 'add', `${virtualIp}/16`, 'dev', this.name], { stdio: 'ignore' });
    } catch {
      /* адрес мог быть добавлен ранее */
    }
    execSync(`ip link set dev ${this.name} mtu ${this.mtu}`);
    execSync(`ip link set dev ${this.name} up`);
    if (this.linuxSplitDefault && this._splitDefaultOnlyDeferred) {
      try {
        execSync(`ip route replace 0.0.0.0/1 dev ${this.name}`);
        execSync(`ip route replace 128.0.0.0/1 dev ${this.name}`);
        this._splitDefaultOnlyDeferred = false;
        console.log('[TUN] split-default применён после ip link set up');
      } catch (err) {
        console.warn('[TUN] split-default failed:', err.message);
      }
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
    try {
      execFileSync('ip', ['addr', 'add', `${this.virtualIp}/16`, 'dev', this.name], { stdio: 'ignore' });
    } catch {
      /* адрес мог быть добавлен ранее */
    }
    execSync(`ip link set dev ${this.name} mtu ${this.mtu}`);
    execSync(`ip link set dev ${this.name} up`);

    const networkPrefix = this.virtualIp.split('.').slice(0, 2).join('.');
    const useLinuxPolicyRouting =
      this.platform === 'linux' && !this.isExit && this.defaultRouteEnabled;

    if (!useLinuxPolicyRouting) {
      try {
        execFileSync(
          'ip',
          ['route', 'add', `${networkPrefix}.0.0/16`, 'dev', this.name],
          { stdio: 'ignore' },
        );
        console.log(`Added route for ${networkPrefix}.0.0/16 via ${this.name}`);
      } catch {
        console.log(`Route for ${networkPrefix}.0.0/16 may already exist`);
      }
    }

    const infraIpv4 = await collectInfraIPv4FromMeshConfigAsync(this.meshVpnConfig || {}, {
      excludeFromVPN: this.excludedIPs,
    });

    // Split-default применяем сразу вместе с infra /32 и ip rules (до WebRTC ICE).
    // Это исключает изменение маршрутизации к живому WebRTC/TURN соединению:
    // ICE гатерит кандидатов и держит consent freshness уже с активным split-default.
    // TURN защищён `ip rule pref 50 to TURN_IP/32 lookup 100`, который настраивается
    // внутри _setupLinuxPolicyRouting() ДО добавления split-default маршрутов.
    if (useLinuxPolicyRouting) {
      try {
        execFileSync(
          'ip',
          ['route', 'add', `${networkPrefix}.0.0/16`, 'dev', this.name],
          { stdio: 'ignore' },
        );
        console.log(`[TUN] Route for ${networkPrefix}.0.0/16 via ${this.name} (main)`);
      } catch {
        console.log(`Route for ${networkPrefix}.0.0/16 may already exist`);
      }
      this._deferredInfraIpv4 = infraIpv4;
      this._deferredNetworkPrefix = networkPrefix;
      this._policyRoutingDeferred = true;
      try {
        const earlyOk = this._setupLinuxPolicyRouting(infraIpv4, networkPrefix, {
          applySplitDefault: this.linuxSplitDefault,
          flushCache: false,
        });
        if (earlyOk && this._linuxPolicyRoutingActive) {
          this._infraAppliedEarly = true;
          this._splitDefaultOnlyDeferred = false; // split-default применён сразу в Phase A
          const splitNote = this.linuxSplitDefault
            ? 'infra /32 + split-default до WebRTC; TURN защищён ip rule pref 50'
            : 'infra /32 + table 100 до WebRTC';
          console.log(`[TUN] ${splitNote}`);
        }
      } catch (e) {
        console.warn(`[TUN] Ранний infra policy routing не удался: ${e.message}`);
      }
    }

    if (!this.isExit && this.defaultRouteEnabled) {
      if (!useLinuxPolicyRouting) {
        this._configureDNS(null);
      } else {
        const dnsNote = this.dnsViaVpn
          ? 'после фазы B (или deferDnsAfterPolicyMs)'
          : 'не трогаем (tun.dnsViaVpn=false)';
        console.log(
          `[TUN] resolv.conf / маршруты к публичным DNS: ${dnsNote}; фаза B после peer-connected`,
        );
      }
    }
  }

  _clearDeferDnsTimer() {
    if (this._deferDnsTimer != null) {
      clearTimeout(this._deferDnsTimer);
      this._deferDnsTimer = null;
    }
  }

  _clearSplitDefaultDelayTimer() {
    if (this._splitDefaultDelayTimer != null) {
      clearTimeout(this._splitDefaultDelayTimer);
      this._splitDefaultDelayTimer = null;
    }
  }

  /** Отмена отложенного split-default (peer-disconnected / повтор фазы B). */
  cancelDeferredSplitDefaultTimer() {
    this._clearSplitDefaultDelayTimer();
  }

  _removeDnsRoutesFromMain() {
    if (!this.name) {
      return;
    }
    const dnsServers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'];
    for (const dns of dnsServers) {
      try {
        execFileSync(
          'ip',
          ['route', 'del', `${dns}/32`, 'dev', this.name],
          { stdio: 'ignore' },
        );
      } catch {
        /* ignore */
      }
    }
  }

  _runDeferredSplitDefaultNow(infraForPolicy) {
    if (!this.running || !this.name || !this._policyRoutingDeferred) {
      return;
    }
    console.log(
      '[TUN] Отложенное добавление split-default (linuxSplitDefaultDelayAfterPeerMs)',
    );
    let ok = true;
    try {
      execSync(`ip route replace 0.0.0.0/1 dev ${this.name}`, { stdio: 'ignore' });
      execSync(`ip route replace 128.0.0.0/1 dev ${this.name}`, { stdio: 'ignore' });
    } catch (err) {
      console.warn('[TUN] Deferred split-default failed:', err.message);
      ok = false;
    }
    if (this.linuxFlushRouteCache) {
      try {
        execFileSync('ip', ['route', 'flush', 'cache'], { stdio: 'ignore' });
      } catch {
        /* ignore */
      }
    } else {
      console.log('[TUN] linuxFlushRouteCache=false: пропуск ip route flush cache');
    }
    this._splitDefaultOnlyDeferred = false;
    if (infraForPolicy.length > 0) {
      this._diagInfraSnapshot = [...infraForPolicy];
    }
    if (!ok || !this._linuxPolicyRoutingActive) {
      console.warn(
        '[TUN] Deferred split-default не применён; повтор при следующем peer-connected',
      );
      return;
    }
    this._finalizeDeferredPolicyRoutingTail(
      infraForPolicy,
      'after-phase-B-split-default-delayed',
    );
  }

  _finalizeDeferredPolicyRoutingTail(
    infraForPolicy,
    diagReason = 'after-phase-B-policy-routing',
  ) {
    this._policyRoutingDeferred = false;
    this._deferredInfraIpv4 = null;
    this._deferredNetworkPrefix = null;
    if (!this._diagInfraSnapshot || this._diagInfraSnapshot.length === 0) {
      this._diagInfraSnapshot = [...infraForPolicy];
    }

    if (!this.isExit && this.defaultRouteEnabled) {
      if (!this.dnsViaVpn) {
        console.log(
          '[TUN] dnsViaVpn=false: resolv.conf и маршруты к 8.8.8.8/… не меняем — резолв через систему (VPC/resolved)',
        );
      } else if (this.deferDnsAfterPolicyMs > 0) {
        this._clearDeferDnsTimer();
        console.log(
          `[TUN] DNS через VPN через ${this.deferDnsAfterPolicyMs}ms после маршрутов`,
        );
        this._deferDnsTimer = setTimeout(() => {
          this._deferDnsTimer = null;
          this._configureDNS(null);
        }, this.deferDnsAfterPolicyMs);
      } else {
        this._configureDNS(null);
      }
    }

    this.logRoutingDiag(diagReason);
  }

  /**
   * Фаза B: split /1 + table 100 + iptables + DNS после первого peer-connected (WebRTC — с задержкой).
   */
  async applyDeferredPolicyRouting() {
    if (this.platform !== 'linux' || this.isExit || !this._policyRoutingDeferred || !this.name) {
      return;
    }
    const infra = this._deferredInfraIpv4;
    const prefix = this._deferredNetworkPrefix;
    if (!prefix) {
      return;
    }

    this._clearSplitDefaultDelayTimer();

    console.log('[TUN] Applying deferred Linux policy routing (WebRTC path ready)');
    this._removeDnsRoutesFromMain();
    let infraForPolicy = infra || [];
    try {
      const fresh = await collectInfraIPv4FromMeshConfigAsync(this.meshVpnConfig || {}, {
        excludeFromVPN: this.excludedIPs,
      });
      if (fresh.length > 0) {
        infraForPolicy = fresh;
        if (fresh.length !== (infra || []).length) {
          console.log(
            `[TUN] Infra IPv4 пересобран перед фазой B: ${fresh.length} адрес(ов) (STUN/TURN актуальны по DNS)`,
          );
        }
      }
    } catch (e) {
      console.warn(`[TUN] Повторный resolve infra перед фазой B не удался: ${e.message}`);
    }

    let ok = true;
    let splitScheduled = false;
    if (this._infraAppliedEarly) {
      if (this._splitDefaultOnlyDeferred && this.linuxSplitDefault) {
        const extraMs = this.linuxSplitDefaultDelayAfterPeerMs;
        if (extraMs > 0) {
          const snap = [...infraForPolicy];
          console.log(
            `[TUN] Split-default отложен на ${extraMs}ms (linuxSplitDefaultDelayAfterPeerMs)`,
          );
          this._splitDefaultDelayTimer = setTimeout(() => {
            this._splitDefaultDelayTimer = null;
            this._runDeferredSplitDefaultNow(snap);
          }, extraMs);
          splitScheduled = true;
        } else {
          console.log('[TUN] Добавление split-default (infra уже применена при поднятии TUN)');
          try {
            execSync(`ip route replace 0.0.0.0/1 dev ${this.name}`, { stdio: 'ignore' });
            execSync(`ip route replace 128.0.0.0/1 dev ${this.name}`, { stdio: 'ignore' });
          } catch (err) {
            console.warn('[TUN] Deferred split-default failed:', err.message);
            ok = false;
          }
          if (this.linuxFlushRouteCache) {
            try {
              execFileSync('ip', ['route', 'flush', 'cache'], { stdio: 'ignore' });
            } catch {
              /* ignore */
            }
          } else {
            console.log('[TUN] linuxFlushRouteCache=false: пропуск ip route flush cache');
          }
        }
      }
      if (!splitScheduled) {
        this._splitDefaultOnlyDeferred = false;
        if (infraForPolicy.length > 0) {
          this._diagInfraSnapshot = [...infraForPolicy];
        }
      }
    } else {
      ok = this._setupLinuxPolicyRouting(infraForPolicy, prefix, {
        applySplitDefault: this.linuxSplitDefault,
      });
    }

    if (splitScheduled) {
      return;
    }

    if (!ok || !this._linuxPolicyRoutingActive) {
      console.warn(
        '[TUN] Deferred full tunnel setup failed; DNS остаётся как до peer-connected, повтор при следующем peer-connected',
      );
      return;
    }

    this._finalizeDeferredPolicyRoutingTail(infraForPolicy);
  }

  /**
   * @param {number|null} linuxRouteTable  If set (Linux policy routing), add DNS /32 routes in this table only.
   */
  _configureDNS(linuxRouteTable = null) {
    const dnsServers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'];
    const tableSuffix =
      linuxRouteTable != null ? ` table ${linuxRouteTable}` : '';

    try {
      for (const dns of dnsServers) {
        try {
          const dnsArgs =
            linuxRouteTable != null
              ? ['route', 'add', `${dns}/32`, 'dev', this.name, 'table', String(linuxRouteTable)]
              : ['route', 'add', `${dns}/32`, 'dev', this.name];
          execFileSync('ip', dnsArgs, { stdio: 'ignore' });
        } catch {
          // Route may already exist
        }
      }
      console.log(
        `Added routes for DNS servers via ${this.name}` +
          (linuxRouteTable != null ? ` (table ${linuxRouteTable})` : '')
      );
      
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
   * Parse first IPv4 default route: `default via G dev I` or `default dev I`.
   * @returns {{ gateway: string|null, iface: string } | null}
   */
  _parseLinuxDefaultUplink() {
    const routeOutput = execSync('ip route show default', { encoding: 'utf8' });
    const routes = routeOutput.trim().split('\n').filter((r) => r.length > 0);
    const line = routes[0];
    if (!line) return null;
    let m = line.match(/default via (\S+)\s+dev\s+(\S+)/);
    if (m) {
      return { gateway: m[1], iface: m[2] };
    }
    m = line.match(/default\s+dev\s+(\S+)/);
    if (m) {
      return { gateway: null, iface: m[1] };
    }
    return null;
  }

  /**
   * Предпочтительный IPv4 source на uplink до split-default (после tun0 ядро может выбрать 10.x с tun
   * для исходящего UDP к TURN — ICE рвётся).
   * @param {string} iface
   * @returns {string|null}
   */
  _parseLinuxPreferredUplinkSrc(iface) {
    if (!iface) {
      return null;
    }
    try {
      const out = execFileSync('ip', ['-4', 'route', 'get', '8.8.8.8'], {
        encoding: 'utf8',
      });
      if (!out.includes(`dev ${iface}`)) {
        return null;
      }
      const m = out.match(/\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})\b/);
      return m ? m[1] : null;
    } catch {
      return null;
    }
  }

  _ipRoute(action, ip, gateway, iface, opts = {}) {
    const args = ['route', action, `${ip}/32`];
    if (gateway != null) args.push('via', gateway);
    args.push('dev', iface);
    if (opts.tableId) args.push('table', String(opts.tableId));
    if (opts.src) args.push('src', opts.src);
    execFileSync('ip', args, { stdio: 'ignore' });
  }

  /**
   * Full tunnel на Linux: при linuxSplitDefault — split default в main (0.0.0.0/1 и 128.0.0.0/1 → tun);
   * иначе только mesh /16 + infra /32 в main. table 100 — uplink для fwmark (SSH). TURN — /32+prefsrc в main.
   * @param {string[]} infraIpv4
   * @param {string} networkPrefix e.g. "10.200"
   * @returns {boolean}
   */
  _setupLinuxPolicyRouting(infraIpv4, networkPrefix, options = {}) {
    const applySplitDefault = options.applySplitDefault !== false;
    const flushCache =
      options.flushCache === undefined ? this.linuxFlushRouteCache : options.flushCache;
    const uplink = this._parseLinuxDefaultUplink();
    if (!uplink) {
      console.warn('[TUN] Could not parse default route; policy routing not configured');
      return false;
    }
    const { gateway, iface } = uplink;
    const tbl = LINUX_RT_TABLE_MESHVPN;
    const prefsrc = this._parseLinuxPreferredUplinkSrc(iface);
    if (prefsrc) {
      console.log(`[TUN] Infra /32 prefsrc=${prefsrc} (uplink ${iface})`);
    }

    try {
      flushIpRulePref(LINUX_IP_RULE_PREF_LOOKUP_MESHVPN_LEGACY);
      flushIpRulePref(LINUX_IP_RULE_PREF_FWMARK_MAIN);
      // Сброс infra-to правил от предыдущего запуска (до 32 IP)
      flushIpRulePref(LINUX_IP_RULE_PREF_INFRA_TO, 32);

      try {
        execSync(`ip route flush table ${tbl}`, { stdio: 'ignore' });
      } catch {
        /* ignore */
      }

      const excludeSet = new Set();
      for (const ip of infraIpv4) {
        if (!isIpv4UplinkBypassSafe(ip)) {
          if (ip && IPV4_RE.test(ip)) {
            console.log(`[TUN] Skip uplink bypass for ${ip} (loopback or link-local)`);
          }
          continue;
        }
        excludeSet.add(ip);
      }
      const cloudImds = '169.254.169.254';
      if (isIpv4UplinkBypassSafe(cloudImds)) {
        excludeSet.add(cloudImds);
      }
      this._linuxMainInfraRoutes = [...excludeSet];

      for (const ip of excludeSet) {
        try {
          this._ipRoute('add', ip, gateway, iface, { tableId: tbl, src: prefsrc });
        } catch {
          /* ignore */
        }
      }

      if (gateway != null) {
        execSync(
          `ip route replace default via ${gateway} dev ${iface} table ${tbl}`,
          { stdio: 'ignore' },
        );
      } else {
        execSync(`ip route replace default dev ${iface} table ${tbl}`, { stdio: 'ignore' });
      }

      for (const ip of excludeSet) {
        try {
          this._ipRoute('replace', ip, gateway, iface, { src: prefsrc });
          console.log(`[TUN] Main bypass /32 (uplink) for infra: ${ip}`);
        } catch {
          /* ignore */
        }
      }

      // Policy rule bypass для TURN/signalling: `ip rule to IP/32 pref 50 lookup 100`.
      // Срабатывает до routing table → не зависит от per-socket route cache.
      // Именно это решает проблему: при добавлении 0.0.0.0/1 в main ядро инвалидирует
      // route cache на открытых UDP-сокетах WebRTC/TURN, но policy rules пересматриваются
      // при каждом lookup — ICE consent freshness (каждые ~5s) и медиа UDP идут через uplink.
      for (const ip of excludeSet) {
        try {
          execSync(
            `ip rule add to ${ip}/32 pref ${LINUX_IP_RULE_PREF_INFRA_TO} lookup ${tbl}`,
            { stdio: 'ignore' },
          );
          console.log(`[TUN] ip rule to ${ip}/32 pref ${LINUX_IP_RULE_PREF_INFRA_TO} → table ${tbl}`);
        } catch {
          /* ignore */
        }
      }

      if (this.linuxSplitDefault) {
        if (applySplitDefault) {
          execSync(`ip route replace 0.0.0.0/1 dev ${this.name}`, { stdio: 'ignore' });
          execSync(`ip route replace 128.0.0.0/1 dev ${this.name}`, { stdio: 'ignore' });
        } else {
          console.log('[TUN] split-default (0.0.0.0/1) отложен до peer-connected');
        }
      } else {
        console.log(
          '[TUN] linuxSplitDefault=false: пропуск 0.0.0.0/1 и 128.0.0.0/1 — дефолтный интернет остаётся на uplink',
        );
      }
      try {
        execSync(`ip route replace ${networkPrefix}.0.0/16 dev ${this.name}`, { stdio: 'ignore' });
      } catch { /* interface may be DOWN during early routing; kernel creates this route on ip addr add */ }

      execSync(
        `ip rule add pref ${LINUX_IP_RULE_PREF_FWMARK_MAIN} fwmark 0x${LINUX_FWMARK_BYPASS_MAIN.toString(16)} lookup ${tbl}`,
        { stdio: 'ignore' },
      );

      const ch = IPTABLES_CHAIN_MESHVPN;
      try {
        execFileSync('iptables', ['-t', 'mangle', '-N', ch], { stdio: 'ignore' });
      } catch {
        /* exists */
      }
      execSync(`iptables -t mangle -F ${ch}`, { stdio: 'ignore' });
      const mk = `0x${LINUX_FWMARK_BYPASS_MAIN.toString(16)}`;
      /* Не маркируем UDP/TURN в mangle: prefsrc + /32 в main достаточно; MARK меняет conntrack/ответный путь и рвёт ICE. */
      execSync(
        `iptables -t mangle -A ${ch} -p tcp -m tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j MARK --set-mark ${mk}`,
        { stdio: 'ignore' },
      );
      execSync(
        `iptables -t mangle -A ${ch} -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j MARK --set-mark ${mk}`,
        { stdio: 'ignore' },
      );
      try {
        execFileSync('iptables', ['-t', 'mangle', '-C', 'OUTPUT', '-j', ch], { stdio: 'ignore' });
      } catch {
        execSync(`iptables -t mangle -I OUTPUT 1 -j ${ch}`, { stdio: 'ignore' });
      }

      if (flushCache) {
        try {
          execFileSync('ip', ['route', 'flush', 'cache'], { stdio: 'ignore' });
        } catch {
          /* ignore */
        }
      } else if (!this.linuxFlushRouteCache) {
        console.log('[TUN] linuxFlushRouteCache=false: пропуск ip route flush cache');
      }

      this._linuxRpFilterBackup = applyLooseRpFilterForVpn([iface, this.name], '[TUN]');

      this._linuxPolicyRoutingActive = true;
      this._diagInfraSnapshot = Array.from(excludeSet);
      let splitPart;
      if (this.linuxSplitDefault) {
        splitPart = applySplitDefault
          ? `main 0.0.0.0/1+128.0.0.0/1 via ${this.name}, `
          : 'split-default отложен, ';
      } else {
        splitPart = 'без split-default в main, ';
      }
      console.log(
        `[TUN] Linux policy routing: ${splitPart}mesh ${networkPrefix}.0.0/16 via ${this.name}, infra /32 uplink; `
        + `table ${tbl} = uplink for fwmark ${LINUX_FWMARK_BYPASS_MAIN} (SSH)`,
      );
      return true;
    } catch (err) {
      console.warn('[TUN] Policy routing setup failed:', err.message);
      return false;
    }
  }

  _restoreLinuxPolicyRouting() {
    if (!this._linuxPolicyRoutingActive) {
      return;
    }
    this._infraAppliedEarly = false;
    this._splitDefaultOnlyDeferred = false;
    this._linuxPolicyRoutingActive = false;

    restoreRpFilterBackup(this._linuxRpFilterBackup, '[TUN]');
    this._linuxRpFilterBackup = null;

    const ch = IPTABLES_CHAIN_MESHVPN;
    try {
      execFileSync('iptables', ['-t', 'mangle', '-D', 'OUTPUT', '-j', ch], { stdio: 'ignore' });
    } catch { /* ignore */ }
    try {
      execFileSync('iptables', ['-t', 'mangle', '-F', ch], { stdio: 'ignore' });
    } catch { /* ignore */ }
    try {
      execFileSync('iptables', ['-t', 'mangle', '-X', ch], { stdio: 'ignore' });
    } catch { /* ignore */ }

    flushIpRulePref(LINUX_IP_RULE_PREF_LOOKUP_MESHVPN_LEGACY);
    flushIpRulePref(LINUX_IP_RULE_PREF_FWMARK_MAIN);
    flushIpRulePref(LINUX_IP_RULE_PREF_INFRA_TO, 32);

    if (this.name) {
      try {
        execFileSync(
          'ip',
          ['route', 'del', '0.0.0.0/1', 'dev', this.name],
          { stdio: 'ignore' },
        );
      } catch {
        /* ignore */
      }
      try {
        execFileSync(
          'ip',
          ['route', 'del', '128.0.0.0/1', 'dev', this.name],
          { stdio: 'ignore' },
        );
      } catch {
        /* ignore */
      }
    }

    if (Array.isArray(this._linuxMainInfraRoutes)) {
      for (const ip of this._linuxMainInfraRoutes) {
        if (ip && IPV4_RE.test(ip)) {
          try {
            execFileSync('ip', ['route', 'del', `${ip}/32`], { stdio: 'ignore' });
          } catch {
            /* ignore */
          }
        }
      }
    }
    this._linuxMainInfraRoutes = null;

    try {
      execSync(`ip route flush table ${LINUX_RT_TABLE_MESHVPN}`, { stdio: 'ignore' });
    } catch {
      /* ignore */
    }

    console.log('[TUN] Linux policy routing restored');
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
      this._clearSplitDefaultDelayTimer();
      this._clearDeferDnsTimer();
      this._restoreLinuxPolicyRouting();
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

  /**
   * Linux early setup: создать tun0 и применить routing (включая split-default) к DOWN-интерфейсу
   * ДО подключения к signalling. Вызывать из MeshNode.start() перед discovery.start().
   * После этого вызвать setup(virtualIp) когда сервер назначит IP.
   */
  async setupEarly() {
    this.tun = new TunInterface({ ...this.config, virtualIp: null });
    this.tun.on('packet', (packet) => { this.emit('outbound-packet', packet); });
    this.tun.on('error', (err) => { this.emit('error', err); });
    await this.tun.openEarly();
  }

  async setup(virtualIp) {
    this.virtualIp = virtualIp;

    if (this.tun) {
      // setupEarly() был вызван: устройство создано, применяем только IP + bring up
      this.tun.virtualIp = virtualIp;
      try {
        await this.tun.assignIpAndBringUp(virtualIp);
        console.log(`TUN interface ${this.tun.name} configured with IP ${virtualIp}`);
      } catch (err) {
        console.error('Failed to configure TUN IP:', err.message);
        this.tun = null;
      }
      return this.tun !== null;
    }

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

  /** Linux full tunnel (фаза B): после peer-connected; для WebRTC — с задержкой из node.js. */
  async applyDeferredPolicyRouting() {
    if (this.tun) {
      await this.tun.applyDeferredPolicyRouting();
    }
  }

  /** Снимок `ip route` / `ip rule` в лог (см. tun.logRouteDiag). */
  logRoutingDiag(reason) {
    if (this.tun) {
      this.tun.logRoutingDiag(reason);
    }
  }

  /** Отмена таймера отложенного split-default при обрыве peer до истечения задержки. */
  cancelDeferredSplitDefaultTimer() {
    if (this.tun) {
      this.tun.cancelDeferredSplitDefaultTimer();
    }
  }
}
