#!/usr/bin/env node
/**
 * Минимальный VPN поверх одного TCP/WebSocket/UDP/WebRTC (DataChannel) транспорта + Linux tun-helper.
 * Без шифрования и авторизации.
 *
 * Требования: Linux, sudo, `helpers/tun-helper` (cd helpers && make).
 *
 * Exit (VPS): tun + NAT в интернет, без split-default.
 * Client: tun + split-default (опция), маршрут к --server через uplink.
 *
 * Протокол (socket / http после преамбулы): uint32 BE + сырой IPv4-пакет (как tun-helper).
 * WebSocket / UDP: одно binary-сообщение или одна датаграмма = один IPv4-пакет (без префикса длины).
 * WebRTC: сигналинг по WebSocket на --server; один SCTP DataChannel — одно бинарное сообщение = один IPv4-пакет.
 * ICE/STUN/TURN: из --config (по умолчанию config/default.json), см. --ice-mode.
 *
 * Пример:
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=websocket
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=websocket --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:51820 --type=udp
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:51820 --type=udp --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:9876 --type=webrtc [--config=config/exit-node.json]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:9876 --type=webrtc --split-default
 *
 * При SIGINT/SIGTERM: снимаются iptables/NAT (exit), net.ipv4.ip_forward, маршруты и rp_filter (client)
 * восстанавливаются по снимку `ip -json route` (если доступен).
 */

import { spawn, execFileSync } from 'child_process';
import dgram from 'dgram';
import fs from 'fs';
import net from 'net';
import path from 'path';
import process from 'process';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import WebSocket from 'ws';
import dns from 'dns/promises';
import { PeerConnection, setSctpSettings } from 'node-datachannel';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const TUN_HELPER = path.join(__dirname, '../helpers/tun-helper');

const TUN_MTU = 1400;
const MAX_PKT = 65535;
const IP_EXIT = '10.99.0.1';
const IP_CLIENT = '10.99.0.2';

const SCTP_DEFAULTS = {
  recvBufferSize: 16 * 1024 * 1024,
  sendBufferSize: 16 * 1024 * 1024,
  maxChunksOnQueue: 32768,
  initialCongestionWindow: 65535,
  delayedSackTime: 2,
};

const DEFAULT_ICE_SERVERS_JSON = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

setSctpSettings(SCTP_DEFAULTS);

const DEFAULT_CONFIG_JSON = path.join(__dirname, '../config/default.json');

/** Как в src/transport/webrtc.js: объекты конфига → строки для node-datachannel. */
function convertIceServers(servers, iceMode) {
  const result = [];
  for (const s of servers) {
    const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
    for (const url of urls) {
      if (!url) continue;
      const isStun = url.startsWith('stun:');
      const isTurn = url.startsWith('turn:') || url.startsWith('turns:');

      if (iceMode === 'relay' && isStun) continue;
      if (iceMode === 'direct' && isTurn) continue;

      if (isTurn && (s.username || s.credential)) {
        const proto = url.startsWith('turns:') ? 'turns' : 'turn';
        const addr = url.replace(/^turns?:/, '');
        result.push(`${proto}:${s.username}:${s.credential}@${addr}`);
      } else {
        result.push(url);
      }
    }
  }
  return result;
}

/**
 * @param {string|null|undefined} configPath — путь к JSON или null → default.json рядом с репо
 * @param {string|null|undefined} cliIceMode — перекрывает iceMode из файла
 */
function loadWebrtcIceFromConfig(configPath, cliIceMode) {
  const resolved = configPath
    ? path.resolve(configPath)
    : DEFAULT_CONFIG_JSON;
  if (!fs.existsSync(resolved)) {
    throw new Error(`Нет файла конфигурации ICE: ${resolved}`);
  }
  const json = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const iceFromFile = json.iceMode || 'auto';
  const iceMode =
    cliIceMode && ['auto', 'relay', 'direct'].includes(cliIceMode)
      ? cliIceMode
      : iceFromFile;
  const raw = [...(json.iceServers || []), ...(json.turnServers || [])];
  const merged = raw.length ? raw : DEFAULT_ICE_SERVERS_JSON;
  const ndcIceServers = convertIceServers(merged, iceMode);
  if (!ndcIceServers.length) {
    throw new Error('После convertIceServers список ICE пуст; проверьте iceMode и turnServers');
  }
  return { ndcIceServers, iceMode, configPath: resolved };
}

function parseArgs(argv) {
  const out = {
    role: null,
    server: null,
    type: null,
    splitDefault: false,
    extIface: null,
    configPath: null,
    iceMode: null,
  };
  for (const a of argv) {
    if (a.startsWith('--role=')) out.role = a.slice('--role='.length);
    else if (a.startsWith('--server=')) out.server = a.slice('--server='.length);
    else if (a.startsWith('--type=')) out.type = a.slice('--type='.length);
    else if (a.startsWith('--ext=')) out.extIface = a.slice('--ext='.length);
    else if (a.startsWith('--config=')) out.configPath = a.slice('--config='.length);
    else if (a.startsWith('--ice-mode=')) out.iceMode = a.slice('--ice-mode='.length);
    else if (a === '--split-default') out.splitDefault = true;
  }
  return out;
}

function parseHostPort(s) {
  const m = String(s).match(/^(.+):(\d+)$/);
  if (!m) throw new Error(`Неверный --server=${s}, ожидается host:port`);
  return { host: m[1], port: parseInt(m[2], 10) };
}

function getDefaultRouteLinux() {
  try {
    const out = execFileSync('ip', ['-4', 'route', 'show', 'default'], { encoding: 'utf8' });
    const line = out.trim().split('\n')[0] || '';
    const via = line.match(/default via (\S+)/);
    const dev = line.match(/dev (\S+)/);
    if (via && dev) return { gw: via[1], dev: dev[1] };
    if (dev) return { gw: null, dev: dev[1] };
  } catch {
    /* ignore */
  }
  return null;
}

function getSysctlNum(key) {
  try {
    const v = execFileSync('sysctl', ['-n', key], { encoding: 'utf8' }).trim();
    const n = parseInt(v, 10);
    return Number.isNaN(n) ? null : n;
  } catch {
    return null;
  }
}

/** Записи table main с данным dst (как в `ip -json route list`). */
function captureRoutesByDst(dst) {
  try {
    const out = execFileSync('ip', ['-4', '-json', 'route', 'list', 'table', 'main'], {
      encoding: 'utf8',
    });
    const arr = JSON.parse(out);
    return arr.filter((r) => r.dst === dst);
  } catch {
    return [];
  }
}

function captureServerRoutes(serverIp) {
  const a = captureRoutesByDst(`${serverIp}/32`);
  if (a.length) return a;
  return captureRoutesByDst(serverIp);
}

function ipRouteAddFromRecord(r) {
  if (!r?.dst) return;
  const args = ['route', 'add', r.dst];
  if (r.gateway) args.push('via', r.gateway);
  if (r.prefsrc) args.push('src', r.prefsrc);
  if (r.dev) args.push('dev', r.dev);
  if (typeof r.metric === 'number') args.push('metric', String(r.metric));
  if (r.scope && r.scope !== 'global') args.push('scope', r.scope);
  execFileSync('ip', args, { stdio: 'inherit' });
}

function restoreRoutesFromRecords(records) {
  for (const r of records) {
    try {
      ipRouteAddFromRecord(r);
    } catch {
      /* ignore */
    }
  }
}

function tryIpRoute(args) {
  try {
    execFileSync('ip', args, { stdio: 'inherit' });
  } catch {
    /* ignore */
  }
}

function findFreeTunName() {
  try {
    const out = execFileSync('ip', ['link', 'show'], { encoding: 'utf8' });
    const used = new Set();
    for (const m of out.matchAll(/tun(\d+):/g)) used.add(parseInt(m[1], 10));
    let i = 0;
    while (used.has(i)) i += 1;
    return `tun${i}`;
  } catch {
    return 'tun0';
  }
}

class StreamFramer {
  constructor() {
    this.buf = Buffer.alloc(0);
  }

  push(chunk, onPacket) {
    this.buf = Buffer.concat([this.buf, chunk]);
    while (this.buf.length >= 4) {
      const len = this.buf.readUInt32BE(0);
      if (len <= 0 || len > MAX_PKT) {
        this.buf = Buffer.alloc(0);
        throw new Error(`bad frame length ${len}`);
      }
      if (this.buf.length < 4 + len) return;
      const pkt = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      onPacket(Buffer.from(pkt));
    }
  }
}

function writeFramed(sock, pkt) {
  const h = Buffer.alloc(4);
  h.writeUInt32BE(pkt.length, 0);
  return sock.write(Buffer.concat([h, pkt]));
}

function spawnTun(tunName) {
  if (!fs.existsSync(TUN_HELPER)) {
    throw new Error(`Нет ${TUN_HELPER}. Соберите: cd helpers && make`);
  }
  const child = spawn(TUN_HELPER, [tunName], { stdio: ['pipe', 'pipe', 'pipe'] });
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => {
      child.kill();
      reject(new Error('tun-helper timeout'));
    }, 5000);
    child.stderr.once('data', (d) => {
      clearTimeout(to);
      const name = d.toString().trim();
      if (name.startsWith('ERROR')) {
        reject(new Error(name));
        return;
      }
      resolve({ child, name });
    });
    child.on('error', reject);
  });
}

function ip(args) {
  execFileSync('ip', args, { stdio: 'inherit' });
}

function sysctlForward(on) {
  try {
    execFileSync('sysctl', [`net.ipv4.ip_forward=${on ? 1 : 0}`], { stdio: 'inherit' });
  } catch {
    console.warn('[clean-vpn] sysctl ip_forward не применён');
  }
}

function setupTunIp(role, ifname) {
  if (role === 'exit') {
    ip(['addr', 'flush', 'dev', ifname]);
    ip(['addr', 'add', `${IP_EXIT}/32`, 'peer', `${IP_CLIENT}/32`, 'dev', ifname]);
  } else {
    ip(['addr', 'flush', 'dev', ifname]);
    ip(['addr', 'add', `${IP_CLIENT}/32`, 'peer', `${IP_EXIT}/32`, 'dev', ifname]);
  }
  ip(['link', 'set', 'dev', ifname, 'mtu', String(TUN_MTU), 'up']);
}

async function setupClientRoutesAsync(ifname, serverHost, splitDefault) {
  const dr = getDefaultRouteLinux();
  if (!dr) throw new Error('Не найден default route (ip route show default)');
  const { gw, dev } = dr;

  let serverIp = serverHost;
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(serverHost)) {
    serverIp = (await dns.lookup(serverHost, { family: 4 })).address;
  }

  const prevRpAll = getSysctlNum('net.ipv4.conf.all.rp_filter');
  const snapHost = captureServerRoutes(serverIp);
  const snap01 = splitDefault ? [...captureRoutesByDst('0.0.0.0/1')] : [];
  const snap128 = splitDefault ? [...captureRoutesByDst('128.0.0.0/1')] : [];

  console.log(`[clean-vpn] bypass маршрут к серверу ${serverIp} через ${dev}`);
  if (gw) {
    ip(['route', 'replace', `${serverIp}/32`, 'via', gw, 'dev', dev]);
  } else {
    ip(['route', 'replace', `${serverIp}/32`, 'dev', dev]);
  }

  if (splitDefault) {
    ip(['route', 'replace', '0.0.0.0/1', 'dev', ifname]);
    ip(['route', 'replace', '128.0.0.0/1', 'dev', ifname]);
    console.log('[clean-vpn] split-default (0.0.0.0/1 + 128.0.0.0/1) через', ifname);
  }
  try {
    execFileSync('sysctl', ['net.ipv4.conf.all.rp_filter=2'], { stdio: 'inherit' });
  } catch {
    /* ignore */
  }

  return {
    serverIp,
    gw,
    dev,
    splitDefault,
    prevRpAll,
    snapHost,
    snap01,
    snap128,
    ifname,
  };
}

function teardownClientRoutes(ctx) {
  if (!ctx) return;
  const { serverIp, gw, dev, splitDefault, prevRpAll, snapHost, snap01, snap128, ifname } = ctx;

  if (splitDefault) {
    tryIpRoute(['route', 'del', '0.0.0.0/1', 'dev', ifname]);
    tryIpRoute(['route', 'del', '128.0.0.0/1', 'dev', ifname]);
    restoreRoutesFromRecords(snap01);
    restoreRoutesFromRecords(snap128);
  }

  if (gw) {
    tryIpRoute(['route', 'del', `${serverIp}/32`, 'via', gw, 'dev', dev]);
  } else {
    tryIpRoute(['route', 'del', `${serverIp}/32`, 'dev', dev]);
  }
  restoreRoutesFromRecords(snapHost);

  if (prevRpAll != null) {
    try {
      execFileSync('sysctl', [`net.ipv4.conf.all.rp_filter=${prevRpAll}`], { stdio: 'inherit' });
    } catch {
      /* ignore */
    }
  }
  console.log('[clean-vpn] client: маршруты и rp_filter восстановлены');
}

function setupExitNat(tunName, extIface) {
  const prevIpForward = getSysctlNum('net.ipv4.ip_forward');
  sysctlForward(true);
  const ext = extIface || getDefaultRouteLinux()?.dev;
  if (!ext) throw new Error('Укажите --ext=eth0 или настройте default route');
  console.log(`[clean-vpn] NAT: ${tunName} -> ${ext} (MASQUERADE)`);
  execFileSync(
    'iptables',
    ['-t', 'nat', '-A', 'POSTROUTING', '-s', `${IP_CLIENT}/32`, '-o', ext, '-j', 'MASQUERADE'],
    { stdio: 'inherit' },
  );
  execFileSync('iptables', ['-A', 'FORWARD', '-i', tunName, '-o', ext, '-j', 'ACCEPT'], {
    stdio: 'inherit',
  });
  execFileSync(
    'iptables',
    [
      '-A',
      'FORWARD',
      '-i',
      ext,
      '-o',
      tunName,
      '-m',
      'conntrack',
      '--ctstate',
      'RELATED,ESTABLISHED',
      '-j',
      'ACCEPT',
    ],
    { stdio: 'inherit' },
  );
  return { ext, tunName, prevIpForward };
}

function restoreExitSysctl(prevIpForward) {
  if (prevIpForward == null) return;
  try {
    execFileSync('sysctl', [`net.ipv4.ip_forward=${prevIpForward}`], { stdio: 'inherit' });
    console.log('[clean-vpn] exit: net.ipv4.ip_forward восстановлен');
  } catch {
    /* ignore */
  }
}

function teardownExitNat(tunName, ext) {
  try {
    execFileSync(
      'iptables',
      ['-t', 'nat', '-D', 'POSTROUTING', '-s', `${IP_CLIENT}/32`, '-o', ext, '-j', 'MASQUERADE'],
      { stdio: 'inherit' },
    );
  } catch {
    /* ignore */
  }
  try {
    execFileSync('iptables', ['-D', 'FORWARD', '-i', tunName, '-o', ext, '-j', 'ACCEPT'], {
      stdio: 'inherit',
    });
  } catch {
    /* ignore */
  }
  try {
    execFileSync(
      'iptables',
      [
        '-D',
        'FORWARD',
        '-i',
        ext,
        '-o',
        tunName,
        '-m',
        'conntrack',
        '--ctstate',
        'RELATED,ESTABLISHED',
        '-j',
        'ACCEPT',
      ],
      { stdio: 'inherit' },
    );
  } catch {
    /* ignore */
  }
}

/**
 * Один активный мост на tun-helper: иначе второй TCP-клиент на exit вешает второй
 * listener на stdout и пакеты дублируются / рассинхрон.
 *
 * @param {'tcp'|'websocket'|'udp-client'|'udp-server'|'webrtc-dc'} transport
 * @param {import('net').Socket|import('ws')|import('dgram').Socket|{sock: import('dgram').Socket, peer?: import('dgram').RemoteInfo}|import('node-datachannel').DataChannel} endpoint
 */
function attachTunBridge(child, transport, endpoint) {
  child.stdout.removeAllListeners('data');
  child.stdout.removeAllListeners('end');

  const framer = new StreamFramer();
  let tunInBuf = Buffer.alloc(0);

  const writeTun = (pkt) => {
    const h = Buffer.alloc(4);
    h.writeUInt32BE(pkt.length, 0);
    if (!child.stdin.write(Buffer.concat([h, pkt]))) {
      child.stdin.once('drain', () => {});
    }
  };

  /** @type {Buffer[]} */
  const dcQueue = [];
  const DC_BUFFER_HIGH = 8 * 1024 * 1024;
  let dcPumpScheduled = false;
  const pumpDcQueue = () => {
    dcPumpScheduled = false;
    if (transport !== 'webrtc-dc') return;
    while (dcQueue.length) {
      if (typeof endpoint.isOpen === 'function' && !endpoint.isOpen()) return;
      let buffered = 0;
      try {
        buffered =
          typeof endpoint.bufferedAmount === 'function' ? endpoint.bufferedAmount() : 0;
      } catch {
        buffered = 0;
      }
      if (buffered > DC_BUFFER_HIGH) {
        dcPumpScheduled = true;
        setImmediate(pumpDcQueue);
        return;
      }
      const pkt = dcQueue.shift();
      if (!pkt) break;
      try {
        endpoint.sendMessageBinary(pkt);
      } catch (e) {
        console.error('[clean-vpn] webrtc-dc send:', e?.message || e);
      }
    }
  };

  const sendOnWire = (pkt) => {
    if (transport === 'websocket') {
      endpoint.send(pkt);
    } else if (transport === 'tcp') {
      writeFramed(endpoint, pkt);
    } else if (transport === 'udp-client') {
      if (pkt.length > 65507) {
        console.warn('[clean-vpn] udp: пакет больше типичного MTU датаграммы');
      }
      endpoint.send(pkt, (err) => {
        if (err) console.error('[clean-vpn] udp send:', err.message);
      });
    } else if (transport === 'udp-server') {
      const pr = endpoint.peer;
      if (!pr) return;
      if (pkt.length > 65507) return;
      endpoint.sock.send(pkt, pr.port, pr.address, (err) => {
        if (err) console.error('[clean-vpn] udp send:', err.message);
      });
    } else if (transport === 'webrtc-dc') {
      dcQueue.push(pkt);
      if (!dcPumpScheduled) {
        dcPumpScheduled = true;
        setImmediate(pumpDcQueue);
      }
    }
  };

  child.stdout.on('data', (d) => {
    tunInBuf = Buffer.concat([tunInBuf, d]);
    while (tunInBuf.length >= 4) {
      const len = tunInBuf.readUInt32BE(0);
      if (len <= 0 || len > MAX_PKT) {
        tunInBuf = Buffer.alloc(0);
        return;
      }
      if (tunInBuf.length < 4 + len) return;
      const pkt = Buffer.from(tunInBuf.subarray(4, 4 + len));
      tunInBuf = tunInBuf.subarray(4 + len);
      sendOnWire(pkt);
    }
  });

  if (transport === 'websocket') {
    endpoint.on('message', (data, isBinary) => {
      if (!isBinary) return;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      writeTun(buf);
    });
  } else if (transport === 'tcp') {
    endpoint.on('data', (chunk) => {
      try {
        framer.push(chunk, writeTun);
      } catch (e) {
        console.error('[clean-vpn] framing error:', e.message);
        endpoint.destroy();
      }
    });
  } else if (transport === 'udp-client') {
    endpoint.on('message', (msg) => {
      if (!msg.length || msg.length > MAX_PKT) return;
      writeTun(Buffer.from(msg));
    });
  } else if (transport === 'udp-server') {
    endpoint.sock.on('message', (msg, rinfo) => {
      if (!msg.length || msg.length > MAX_PKT) return;
      if (!endpoint.peer) {
        endpoint.peer = rinfo;
        console.log(`[clean-vpn] udp peer ${rinfo.address}:${rinfo.port}`);
      } else if (
        endpoint.peer.address !== rinfo.address ||
        endpoint.peer.port !== rinfo.port
      ) {
        return;
      }
      writeTun(Buffer.from(msg));
    });
  } else if (transport === 'webrtc-dc') {
    endpoint.onMessage((data) => {
      if (typeof data === 'string') return;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (!buf.length || buf.length > MAX_PKT) return;
      writeTun(buf);
    });
  }

  child.stdout.on('end', () => process.exit(0));
  child.on('close', () => process.exit(0));
}

function handleHttpSocket(sock, onReady) {
  const onData = (chunk) => {
    const buf = sock.__httpBuf ? Buffer.concat([sock.__httpBuf, chunk]) : chunk;
    const idx = buf.indexOf('\r\n\r\n');
    if (idx === -1) {
      sock.__httpBuf = buf;
      return;
    }
    const rest = buf.subarray(idx + 4);
    delete sock.__httpBuf;
    sock.off('data', onData);
    if (sock.__isServer) {
      const res =
        'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n';
      sock.write(res);
    }
    onReady(rest);
  };
  sock.on('data', onData);
}

async function runExit({ server, type, extIface, configPath, iceMode }) {
  const { host, port } = parseHostPort(server);
  const tunName = findFreeTunName();
  const { child, name: ifname } = await spawnTun(tunName);
  setupTunIp('exit', ifname);
  const nat = setupExitNat(ifname, extIface);

  /** @type {import('net').Socket|null} */
  let activeTcp = null;
  /** @type {import('ws').WebSocketServer|null} */
  let wss = null;
  /** @type {import('net').Server|null} */
  let tcpSrv = null;
  /** @type {import('dgram').Socket|null} */
  let udpSock = null;
  /** @type {import('node-datachannel').PeerConnection|null} */
  let webrtcPc = null;
  let shuttingDown = false;

  const startBridge = (sock, restBuf, transport) => {
    if (transport === 'tcp' && activeTcp && !activeTcp.destroyed) {
      activeTcp.destroy();
    }
    if (transport === 'tcp') activeTcp = sock;
    attachTunBridge(child, transport, sock);
    if (restBuf && restBuf.length && transport === 'tcp') {
      sock.emit('data', restBuf);
    }
  };

  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      if (webrtcPc) {
        webrtcPc.destroy();
        webrtcPc = null;
      }
    } catch {
      /* ignore */
    }
    try {
      if (wss) {
        wss.close();
        wss = null;
      }
    } catch {
      /* ignore */
    }
    try {
      if (tcpSrv) {
        tcpSrv.close();
        tcpSrv = null;
      }
    } catch {
      /* ignore */
    }
    try {
      if (udpSock) {
        udpSock.close();
        udpSock = null;
      }
    } catch {
      /* ignore */
    }
    try {
      if (activeTcp && !activeTcp.destroyed) {
        activeTcp.destroy();
      }
    } catch {
      /* ignore */
    }
    teardownExitNat(nat.tunName, nat.ext);
    restoreExitSysctl(nat.prevIpForward);
    try {
      child.stdin.end();
      child.kill('SIGTERM');
    } catch {
      /* ignore */
    }
    console.log('[clean-vpn] exit: остановка');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  if (type === 'websocket') {
    wss = new WebSocketServer({ host, port });
    wss.on('listening', () => {
      console.log(`[clean-vpn] exit WebSocket ws://${host === '0.0.0.0' ? '*' : host}:${port}/`);
    });
    wss.on('connection', (ws) => {
      console.log('[clean-vpn] ws client connected');
      wss.clients.forEach((c) => {
        if (c !== ws) c.close();
      });
      startBridge(ws, null, 'websocket');
    });
    return;
  }

  if (type === 'socket' || type === 'http') {
    tcpSrv = net
      .createServer((sock) => {
        console.log('[clean-vpn] tcp connected', sock.remoteAddress);
        if (type === 'socket') {
          startBridge(sock, null, 'tcp');
          return;
        }
        sock.__isServer = true;
        handleHttpSocket(sock, (rest) => startBridge(sock, rest, 'tcp'));
      })
      .listen(port, host, () => {
        console.log(`[clean-vpn] exit ${type} listening ${host}:${port}`);
      });
    return;
  }

  if (type === 'udp') {
    udpSock = dgram.createSocket('udp4');
    udpSock.on('error', (err) => {
      console.error('[clean-vpn] udp socket error:', err.message);
    });
    const udpEp = { sock: udpSock, peer: undefined };
    udpSock.bind(port, host, () => {
      console.log(`[clean-vpn] exit UDP ${host}:${port} (один peer по первому пакету)`);
    });
    attachTunBridge(child, 'udp-server', udpEp);
    return;
  }

  if (type === 'webrtc') {
    const ice = loadWebrtcIceFromConfig(configPath, iceMode);
    console.log(
      `[clean-vpn] webrtc exit: ICE mode=${ice.iceMode}, серверов=${ice.ndcIceServers.length}, конфиг=${ice.configPath}`,
    );
    for (const s of ice.ndcIceServers) {
      console.log(`[clean-vpn]   - ${s.replace(/:[^:@]+@/, ':***@')}`);
    }
    wss = new WebSocketServer({ host, port });
    wss.on('listening', () => {
      console.log(
        `[clean-vpn] exit webrtc сигналинг ws://${host === '0.0.0.0' ? '*' : host}:${port}/ (ждём clean-vpn-ready)`,
      );
    });
    wss.on('connection', (ws) => {
      wss.clients.forEach((c) => {
        if (c !== ws) c.close();
      });
      if (webrtcPc) {
        try {
          webrtcPc.destroy();
        } catch {
          /* ignore */
        }
        webrtcPc = null;
      }

      let handshakeDone = false;
      /** @type {import('node-datachannel').PeerConnection|null} */
      let connPc = null;

      const signal = (msg) => {
        if (ws.readyState === WebSocket.OPEN) {
          try {
            ws.send(JSON.stringify(msg));
          } catch {
            /* ignore */
          }
        }
      };

      const handleSignal = (msg) => {
        if (!connPc) return;
        if (msg.type === 'offer') connPc.setRemoteDescription(msg.sdp, 'Offer');
        else if (msg.type === 'answer') connPc.setRemoteDescription(msg.sdp, 'Answer');
        else if (msg.type === 'candidate') {
          try {
            connPc.addRemoteCandidate(msg.candidate, msg.mid || '0');
          } catch (e) {
            console.warn('[clean-vpn] addRemoteCandidate:', e?.message || e);
          }
        }
      };

      const setupInitiator = () => {
        if (handshakeDone) return;
        handshakeDone = true;
        connPc = new PeerConnection('clean-vpn-exit', {
          iceServers: ice.ndcIceServers,
          maxMessageSize: 65536,
          ...(ice.iceMode === 'relay' ? { iceTransportPolicy: 'relay' } : {}),
        });
        webrtcPc = connPc;

        connPc.onLocalDescription((sdp, t) => {
          signal({ type: String(t).toLowerCase(), sdp });
        });
        connPc.onLocalCandidate((candidate, mid) => {
          signal({ type: 'candidate', candidate, mid });
        });
        connPc.onStateChange((state) => {
          console.log('[clean-vpn] webrtc exit PC:', state);
        });

        const dc = connPc.createDataChannel('clean-vpn');
        dc.onOpen(() => {
          console.log('[clean-vpn] DataChannel open (exit)');
          attachTunBridge(child, 'webrtc-dc', dc);
        });
        dc.onClosed(() => {
          console.log('[clean-vpn] DataChannel closed (exit)');
        });
        dc.onError((err) => {
          console.error('[clean-vpn] DataChannel error (exit):', err);
        });
      };

      ws.on('message', (data, isBinary) => {
        if (isBinary) return;
        let msg;
        try {
          msg = JSON.parse(data.toString());
        } catch {
          return;
        }
        if (msg.type === 'clean-vpn-ready' && !handshakeDone) {
          setupInitiator();
          return;
        }
        handleSignal(msg);
      });

      ws.on('close', () => {
        if (connPc && webrtcPc === connPc) {
          try {
            webrtcPc.destroy();
          } catch {
            /* ignore */
          }
          webrtcPc = null;
          connPc = null;
        }
      });

      ws.on('error', (err) => {
        console.error('[clean-vpn] webrtc signalling ws:', err.message);
      });
    });
    return;
  }

  throw new Error(`Неизвестный --type=${type}`);
}

async function runClient({ server, type, splitDefault, configPath, iceMode }) {
  const { host, port } = parseHostPort(server);
  const tunName = findFreeTunName();
  const { child, name: ifname } = await spawnTun(tunName);
  setupTunIp('client', ifname);
  const routeCtx = await setupClientRoutesAsync(ifname, host, splitDefault);

  /** @type {import('node-datachannel').PeerConnection|null} */
  let webrtcPc = null;
  /** @type {import('ws').WebSocket|null} */
  let webrtcSigWs = null;

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      if (webrtcPc) {
        webrtcPc.destroy();
        webrtcPc = null;
      }
    } catch {
      /* ignore */
    }
    try {
      if (webrtcSigWs) {
        webrtcSigWs.close();
        webrtcSigWs = null;
      }
    } catch {
      /* ignore */
    }
    teardownClientRoutes(routeCtx);
    try {
      child.stdin.end();
      child.kill('SIGTERM');
    } catch {
      /* ignore */
    }
    console.log('[clean-vpn] client: остановка');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  if (type === 'websocket') {
    const url = `ws://${host}:${port}/`;
    const ws = new WebSocket(url);
    ws.binaryType = 'nodebuffer';
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
    console.log('[clean-vpn] WebSocket connected');
    attachTunBridge(child, 'websocket', ws);
    return;
  }

  if (type === 'udp') {
    const udp = dgram.createSocket('udp4');
    await new Promise((resolve, reject) => {
      udp.once('error', reject);
      udp.connect(port, host, () => {
        udp.off('error', reject);
        console.log(`[clean-vpn] UDP «connected» к ${host}:${port}`);
        attachTunBridge(child, 'udp-client', udp);
        resolve();
      });
    });
    return;
  }

  if (type === 'webrtc') {
    const ice = loadWebrtcIceFromConfig(configPath, iceMode);
    console.log(`[clean-vpn] webrtc client: ICE mode=${ice.iceMode}, конфиг=${ice.configPath}`);
    const url = `ws://${host}:${port}/`;
    webrtcSigWs = new WebSocket(url);

    await new Promise((resolve, reject) => {
      webrtcSigWs.once('open', resolve);
      webrtcSigWs.once('error', reject);
    });
    console.log('[clean-vpn] WebRTC сигналинг подключён');

    const signal = (msg) => {
      if (webrtcSigWs?.readyState === WebSocket.OPEN) {
        try {
          webrtcSigWs.send(JSON.stringify(msg));
        } catch {
          /* ignore */
        }
      }
    };

    const pcConfig = {
      iceServers: ice.ndcIceServers,
      maxMessageSize: 65536,
      ...(ice.iceMode === 'relay' ? { iceTransportPolicy: 'relay' } : {}),
    };
    webrtcPc = new PeerConnection('clean-vpn-client', pcConfig);

    webrtcPc.onLocalDescription((sdp, t) => {
      signal({ type: String(t).toLowerCase(), sdp });
    });
    webrtcPc.onLocalCandidate((candidate, mid) => {
      signal({ type: 'candidate', candidate, mid });
    });
    webrtcPc.onStateChange((state) => {
      console.log('[clean-vpn] webrtc client PC:', state);
    });

    webrtcPc.onDataChannel((dc) => {
      dc.onOpen(() => {
        console.log('[clean-vpn] DataChannel open (client)');
        attachTunBridge(child, 'webrtc-dc', dc);
      });
      dc.onError((err) => {
        console.error('[clean-vpn] DataChannel error (client):', err);
      });
    });

    webrtcSigWs.on('message', (data, isBinary) => {
      if (isBinary) return;
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      if (msg.type === 'offer') webrtcPc.setRemoteDescription(msg.sdp, 'Offer');
      else if (msg.type === 'answer') webrtcPc.setRemoteDescription(msg.sdp, 'Answer');
      else if (msg.type === 'candidate') {
        try {
          webrtcPc.addRemoteCandidate(msg.candidate, msg.mid || '0');
        } catch (e) {
          console.warn('[clean-vpn] addRemoteCandidate:', e?.message || e);
        }
      }
    });

    webrtcSigWs.on('error', (err) => {
      console.error('[clean-vpn] webrtc signalling ws:', err.message);
    });

    webrtcSigWs.send(JSON.stringify({ type: 'clean-vpn-ready' }));
    return;
  }

  await new Promise((resolve, reject) => {
    const sock = net.connect(port, host, () => {
      console.log('[clean-vpn] TCP connected');
      if (type === 'socket') {
        attachTunBridge(child, 'tcp', sock);
        resolve();
        return;
      }
      sock.__isServer = false;
      handleHttpSocket(sock, (rest) => {
        attachTunBridge(child, 'tcp', sock);
        if (rest && rest.length) {
          sock.emit('data', rest);
        }
        resolve();
      });
      sock.write(
        `GET /clean-vpn HTTP/1.1\r\nHost: ${host}\r\nConnection: keep-alive\r\n\r\n`,
      );
    });
    sock.on('error', reject);
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (process.platform !== 'linux') {
    console.error('Только Linux (tun-helper-linux).');
    process.exit(1);
  }
  if (!args.role || !args.server || !args.type) {
    console.error(`Использование:
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=socket [--ext=eth0]
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=HOST:8765 --type=socket --split-default

--type: socket | http | websocket | udp | webrtc
--split-default: только client, split 0.0.0.0/1 + 128.0.0.0/1 через tun
--ext: только exit, интерфейс в интернет для NAT (иначе из default route)
--config=PATH: для --type=webrtc — JSON с iceServers/turnServers (по умолчанию config/default.json от корня репо)
--ice-mode=auto|relay|direct: для webrtc — перекрывает iceMode из --config`);
    process.exit(1);
  }

  if (
    args.iceMode &&
    !['auto', 'relay', 'direct'].includes(args.iceMode)
  ) {
    console.error('[clean-vpn] --ice-mode должен быть auto | relay | direct');
    process.exit(1);
  }

  if (args.role === 'exit') {
    await runExit(args);
  } else if (args.role === 'client') {
    await runClient(args);
  } else {
    console.error('role: exit | client');
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
