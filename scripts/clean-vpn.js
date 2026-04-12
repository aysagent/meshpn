#!/usr/bin/env node
/**
 * Минимальный VPN поверх TCP/WebSocket/UDP/WebRTC/QUIC (node:quic / @infisical/quic) + Linux TUN (native N-API addon).
 * Без шифрования и авторизации.
 *
 * Требования: Linux, sudo, собранный addon `native/tun_linux` (`npm run build:tun-linux`; python3, make, g++).
 * После `npm install` addon собирается в postinstall (ошибка сборки не роняет install — тогда соберите вручную).
 * Основной mesh (`src/network/tun.js`) по-прежнему может использовать бинарь `helpers/tun-helper` из `cd helpers && make`.
 *
 * Exit (VPS): tun + NAT в интернет, без split-default.
 * Client: tun + split-default (опция, только IPv4 default), маршрут к --server через uplink.
 *
 * Протокол (socket / http после преамбулы): uint32 BE + сырой IPv4-пакет (как у прежнего tun-helper по транспорту).
 * WebSocket / UDP: одно binary-сообщение или одна датаграмма = один IPv4-пакет (без префикса длины).
 * WebRTC DataChannel через Puppeteer (--type=rtc-chrome): client — Chrome + RTCPeerConnection к exit `--type=webrtc`, сигналинг как у webrtc, TUN ↔ локальный WS; `npm install puppeteer`.
 * WebSocket через Puppeteer (--type=ws-chrome): на client Headless Chrome держит исходящий WS к exit; `npm install puppeteer`.
 *   По умолчанию данные идут через локальный ws://127.0.0.1 (без CDP на каждый пакет). Медленный путь: --ws-chrome-cdp-data или CLEAN_VPN_WS_CHROME_CDP_DATA=1.
 *   --ws-chrome-url=... (произвольная страница) — только CDP-путь. exit --type=ws-chrome + GET /clean-vpn-chrome; Puppeteer с --ws-chrome-exit-page без CDP использует setContent (тот же быстрый мост).
 *   Chrome: --ws-chrome-executable=PATH или PUPPETEER_EXECUTABLE_PATH; в контейнере: CLEAN_VPN_PUPPETEER_NO_SANDBOX=1
 *   Linux ARM64 (Multipass на Apple Silicon и т.п.): встроенный Chrome из кэша Puppeteer часто ломается — ставьте `chromium-browser`/`chromium` из apt и укажите путь или положитесь на авто-поиск на arm64.
 * WebRTC: сигналинг по WebSocket на --server; один SCTP DataChannel — одно бинарное сообщение = один IPv4-пакет.
 * ICE/STUN/TURN: из --config (по умолчанию config/default.json), см. --ice-mode.
 * QUIC (Node 25+): нативный node:quic, ALPN clean-vpn, один bidi stream = тот же uint32+IPv4, что TCP.
 *   Нужен бинарь Node, собранный с QUIC (в рантайме: node -p "process.config.variables.node_use_quic" — должно быть истинно); одного флага --experimental-quic недостаточно, если модуль не вкомпилирован (часто apt/snap).
 *   Запуск: node --experimental-quic …  TLS: ca.pem / cert.pem / key.pem в certs/ (создаются через openssl при отсутствии).
 * QUIC-EXT (--type=quic-ext): пакет @infisical/quic (quiche), Node 18+, без node:quic и без --experimental-quic.
 *   Тот же UDP host:port и фрейминг uint32+IPv4 по одному bidi stream. ALPN: clean-vpn-ext (должен совпадать на обеих сторонах).
 *   TLS: те же ca.pem / cert.pem / key.pem (--quic-certs-dir). Дополнительно для stateless retry: quic-ext-hmac.key (32 байта) в том же каталоге — создаётся на exit при отсутствии; для client не нужен.
 *   Опционально: --quic-ext-crypto-key=PATH — явный файл с 32 байтами HMAC-ключа (вместо quic-ext-hmac.key в каталоге сертификатов).
 *
 * Пример:
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=socket
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=socket --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=http
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=http --split-default
 *   HTTP (--type=http): тот же TCP, что socket; клиент — GET /clean-vpn, ответ 200, затем uint32+IPv4 (см. строку «Протокол» выше).
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=websocket
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=websocket --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=ws-chrome
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=ws-chrome --split-default [--ws-chrome-exit-page]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:51820 --type=udp
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:51820 --type=udp --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:9876 --type=webrtc [--config=config/exit-node.json]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:9876 --type=webrtc --split-default --ice-mode=relay
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:9876 --type=rtc-chrome --split-default [--config=...] [--rtc-chrome-executable=...]
 *   sudo env PATH=$PATH node --experimental-quic scripts/clean-vpn.js --role=exit --server=0.0.0.0:4433 --type=quic
 *   sudo env PATH=$PATH node --experimental-quic scripts/clean-vpn.js --role=client --server=VPS:4433 --type=quic --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:4433 --type=quic-ext
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:4433 --type=quic-ext --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:443 --type=tls [--tls-cert-dir=...] [--tls-public-name=vpn.example.com] [--tls-probe-target=host:port]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:443 --type=tls --split-default [--tls-server-name=...]
 * TLS (--type=tls): TCP + TLS, ALPN clean-vpn-tls; тот же uint32+IPv4 после рукопожатия.
 *   Exit: сырой TCP → разбор ClientHello (SNI/ALPN): VPN / «честная» страница по SNI / passthrough на --tls-probe-target (см. лимиты).
 *   На exit: --tls-cert-dir, --tls-public-name (SNI для «It works!»), --tls-probe-target (куда passthrough). Флаг --tls-server-name на exit не читается (только client).
 *   Внимание: passthrough на сторонний хост может нарушать ToS сервиса и законы юрисдикции — только на свой страх и риск.
 *   Сертификаты: --tls-cert-dir с fullchain.pem+privkey.pem (Let's Encrypt) или, как у QUIC, ca.pem+cert.pem+key.pem.
 *   Client: --tls-server-name — SNI и проверка сертификата. Если в --server указан IP, SNI не может быть IP (RFC 6066): без флага подставляется clean-vpn (как у ca/cert из репо); для Let's Encrypt укажите --tls-server-name=ваш.домен.
 *   Split-default: маршруты 0.0.0.0/1 + 128.0.0.0/1 — только IPv4; плюс 10/8, 172.16/12, 192.168/16 через uplink (DNS/LAN не на exit). IPv6 default не трогается. Проверка внешнего IPv4: curl -4 https://ifconfig.me (без -4 curl может выбрать IPv6).
 *
 * При SIGINT/SIGTERM: снимаются iptables/NAT (exit), net.ipv4.ip_forward, маршруты и rp_filter (client)
 * восстанавливаются по снимку `ip -json route` (если доступен).
 *
 * Производительность (Linux, опционально, вручную):
 *   Высокий PPS / UDP / QUIC: увеличить лимиты сокетных буферов ядра, например:
 *   `sudo sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728`
 *   При узких TCP-окнах при необходимости смотреть `net.ipv4.tcp_rmem` / `tcp_wmem` (зависит от сценария).
 *   Аномалии фрагментации или латентности на физическом NIC: `ethtool -k <iface>` (иногда GRO/LRO влияют на кейс).
 */

import { execFileSync } from 'child_process';
import { EventEmitter } from 'events';
import { createRequire } from 'module';
import { createPrivateKey, randomBytes } from 'crypto';
import dgram from 'dgram';
import fs from 'fs';
import http from 'http';
import net from 'net';
import tls from 'tls';
import path from 'path';
import process from 'process';
import { Readable, Writable } from 'stream';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import WebSocket from 'ws';
import dns from 'dns/promises';
import { PeerConnection, setSctpSettings } from 'node-datachannel';
// @matrixai/logger — CJS; в ESM класс лежит в .default, не в корне namespace.
import matrixAiLogger from '@matrixai/logger';
const LoggerClass = matrixAiLogger.default ?? matrixAiLogger;
const { LogLevel, StreamHandler } = matrixAiLogger;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const requireAddon = createRequire(import.meta.url);
const TUN_LINUX_ADDON = path.join(__dirname, '../native/tun_linux/build/Release/tun_linux.node');

/** @type {{ open: (name: string) => object }|null} */
let tunLinuxAddonCache = null;

function loadTunLinuxAddon() {
  if (tunLinuxAddonCache) return tunLinuxAddonCache;
  try {
    tunLinuxAddonCache = requireAddon(TUN_LINUX_ADDON);
  } catch (e) {
    throw new Error(
      `Не удалось загрузить native TUN (${TUN_LINUX_ADDON}). Соберите: npm run build:tun-linux (нужны python3, make, g++; только Linux).`,
      { cause: e },
    );
  }
  return tunLinuxAddonCache;
}

/**
 * Открывает TUN через N-API addon (без subprocess tun-helper).
 * @param {string} tunName — желаемое имя, например tun0
 * @returns {{ tun: { ifname: string, write: (b: Buffer) => void, startRead: (cb: (batch: ArrayBuffer[]) => void) => void, close: () => void }, name: string }}
 */
function openTunNative(tunName) {
  const addon = loadTunLinuxAddon();
  const tun = addon.open(tunName);
  return { tun, name: tun.ifname };
}

// =============================================================================
// === Константы: native TUN addon, адреса VPN, SCTP, пути конфигов, ALPN ===
// =============================================================================

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
const DEFAULT_QUIC_CERTS_DIR = path.join(__dirname, '../certs');
const QUIC_ALPN = 'clean-vpn';
const QUIC_TLS_CA = 'ca.pem';
const QUIC_TLS_CERT = 'cert.pem';
const QUIC_TLS_KEY = 'key.pem';
/** ALPN для @infisical/quic (quiche); должен совпадать на exit и client. */
const QUIC_EXT_ALPN = 'clean-vpn-ext';
const QUIC_EXT_HMAC_FILE = 'quic-ext-hmac.key';

/** ALPN для --type=tls (VPN); браузер обычно шлёт http/1.1 / h2. */
const TLS_ALPN_VPN = 'clean-vpn-tls';
/** Маркер в ClientHello для scripts/probe.js (не VPN; только логи probeTool на exit). */
const TLS_ALPN_PROBE = 'clean-vpn-probe';
const TLS_LE_FULLCHAIN = 'fullchain.pem';
const TLS_LE_PRIVKEY = 'privkey.pem';
const TLS_HTTP_WORKS_BODY = 'It works!\n';
const DEFAULT_TLS_PROBE_TARGET = 'www.google.com:443';
const DEFAULT_TLS_PROBE_MAX_BYTES = 49152;
const DEFAULT_TLS_PROBE_MAX_SECONDS = 30;
const DEFAULT_TLS_PROBE_FULL_PROXY_PER_IP = 0;
/** Таймаут ожидания TLS-рукопожатия на client (до attachTunBridge). */
const TLS_CLIENT_HANDSHAKE_MS = 30000;

// =============================================================================
// === tun: маршруты split-default (RFC1918 через uplink) ===
// =============================================================================

/** RFC1918: при split-default идут через uplink (длиннее префикса /1), чтобы DNS/LAN не уезжали на exit. Peer 10.99.0.1 остаётся /32 на tun. */
const SPLIT_PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

/**
 * @param {string|null|undefined} gw
 * @param {string} dev
 */
function addSplitPrivateUplinkRoutes(gw, dev) {
  for (const dst of SPLIT_PRIVATE_V4) {
    if (gw) {
      ip(['route', 'replace', dst, 'via', gw, 'dev', dev]);
    } else {
      ip(['route', 'replace', dst, 'dev', dev]);
    }
  }
}

/**
 * @param {string|null|undefined} gw
 * @param {string} dev
 */
function delSplitPrivateUplinkRoutes(gw, dev) {
  for (const dst of SPLIT_PRIVATE_V4) {
    if (gw) {
      tryIpRoute(['route', 'del', dst, 'via', gw, 'dev', dev]);
    } else {
      tryIpRoute(['route', 'del', dst, 'dev', dev]);
    }
  }
}

// =============================================================================
// === --type=quic-ext: HMAC stateless retry, импорт @infisical/quic, логер ===
// =============================================================================

function createQuicExtLogger() {
  return new LoggerClass('clean-vpn-quic-ext', LogLevel.WARN, [new StreamHandler(process.stderr)]);
}

/** @param {Buffer} buf */
function bufferToArrayBuffer(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

/**
 * @param {ArrayBuffer} keyBuf
 * @param {ArrayBuffer} dataBuf
 */
async function quicExtSignHMAC(keyBuf, dataBuf) {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBuf,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return globalThis.crypto.subtle.sign('HMAC', key, dataBuf);
}

/**
 * @param {ArrayBuffer} keyBuf
 * @param {ArrayBuffer} dataBuf
 * @param {ArrayBuffer} sigBuf
 */
async function quicExtVerifyHMAC(keyBuf, dataBuf, sigBuf) {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBuf,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  return globalThis.crypto.subtle.verify('HMAC', key, sigBuf, dataBuf);
}

/** @param {ArrayBuffer} data */
async function quicExtRandomBytes(data) {
  const u8 = new Uint8Array(data);
  globalThis.crypto.getRandomValues(u8);
}

/**
 * 32-байтовый HMAC-ключ для stateless retry @infisical/quic (общий на одну пару exit+client через файл).
 * @param {string} certsDir
 * @param {string|null} explicitPath
 */
function ensureQuicExtHmacKey(certsDir, explicitPath) {
  const keyPath = explicitPath ? path.resolve(explicitPath) : path.join(certsDir, QUIC_EXT_HMAC_FILE);
  if (explicitPath) {
    if (!fs.existsSync(keyPath)) {
      throw new Error(
        `QUIC-EXT: нет файла --quic-ext-crypto-key=${keyPath} (нужны ровно 32 байта).`,
      );
    }
    const buf = fs.readFileSync(keyPath);
    if (buf.length !== 32) {
      throw new Error(`QUIC-EXT: ${keyPath} должен быть ровно 32 байта, сейчас ${buf.length}`);
    }
    return bufferToArrayBuffer(buf);
  }
  if (fs.existsSync(keyPath)) {
    const buf = fs.readFileSync(keyPath);
    if (buf.length !== 32) {
      throw new Error(`QUIC-EXT: ${keyPath} должен быть ровно 32 байта, сейчас ${buf.length}`);
    }
    return bufferToArrayBuffer(buf);
  }
  fs.mkdirSync(certsDir, { recursive: true });
  const rnd = randomBytes(32);
  fs.writeFileSync(keyPath, rnd, { mode: 0o600 });
  console.log('[clean-vpn] QUIC-EXT: создан ключ stateless retry', keyPath);
  return bufferToArrayBuffer(rnd);
}

async function importQuicExt() {
  try {
    const m = await import('@infisical/quic');
    const root = m.default ?? m;
    const QUICServer = root.QUICServer ?? m.QUICServer;
    const QUICClient = root.QUICClient ?? m.QUICClient;
    const events = root.events ?? m.events;
    if (!QUICServer || !QUICClient || !events?.EventQUICServerConnection) {
      throw new Error('неполный экспорт пакета (QUICServer / QUICClient / events)');
    }
    return { QUICServer, QUICClient, events };
  } catch (e) {
    const arch = process.arch;
    const plat = process.platform;
    throw new Error(
      `Не удалось загрузить @infisical/quic (${plat}/${arch}): ${e.message}. ` +
        `Нужен prebuild под вашу платформу; см. optionalDependencies пакета и выполните npm install.`,
    );
  }
}

// =============================================================================
// === --type=quic (node:quic): версия Node, dynamic import ===
// =============================================================================

function assertQuicNodeVersion() {
  const major = parseInt(String(process.versions.node).split('.')[0], 10);
  if (Number.isNaN(major) || major < 25) {
    throw new Error(
      `--type=quic требует Node.js 25+ (сейчас ${process.versions.node}). Остальные --type работают на Node 18+.`,
    );
  }
}

async function importNodeQuic() {
  try {
    return await import('node:quic');
  } catch (e) {
    const hint =
      'Проверьте: node -p "process.config.variables.node_use_quic" — если не true/1, этот бинарь собран без QUIC; возьмите сборку с nodejs.org или nvm (не пакет apt без node_use_quic). ';
    throw new Error(
      `Не удалось загрузить node:quic: ${e.message}. ` +
        `Нужны Node 25+ и флаг --experimental-quic перед скриптом. ` +
        `Если версия уже 25+ и флаг есть, типичная причина — сборка без вкомпилированного QUIC. ` +
        hint,
    );
  }
}

// =============================================================================
// === Общее: OpenSSL, каталог сертификатов (quic / quic-ext / tls) ===
// =============================================================================

function opensslAvailable() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Локальный CA + серверный cert (CN=clean-vpn). Клиент доверяет ca.pem; SNI на клиенте — clean-vpn.
 */
function ensureQuicCerts(dir) {
  const caPath = path.join(dir, QUIC_TLS_CA);
  const certPath = path.join(dir, QUIC_TLS_CERT);
  const keyPath = path.join(dir, QUIC_TLS_KEY);
  if (fs.existsSync(caPath) && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { caPath, certPath, keyPath };
  }
  if (!opensslAvailable()) {
    throw new Error(
      `QUIC: нет ${caPath}, ${certPath}, ${keyPath} и не найден openssl в PATH. Установите openssl или создайте файлы вручную.`,
    );
  }
  fs.mkdirSync(dir, { recursive: true });
  const caKeyPath = path.join(dir, '.clean-vpn-ca.key');
  const csrPath = path.join(dir, '.clean-vpn-server.csr');
  const sslOpt = { stdio: 'inherit', cwd: dir };
  try {
    execFileSync('openssl', ['genrsa', '-out', caKeyPath, '4096'], sslOpt);
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-new',
        '-nodes',
        '-key',
        caKeyPath,
        '-sha256',
        '-days',
        '3650',
        '-subj',
        '/CN=clean-vpn-dev-ca',
        '-out',
        caPath,
      ],
      sslOpt,
    );
    execFileSync('openssl', ['genrsa', '-out', keyPath, '2048'], sslOpt);
    execFileSync(
      'openssl',
      ['req', '-new', '-key', keyPath, '-out', csrPath, '-subj', '/CN=clean-vpn'],
      sslOpt,
    );
    execFileSync(
      'openssl',
      [
        'x509',
        '-req',
        '-in',
        csrPath,
        '-CA',
        caPath,
        '-CAkey',
        caKeyPath,
        '-CAcreateserial',
        '-out',
        certPath,
        '-days',
        '825',
        '-sha256',
      ],
      sslOpt,
    );
  } finally {
    for (const p of [caKeyPath, csrPath]) {
      try {
        fs.unlinkSync(p);
      } catch {
        /* ignore */
      }
    }
    for (const srl of [
      path.join(dir, `${path.basename(caPath)}.srl`),
      path.join(dir, 'ca.srl'),
    ]) {
      try {
        fs.unlinkSync(srl);
      } catch {
        /* ignore */
      }
    }
  }
  console.log('[clean-vpn] QUIC: созданы тестовые TLS-файлы в', dir);
  return { caPath, certPath, keyPath };
}

/**
 * @param {{ tlsCertDir?: string|null, quicCertsDir?: string|null }} args
 */
function resolveTlsCertsDir(args) {
  if (args.tlsCertDir) return path.resolve(args.tlsCertDir);
  if (args.quicCertsDir) return path.resolve(args.quicCertsDir);
  return DEFAULT_QUIC_CERTS_DIR;
}

/**
 * Серверные PEM для TLS exit: приоритет Let's Encrypt (fullchain+privkey), иначе ensureQuicCerts.
 * @returns {{ cert: string, key: string, caPath: string }}
 */
function loadTlsServerCredentials(dir) {
  const fullchainPath = path.join(dir, TLS_LE_FULLCHAIN);
  const privkeyPath = path.join(dir, TLS_LE_PRIVKEY);
  if (fs.existsSync(fullchainPath) && fs.existsSync(privkeyPath)) {
    return {
      cert: fs.readFileSync(fullchainPath, 'utf8'),
      key: fs.readFileSync(privkeyPath, 'utf8'),
      caPath: fullchainPath,
    };
  }
  const t = ensureQuicCerts(dir);
  return {
    cert: fs.readFileSync(t.certPath, 'utf8'),
    key: fs.readFileSync(t.keyPath, 'utf8'),
    caPath: t.caPath,
  };
}

/** CA для tls.connect на клиенте: при LE — fullchain; иначе ca.pem. */
function loadTlsClientCaPem(dir) {
  const fullchainPath = path.join(dir, TLS_LE_FULLCHAIN);
  if (fs.existsSync(fullchainPath)) return fs.readFileSync(fullchainPath, 'utf8');
  const t = ensureQuicCerts(dir);
  return fs.readFileSync(t.caPath, 'utf8');
}

// =============================================================================
// === --type=tls: парсинг ClientHello, SNI/ALPN, passthrough, inbound exit ===
// =============================================================================

/** Макс. буфер при сборке ClientHello из нескольких TLS records (защита от DOS). */
const TLS_MUX_MAX_CLIENT_BUF = 512 * 1024;

/**
 * SNI / ALPN из тела ClientHello (после fixed части до extensions).
 * @returns {{ ok: true, sni: string[], alpn: string[] } | { ok: false, reason: string }}
 */
function parseTlsClientHelloExtensions(ch) {
  let o = 0;
  if (ch.length < 34) return { ok: false, reason: 'short_ch' };
  o += 34;
  const sidLen = ch[o];
  o += 1;
  if (ch.length < o + sidLen + 2) return { ok: false, reason: 'short_ch2' };
  o += sidLen;
  const csLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + csLen + 1) return { ok: false, reason: 'short_ch3' };
  o += csLen;
  const compLen = ch[o];
  o += 1;
  if (ch.length < o + compLen + 2) return { ok: false, reason: 'short_ch4' };
  o += compLen;
  const extLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + extLen) return { ok: false, reason: 'short_ext' };
  const extBlock = ch.subarray(o, o + extLen);
  /** @type {string[]} */
  const sni = [];
  /** @type {string[]} */
  const alpn = [];
  let eo = 0;
  while (eo + 4 <= extBlock.length) {
    const et = extBlock.readUInt16BE(eo);
    const el = extBlock.readUInt16BE(eo + 2);
    eo += 4;
    if (eo + el > extBlock.length) break;
    const ed = extBlock.subarray(eo, eo + el);
    if (et === 0 && ed.length >= 2) {
      let listLen = ed.readUInt16BE(0);
      let so = 2;
      while (so + 3 <= ed.length && listLen >= 3) {
        const nt = ed[so];
        const nl = ed.readUInt16BE(so + 1);
        so += 3;
        if (so + nl > ed.length) break;
        if (nt === 0) sni.push(ed.subarray(so, so + nl).toString('utf8'));
        so += nl;
        listLen -= 3 + nl;
      }
    } else if (et === 16 && ed.length >= 2) {
      let listLen = ed.readUInt16BE(0);
      let ao = 2;
      while (ao + 1 <= ed.length && listLen > 0) {
        const pl = ed[ao];
        ao += 1;
        if (ao + pl > ed.length) break;
        alpn.push(ed.subarray(ao, ao + pl).toString('utf8'));
        ao += pl;
        listLen -= 1 + pl;
      }
    }
    eo += el;
  }
  return { ok: true, sni, alpn };
}

/**
 * ClientHello может занимать несколько подряд TLS records (0x16) — типично при крупном hello (OpenSSL 3 / PQ).
 * @returns {{ needMore: true, minTotal: number } | { ok: false, reason: string } | { ok: true, sni: string[], alpn: string[], bytesConsumed: number }}
 */
function parseFirstTlsClientHello(buf) {
  if (buf.length > TLS_MUX_MAX_CLIENT_BUF) {
    return { ok: false, reason: 'buffer_max' };
  }
  if (buf.length < 5) return { needMore: true, minTotal: 5 };
  if (buf[0] !== 0x16) return { ok: false, reason: 'not_tls_handshake' };

  /** @type {Buffer[]} */
  const payloads = [];
  let offset = 0;
  for (;;) {
    if (buf.length - offset < 5) {
      return { needMore: true, minTotal: offset + 5 };
    }
    if (buf[offset] !== 0x16) {
      return offset === 0
        ? { ok: false, reason: 'not_tls_handshake' }
        : { ok: false, reason: 'non_handshake_record' };
    }
    const recLen = buf.readUInt16BE(offset + 3);
    const recordEnd = offset + 5 + recLen;
    if (recLen < 1 || recordEnd > TLS_MUX_MAX_CLIENT_BUF) {
      return { ok: false, reason: 'record_oversize' };
    }
    if (recordEnd > buf.length) {
      return { needMore: true, minTotal: recordEnd };
    }
    payloads.push(buf.subarray(offset + 5, recordEnd));
    offset = recordEnd;
    const combined = Buffer.concat(payloads);
    if (combined.length < 4) continue;
    if (combined[0] !== 1) return { ok: false, reason: 'not_client_hello' };
    const hsLen = combined.readUIntBE(1, 3);
    const totalHs = 4 + hsLen;
    if (combined.length < totalHs) continue;
    const ch = combined.subarray(4, totalHs);
    const ext = parseTlsClientHelloExtensions(ch);
    if (!ext.ok) return ext;
    return { ok: true, sni: ext.sni, alpn: ext.alpn, bytesConsumed: offset };
  }
}

/**
 * @param {string[]} sniList
 * @param {string} publicName
 */
function sniMatchesTlsPublicName(sniList, publicName) {
  const want = String(publicName).toLowerCase().replace(/\.$/, '');
  if (!want) return false;
  for (const raw of sniList) {
    const h = String(raw).toLowerCase().replace(/\.$/, '');
    if (h === want) return true;
  }
  return false;
}

function tlsClientIp(socket) {
  const a = socket.remoteAddress || '';
  return a.replace(/^\:\:ffff\:/, '');
}

function tlsUtcDayBucket() {
  return Math.floor(Date.now() / 86400000);
}

/** После того как байты уже шли через pipe, такие errno — типичный разрыв пира, не сбой прокси. */
const TCP_BENIGN_AFTER_DATA_CODES = new Set(['ECONNRESET', 'EPIPE', 'ECONNABORTED']);

/**
 * @param {import('net').Socket} socket
 * @param {string} reason
 * @param {Buffer} fullBuf
 * @param {boolean} [probeTool]
 */
function logTlsPassthrough(socket, reason, fullBuf, probeTool = false) {
  const ip = tlsClientIp(socket);
  const port = socket.remotePort ?? '?';
  const hex = fullBuf.subarray(0, Math.min(16, fullBuf.length)).toString('hex');
  console.log(
    `[clean-vpn] tls active-probe: start ip=${ip} port=${port} reason=${reason} probeTool=${probeTool} prefix=${hex}…`,
  );
}

/**
 * Двунаправленный pipe с лимитом байт и времени.
 * @param {import('net').Socket} a
 * @param {import('net').Socket} b
 * @param {{ maxBytes: number, maxMs: number, treatCommonResetAsClose?: boolean }} opts
 * @param {(meta: { totalBytes: number, cause: 'timeout'|'byte_limit'|'error'|'close', socketError: boolean }) => void} onEnd
 */
function pipeTcpWithLimits(a, b, opts, onEnd) {
  let total = 0;
  const deadline = Date.now() + opts.maxMs;
  let ended = false;
  /** @type {'timeout'|'byte_limit'|'error'|'close'|null} */
  let endCause = null;
  let socketError = false;
  function finish(cause, fromError = false) {
    if (ended) return;
    ended = true;
    endCause = cause;
    if (fromError) socketError = true;
    clearInterval(tick);
    try {
      a.destroy();
    } catch {
      /* ignore */
    }
    try {
      b.destroy();
    } catch {
      /* ignore */
    }
    try {
      onEnd({
        totalBytes: total,
        cause: /** @type {'timeout'|'byte_limit'|'error'|'close'} */ (endCause || 'close'),
        socketError,
      });
    } catch {
      /* ignore */
    }
  }
  const tick = setInterval(() => {
    if (Date.now() > deadline) finish('timeout', false);
  }, 1000);
  tick.unref?.();
  const count = (n) => {
    total += n;
    if (total >= opts.maxBytes) finish('byte_limit', false);
  };
  const pipeDir = (src, dst) => {
    src.on('data', (chunk) => {
      if (ended) return;
      count(chunk.length);
      if (ended) return;
      const ok = dst.write(chunk);
      if (!ok) src.pause();
    });
    dst.on('drain', () => src.resume());
  };
  pipeDir(a, b);
  pipeDir(b, a);
  const onSockError = (err) => {
    const code = err && /** @type {NodeJS.ErrnoException} */ (err).code;
    if (
      opts.treatCommonResetAsClose &&
      total > 0 &&
      code &&
      TCP_BENIGN_AFTER_DATA_CODES.has(code)
    ) {
      finish('close', false);
      return;
    }
    finish('error', true);
  };
  a.on('error', onSockError);
  b.on('error', onSockError);
  a.on('close', () => finish('close', false));
  b.on('close', () => finish('close', false));
}

// =============================================================================
// === --type=quic (node:quic): QuicStream bidi → socket-like для attachTunBridge ===
// =============================================================================

/** @param {any} qs — quic.QuicStream (bidi) */
function quicBidiToSocketLike(qs) {
  if (!qs?.readable) {
    throw new Error('QUIC: у потока нет readable');
  }
  if (!qs.writable) {
    throw new Error('QUIC: у потока нет writable (нужен bidirectional stream)');
  }
  const r = Readable.fromWeb(qs.readable, { highWaterMark: 4 * 1024 * 1024 });
  const w = Writable.fromWeb(qs.writable, { highWaterMark: 4 * 1024 * 1024 });
  const sock = /** @type {any} */ (r);
  sock.destroyed = false;
  sock.write = (chunk, enc, cb) => w.write(chunk, enc, cb);
  sock.destroy = (err) => {
    if (sock.destroyed) return;
    sock.destroyed = true;
    try {
      qs.destroy(err);
    } catch {
      /* ignore */
    }
    try {
      w.destroy(err);
    } catch {
      /* ignore */
    }
    try {
      r.destroy(err);
    } catch {
      /* ignore */
    }
  };
  return sock;
}

// =============================================================================
// === --type=webrtc: ICE/STUN/TURN из JSON (node-datachannel) ===
// =============================================================================

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

/**
 * ICE в формате для RTCPeerConnection (Chrome): те же правила фильтрации, что у convertIceServers.
 * @returns {{ iceServers: Array<{ urls: string|string[], username?: string, credential?: string }>, iceMode: string, configPath: string }}
 */
function convertIceServersToBrowserObjects(servers, iceMode) {
  /** @type {Array<{ urls: string|string[], username?: string, credential?: string }>} */
  const result = [];
  for (const s of servers) {
    const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
    const kept = [];
    for (const url of urls) {
      if (!url) continue;
      const u = String(url);
      const isStun = u.startsWith('stun:');
      const isTurn = u.startsWith('turn:') || u.startsWith('turns:');
      if (iceMode === 'relay' && isStun) continue;
      if (iceMode === 'direct' && isTurn) continue;
      kept.push(u);
    }
    if (!kept.length) continue;
    const entry =
      kept.length === 1
        ? { urls: kept[0] }
        : { urls: kept };
    if (s.username != null && s.username !== '') entry.username = s.username;
    if (s.credential != null && s.credential !== '') entry.credential = s.credential;
    result.push(entry);
  }
  return result;
}

/**
 * @param {string|null|undefined} configPath
 * @param {string|null|undefined} cliIceMode
 */
function loadWebrtcBrowserIceFromConfig(configPath, cliIceMode) {
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
  const iceServers = convertIceServersToBrowserObjects(merged, iceMode);
  if (!iceServers.length) {
    throw new Error(
      'rtc-chrome: после фильтрации iceMode список ICE пуст; проверьте turnServers',
    );
  }
  return { iceServers, iceMode, configPath: resolved };
}

// =============================================================================
// === Общее: разбор CLI, parseHostPort, снимки и правки ip route (client) ===
// =============================================================================

function parseArgs(argv) {
  const out = {
    role: null,
    server: null,
    type: null,
    splitDefault: false,
    extIface: null,
    configPath: null,
    iceMode: null,
    quicCertsDir: null,
    quicExtCryptoKey: null,
    tlsCertDir: null,
    tlsServerName: null,
    tlsPublicName: null,
    tlsProbeTarget: null,
    tlsProbeMaxBytes: null,
    tlsProbeMaxSeconds: null,
    tlsProbeFullProxyPerIp: null,
    wsChromeExecutable: null,
    wsChromeWsUrl: null,
    wsChromeUrl: null,
    wsChromeExitPage: false,
    wsChromeCdpData: false,
    rtcChromeExecutable: null,
  };
  for (const a of argv) {
    if (a.startsWith('--role=')) out.role = a.slice('--role='.length);
    else if (a.startsWith('--server=')) out.server = a.slice('--server='.length);
    else if (a.startsWith('--type=')) out.type = a.slice('--type='.length);
    else if (a.startsWith('--ext=')) out.extIface = a.slice('--ext='.length);
    else if (a.startsWith('--config=')) out.configPath = a.slice('--config='.length);
    else if (a.startsWith('--ice-mode=')) out.iceMode = a.slice('--ice-mode='.length);
    else if (a.startsWith('--quic-certs-dir=')) {
      out.quicCertsDir = a.slice('--quic-certs-dir='.length);
    } else if (a.startsWith('--quic-ext-crypto-key=')) {
      out.quicExtCryptoKey = a.slice('--quic-ext-crypto-key='.length);
    } else if (a.startsWith('--tls-cert-dir=')) {
      out.tlsCertDir = a.slice('--tls-cert-dir='.length);
    } else if (a.startsWith('--tls-server-name=')) {
      out.tlsServerName = a.slice('--tls-server-name='.length);
    } else if (a.startsWith('--tls-public-name=')) {
      out.tlsPublicName = a.slice('--tls-public-name='.length);
    } else if (a.startsWith('--tls-probe-target=')) {
      out.tlsProbeTarget = a.slice('--tls-probe-target='.length);
    } else if (a.startsWith('--tls-probe-max-bytes=')) {
      out.tlsProbeMaxBytes = parseInt(a.slice('--tls-probe-max-bytes='.length), 10);
    } else if (a.startsWith('--tls-probe-max-seconds=')) {
      out.tlsProbeMaxSeconds = parseInt(a.slice('--tls-probe-max-seconds='.length), 10);
    } else if (a.startsWith('--tls-probe-full-proxy-per-ip=')) {
      out.tlsProbeFullProxyPerIp = parseInt(a.slice('--tls-probe-full-proxy-per-ip='.length), 10);
    } else if (a.startsWith('--ws-chrome-executable=')) {
      out.wsChromeExecutable = a.slice('--ws-chrome-executable='.length);
    } else if (a.startsWith('--ws-chrome-ws-url=')) {
      out.wsChromeWsUrl = a.slice('--ws-chrome-ws-url='.length);
    } else if (a.startsWith('--ws-chrome-url=')) {
      out.wsChromeUrl = a.slice('--ws-chrome-url='.length);
    } else if (a === '--ws-chrome-exit-page') out.wsChromeExitPage = true;
    else if (a === '--ws-chrome-cdp-data') out.wsChromeCdpData = true;
    else if (a.startsWith('--rtc-chrome-executable=')) {
      out.rtcChromeExecutable = a.slice('--rtc-chrome-executable='.length);
    } else if (a === '--split-default') out.splitDefault = true;
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

// =============================================================================
// === tun (продолжение): имя интерфейса, native addon, ip addr, sysctl, NAT ===
// =============================================================================

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

// =============================================================================
// === Общее: uint32+IPv4 фрейминг, writeFramed, attachTunBridge (все transport) ===
// =============================================================================

/** Сдвиг накопленного буфера; при большом byteOffset — компактная копия, чтобы не держать гигантский ArrayBuffer. */
const STREAM_FRAMER_COMPACT_THRESHOLD = 65536;

class StreamFramer {
  constructor() {
    this.buf = Buffer.alloc(0);
  }

  /**
   * @param {Buffer} chunk
   * @param {(pkt: Buffer) => void} onPacket — срез внутреннего буфера; не мутировать после колбэка.
   */
  push(chunk, onPacket) {
    if (chunk.length) {
      // Нельзя хранить ссылку на `chunk` из socket 'data': Node переиспользует slab.
      const piece = Buffer.from(chunk);
      if (this.buf.length === 0) {
        this.buf = piece;
      } else {
        const next = Buffer.allocUnsafe(this.buf.length + piece.length);
        this.buf.copy(next, 0);
        piece.copy(next, this.buf.length);
        this.buf = next;
      }
    }
    for (;;) {
      if (this.buf.length < 4) break;
      const len = this.buf.readUInt32BE(0);
      if (len <= 0 || len > MAX_PKT) {
        this.buf = Buffer.alloc(0);
        throw new Error(`bad frame length ${len}`);
      }
      if (this.buf.length < 4 + len) break;
      const pkt = this.buf.subarray(4, 4 + len);
      const rest = 4 + len;
      this.buf = rest === this.buf.length ? Buffer.alloc(0) : this.buf.subarray(rest);
      onPacket(pkt);
    }
    this.#compactIfNeeded();
  }

  #compactIfNeeded() {
    if (this.buf.length === 0) return;
    if (this.buf.byteOffset >= STREAM_FRAMER_COMPACT_THRESHOLD) {
      const copy = Buffer.allocUnsafe(this.buf.length);
      this.buf.copy(copy);
      this.buf = copy;
    }
  }
}

function writeFramed(sock, pkt) {
  // Отдельный буфер на каждый кадр: переиспользуемый заголовок ломает очередь, если write()
  // откладывает отправку и следующий пакет перезапишет те же 4 байта.
  const h = Buffer.allocUnsafe(4);
  h.writeUInt32BE(pkt.length, 0);
  const w1 = sock.write(h);
  const w2 = sock.write(pkt);
  return w1 && w2;
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
    addSplitPrivateUplinkRoutes(gw, dev);
    console.log('[clean-vpn] split-default (0.0.0.0/1 + 128.0.0.0/1) через', ifname);
    console.log(
      '[clean-vpn] split-default: частные сети',
      SPLIT_PRIVATE_V4.join(', '),
      '→ uplink',
      gw ? `via ${gw}` : '',
      dev,
    );
    console.warn(
      '[clean-vpn] split-default только для IPv4; IPv6 default не в туннеле. Проверка внешнего IPv4: curl -4 https://ifconfig.me',
    );
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
    delSplitPrivateUplinkRoutes(gw, dev);
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
 * Один активный мост на TUN: иначе второй TCP-клиент на exit вешает второй
 * listener и пакеты дублируются / рассинхрон.
 *
 * @param {{ write: (b: Buffer) => void, startRead: (cb: (batch: ArrayBuffer[]) => void) => void }} tun — native addon
 * @param {'tcp'|'websocket'|'udp-client'|'udp-server'|'webrtc-dc'} transport
 * @param {import('net').Socket|import('ws')|import('dgram').Socket|{sock: import('dgram').Socket, peer?: import('dgram').RemoteInfo}|import('node-datachannel').DataChannel} endpoint
 */
function attachTunBridge(tun, transport, endpoint) {
  const framer = new StreamFramer();

  const writeTun = (pkt) => {
    try {
      tun.write(pkt);
    } catch (e) {
      console.error('[clean-vpn] tun write:', e?.message || e);
    }
  };

  /** @type {Buffer[]} */
  const dcQueue = [];
  let dcHead = 0;
  const DC_QUEUE_COMPACT_AFTER = 2048;
  const DC_BUFFER_HIGH = 8 * 1024 * 1024;
  let dcPumpScheduled = false;
  const pumpDcQueue = () => {
    dcPumpScheduled = false;
    if (transport !== 'webrtc-dc') return;
    while (dcHead < dcQueue.length) {
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
      const pkt = dcQueue[dcHead++];
      if (!pkt) break;
      try {
        endpoint.sendMessageBinary(pkt);
      } catch (e) {
        console.error('[clean-vpn] webrtc-dc send:', e?.message || e);
      }
    }
    if (
      dcHead >= DC_QUEUE_COMPACT_AFTER &&
      dcHead > (dcQueue.length >> 1)
    ) {
      dcQueue.splice(0, dcHead);
      dcHead = 0;
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
      writeTun(Buffer.isBuffer(msg) ? msg : Buffer.from(msg));
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
      writeTun(Buffer.isBuffer(msg) ? msg : Buffer.from(msg));
    });
  } else if (transport === 'webrtc-dc') {
    endpoint.onMessage((data) => {
      if (typeof data === 'string') return;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (!buf.length || buf.length > MAX_PKT) return;
      writeTun(buf);
    });
  }

  tun.startRead((batch) => {
    const pkts = Array.isArray(batch) ? batch : [batch];
    for (const raw of pkts) {
      const pkt = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      if (!pkt.length || pkt.length > MAX_PKT) continue;
      sendOnWire(pkt);
    }
  });
}

/**
 * После рукопожатия: VPN-мост или «It works!» для public.
 *
 * @param {import('tls').TLSSocket} tlsSock
 * @param {'vpn'|'public'} mode
 * @param {{
 *   startBridge: (sock: any, restBuf: Buffer|null, transport: 'tcp') => void,
 * }} ctx
 */
function wireExitTlsSocket(tlsSock, mode, ctx) {
  tlsSock.on('error', (e) => {
    console.error(`[clean-vpn] tls ${mode} socket:`, e?.message || e);
  });
  tlsSock.once('secure', () => {
    try {
      if (mode === 'vpn') {
        if (tlsSock.alpnProtocol !== TLS_ALPN_VPN) {
          tlsSock.destroy();
          return;
        }
        console.log('[clean-vpn] tls VPN client connected', tlsSock.remoteAddress);
        ctx.startBridge(tlsSock, null, 'tcp');
        return;
      }
      if (tlsSock.alpnProtocol === 'h2') {
        console.warn(
          '[clean-vpn] tls exit: браузер выбрал только h2 — закройте вкладку или включите http/1.1 в ALPN (MVP без HTTP/2)',
        );
        tlsSock.destroy();
        return;
      }
      let httpBuf = Buffer.alloc(0);
      const onHttp = (d) => {
        httpBuf = Buffer.concat([httpBuf, d]);
        if (httpBuf.includes(Buffer.from('\r\n\r\n'))) {
          tlsSock.off('data', onHttp);
          const body = TLS_HTTP_WORKS_BODY;
          const res = `HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`;
          tlsSock.write(res, () => {
            try {
              tlsSock.end();
            } catch {
              /* ignore */
            }
          });
        }
      };
      tlsSock.on('data', onHttp);
      setTimeout(() => {
        if (!tlsSock.destroyed) tlsSock.destroy();
      }, 30000).unref?.();
    } catch (e) {
      console.error('[clean-vpn] tls secure handler:', e?.message || e);
      try {
        tlsSock.destroy();
      } catch {
        /* ignore */
      }
    }
  });
}

/**
 * @param {import('net').Socket} clientSock
 * @param {Buffer} prefixBuf
 * @param {{
 *   probeTargetHost: string,
 *   probeTargetPort: number,
 *   probeShortMaxBytes: number,
 *   probeMaxSeconds: number,
 *   probeFullProxyPerIp: number,
 *   probeBudget: Map<string, { day: number, fullCount: number }>,
 * }} ctx
 * @param {boolean} [probeTool]
 */
function runTlsProbePassthrough(clientSock, prefixBuf, ctx, probeTool = false) {
  const ip = tlsClientIp(clientSock);
  const port = clientSock.remotePort ?? '?';
  const remote = net.createConnection(
    { port: ctx.probeTargetPort, host: ctx.probeTargetHost },
    () => {
      remote.write(prefixBuf);
      const day = tlsUtcDayBucket();
      const ipKey = tlsClientIp(clientSock);
      let fb = ctx.probeBudget.get(ipKey);
      if (!fb || fb.day !== day) {
        fb = { day, fullCount: 0 };
        ctx.probeBudget.set(ipKey, fb);
      }
      let maxBytes = ctx.probeShortMaxBytes;
      if (ctx.probeFullProxyPerIp > 0 && fb.fullCount < ctx.probeFullProxyPerIp) {
        fb.fullCount += 1;
        maxBytes = Number.MAX_SAFE_INTEGER;
      }
      pipeTcpWithLimits(
        clientSock,
        remote,
        {
          maxBytes,
          maxMs: ctx.probeMaxSeconds * 1000,
          treatCommonResetAsClose: true,
        },
        (meta) => {
          const ok = !meta.socketError;
          console.log(
            `[clean-vpn] tls active-probe: end ip=${ip} port=${port} probeTool=${probeTool} result=${ok ? 'ok' : 'fail'} bytes=${meta.totalBytes} cause=${meta.cause}`,
          );
        },
      );
    },
  );
  remote.on('error', (e) => {
    console.log(
      `[clean-vpn] tls active-probe: end ip=${ip} port=${port} probeTool=${probeTool} result=fail cause=upstream err=${e.message}`,
    );
    try {
      clientSock.destroy();
    } catch {
      /* ignore */
    }
  });
}

/**
 * @param {import('net').Socket} socket
 * @param {{
 *   startBridge: (sock: any, restBuf: Buffer|null, transport: 'tcp') => void,
 *   creds: { cert: string, key: string },
 *   tlsPublicName: string|null,
 *   probeTargetHost: string,
 *   probeTargetPort: number,
 *   probeShortMaxBytes: number,
 *   probeMaxSeconds: number,
 *   probeFullProxyPerIp: number,
 *   probeBudget: Map<string, { day: number, fullCount: number }>,
 *   tlsExitSecureContext: import('tls').SecureContext,
 * }} ctx
 */
function handleTlsExitInbound(socket, ctx) {
  const ra = socket.remoteAddress || '';
  const rp = socket.remotePort;
  console.log(
    `[clean-vpn] tls: входящий TCP с ${ra.replace(/^\:\:ffff\:/, '')}:${rp ?? '?'}`,
  );
  /** @type {Buffer[]} */
  const chunks = [];
  const helloTimer = setTimeout(() => {
    try {
      socket.destroy();
    } catch {
      /* ignore */
    }
  }, 60000);
  const onData = (c) => {
    chunks.push(c);
    const buf = Buffer.concat(chunks);
    const p = parseFirstTlsClientHello(buf);
    if ('needMore' in p && p.needMore) return;
    clearTimeout(helloTimer);
    socket.off('data', onData);
    const fullBuf = Buffer.concat(chunks);
    if (!('ok' in p && p.ok)) {
      logTlsPassthrough(socket, p.reason || 'parse_fail', fullBuf, false);
      runTlsProbePassthrough(socket, fullBuf, ctx, false);
      return;
    }
    const hasVpnAlpn = p.alpn.includes(TLS_ALPN_VPN);
    const probeTool = p.alpn.includes(TLS_ALPN_PROBE);
    const publicOk =
      ctx.tlsPublicName &&
      sniMatchesTlsPublicName(p.sni, ctx.tlsPublicName) &&
      !hasVpnAlpn;
    if (!hasVpnAlpn && !publicOk) {
      logTlsPassthrough(socket, 'no_vpn_alpn_and_no_public_sni_match', fullBuf, probeTool);
      runTlsProbePassthrough(socket, fullBuf, ctx, probeTool);
      return;
    }
    console.log(
      `[clean-vpn] tls: ClientHello ок (ALPN=${p.alpn.join(',') || '—'}; SNI=${p.sni.join(',') || '—'}) → TLS server (${hasVpnAlpn ? 'vpn' : 'public'})`,
    );
    const mode = hasVpnAlpn ? 'vpn' : 'public';
    setImmediate(() => {
      try {
        const tlsSock = new tls.TLSSocket(socket, {
          isServer: true,
          secureContext: ctx.tlsExitSecureContext,
          ALPNProtocols: hasVpnAlpn ? [TLS_ALPN_VPN] : ['http/1.1', 'h2'],
          requestCert: false,
          handshakeTimeout: 60000,
        });
        wireExitTlsSocket(tlsSock, mode, ctx);
        socket.unshift(fullBuf);
        try {
          socket.resume();
        } catch {
          /* ignore */
        }
      } catch (e) {
        console.error('[clean-vpn] tls: TLSSocket(secureContext):', e?.message || e);
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
      }
    });
  };
  socket.on('data', onData);
  socket.on('error', () => clearTimeout(helloTimer));
  socket.on('close', () => clearTimeout(helloTimer));
}

// =============================================================================
// === Общее: HTTP-преамбула для --type=socket | --type=http ===
// =============================================================================

function handleHttpSocket(sock, onReady) {
  const HTTP_PREAMBLE_COMPACT = 32768;
  const onData = (chunk) => {
    let base = sock.__httpBuf;
    if (base && base.byteOffset >= HTTP_PREAMBLE_COMPACT) {
      const c = Buffer.allocUnsafe(base.length);
      base.copy(c);
      base = c;
    }
    const buf =
      base == null
        ? Buffer.from(chunk)
        : (() => {
            const n = Buffer.allocUnsafe(base.length + chunk.length);
            base.copy(n, 0);
            chunk.copy(n, base.length);
            return n;
          })();
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

/** Exit --type=ws-chrome: страница для Puppeteer (GET /clean-vpn-chrome). */
const WS_CHROME_BRIDGE_PAGE_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>clean-vpn-chrome</title></head><body>
<script>
(function () {
  var ws = new WebSocket((location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/');
  ws.binaryType = 'arraybuffer';
  ws.onopen = function () { if (window.cleanVpnWsReady) window.cleanVpnWsReady(); };
  ws.onmessage = function (ev) {
    var d = ev.data;
    if (d instanceof ArrayBuffer && window.cleanVpnBrowserToNode) {
      window.cleanVpnBrowserToNode(Array.from(new Uint8Array(d)));
    }
  };
  ws.onclose = function () { if (window.cleanVpnWsClosed) window.cleanVpnWsClosed(); };
  ws.onerror = function () {};
  window.__cleanVpnSend = function (u8) {
    if (ws.readyState === WebSocket.OPEN) ws.send(u8);
  };
})();
</script></body></html>`;

/** На Linux arm64/arm предпочитаем системный Chromium — бандл из ~/.cache/puppeteer там часто несовместим (Multipass, VM). */
function resolveLinuxArmSystemChromium() {
  if (process.platform !== 'linux') return null;
  if (process.arch !== 'arm64' && process.arch !== 'arm') return null;
  const candidates = [
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/snap/bin/chromium',
    '/usr/bin/google-chrome-stable',
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}

/** Встроенная страница для режима CDP (медленный путь): один WS к exit + exposeFunction/evaluate на пакет. */
function buildWsChromeCdpEmbeddedPageHtml(wsUrl) {
  const u = JSON.stringify(wsUrl);
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
(function () {
  var ws = new WebSocket(${u});
  ws.binaryType = 'arraybuffer';
  ws.onopen = function () { window.cleanVpnWsReady(); };
  ws.onmessage = function (ev) {
    var d = ev.data;
    if (d instanceof ArrayBuffer) window.cleanVpnBrowserToNode(Array.from(new Uint8Array(d)));
  };
  ws.onclose = function () { window.cleanVpnWsClosed(); };
  ws.onerror = function () {};
  window.__cleanVpnSend = function (u8) {
    if (ws.readyState === WebSocket.OPEN) ws.send(u8);
  };
})();
</script></body></html>`;
}

/**
 * Два WebSocket: к exit и к локальному Node (127.0.0.1). Бинарные кадры 1:1; горячий путь без CDP.
 */
function buildWsChromeDualBridgePageHtml(wsUrl, localWsUrl) {
  const u = JSON.stringify(wsUrl);
  const l = JSON.stringify(localWsUrl);
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
(function () {
  var OPEN = 1;
  var exitWs = new WebSocket(${u});
  var localWs = new WebSocket(${l});
  exitWs.binaryType = 'arraybuffer';
  localWs.binaryType = 'arraybuffer';
  var exitBuf = [];
  var localBuf = [];
  function flushToLocal() {
    while (exitBuf.length && localWs.readyState === OPEN) {
      localWs.send(exitBuf.shift());
    }
  }
  function flushToExit() {
    while (localBuf.length && exitWs.readyState === OPEN) {
      exitWs.send(localBuf.shift());
    }
  }
  exitWs.onopen = function () {
    flushToLocal();
    if (window.cleanVpnWsReady) window.cleanVpnWsReady();
  };
  localWs.onopen = function () {
    flushToExit();
  };
  exitWs.onmessage = function (ev) {
    var d = ev.data;
    if (localWs.readyState !== OPEN) {
      exitBuf.push(d);
      return;
    }
    localWs.send(d);
  };
  localWs.onmessage = function (ev) {
    var d = ev.data;
    if (exitWs.readyState !== OPEN) {
      localBuf.push(d);
      return;
    }
    exitWs.send(d);
  };
  exitWs.onclose = function () { if (window.cleanVpnWsClosed) window.cleanVpnWsClosed(); };
  localWs.onclose = function () { if (window.cleanVpnWsClosed) window.cleanVpnWsClosed(); };
  exitWs.onerror = function () {};
  localWs.onerror = function () {};
})();
</script></body></html>`;
}

/** page.exposeFunction сериализует Uint8Array в plain object {0:..,1:..}; Buffer.from(data) падает. */
function bufferFromPuppeteerExpose(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) return Buffer.from(data);
  if (data && typeof data === 'object') {
    const keys = Object.keys(data);
    if (keys.length === 0) return Buffer.alloc(0);
    const numeric = keys.filter((k) => /^\d+$/.test(k));
    if (numeric.length === keys.length && numeric.length > 0) {
      const len = numeric.length;
      const out = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) {
        out[i] = Number(data[String(i)]) & 0xff;
      }
      return out;
    }
  }
  throw new TypeError('ws-chrome: неподдерживаемый формат пакета из браузера');
}

/**
 * Puppeteer: страница держит WebSocket к exit; мост с API как у `ws` для attachTunBridge.
 * @param {{
 *   wsUrl: string,
 *   useLocalBridge: boolean,
 *   executablePath?: string|null,
 *   pageMode: 'embedded'|'goto',
 *   gotoUrl?: string|null,
 * }} opts
 */
async function createWsChromeClientBridge(opts) {
  if (opts.useLocalBridge && opts.pageMode === 'goto') {
    throw new Error('ws-chrome: локальный мост несовместим с pageMode goto');
  }

  /** @type {import('ws').WebSocketServer|null} */
  let localWss = null;
  /** @type {string} */
  let localWsUrl = '';

  if (opts.useLocalBridge) {
    localWss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((resolve, reject) => {
      localWss.once('error', reject);
      localWss.once('listening', resolve);
    });
    const ad = localWss.address();
    if (!ad || typeof ad === 'string') {
      try {
        localWss.close();
      } catch {
        /* ignore */
      }
      throw new Error('ws-chrome: не удалось получить адрес локального WSS');
    }
    localWsUrl = `ws://127.0.0.1:${ad.port}/`;
  }

  let puppeteerMod;
  try {
    puppeteerMod = await import('puppeteer');
  } catch (e) {
    if (localWss) {
      try {
        localWss.close();
      } catch {
        /* ignore */
      }
    }
    throw new Error('Для --type=ws-chrome установите: npm install puppeteer', { cause: e });
  }
  const puppeteer = puppeteerMod.default ?? puppeteerMod;
  const launchArgs = [];
  if (
    process.env.CLEAN_VPN_PUPPETEER_NO_SANDBOX === '1' ||
    (typeof process.getuid === 'function' && process.getuid() === 0)
  ) {
    launchArgs.push('--no-sandbox', '--disable-setuid-sandbox');
  }
  const launchOpts = {
    headless: true,
    args: launchArgs,
  };
  let executablePath =
    opts.executablePath || process.env.PUPPETEER_EXECUTABLE_PATH || null;
  if (!executablePath) {
    const sys = resolveLinuxArmSystemChromium();
    if (sys) {
      executablePath = sys;
      console.log(`[clean-vpn] ws-chrome: используем системный браузер ${sys}`);
    }
  }
  if (executablePath) {
    launchOpts.executablePath = executablePath;
  }
  let browser;
  try {
    browser = await puppeteer.launch(launchOpts);
  } catch (launchErr) {
    if (localWss) {
      try {
        localWss.close();
      } catch {
        /* ignore */
      }
    }
    const hint = `ws-chrome: не удалось запустить браузер (${launchErr?.message || launchErr}).
Частые причины на Linux ARM64 (Multipass/VM на Mac M*):
  sudo apt update && sudo apt install -y chromium-browser
  # или пакет chromium; затем явно:
  sudo ... --ws-chrome-executable=/usr/bin/chromium-browser
Либо удалите битый кэш: rm -rf ~/.cache/puppeteer
При sudo node добавляются --no-sandbox; при необходимости: CLEAN_VPN_PUPPETEER_NO_SANDBOX=1
См. https://pptr.dev/troubleshooting`;
    throw new Error(hint, { cause: launchErr });
  }
  const page = await browser.newPage();

  const lifecycle = new EventEmitter();

  if (opts.useLocalBridge) {
    console.log('[clean-vpn] ws-chrome: локальный WS-мост 127.0.0.1 (данные не через CDP)');

    let localConnDone = false;
    const localClientPromise = new Promise((resolve, reject) => {
      const to = setTimeout(
        () => reject(new Error('ws-chrome: таймаут подключения локального WS моста')),
        120000,
      );
      localWss.on('connection', (ws) => {
        if (localConnDone) {
          try {
            ws.close();
          } catch {
            /* ignore */
          }
          return;
        }
        localConnDone = true;
        clearTimeout(to);
        resolve(ws);
      });
    });

    await page.exposeFunction('cleanVpnWsReady', () => {
      lifecycle.emit('_chromeWsOpen');
    });
    await page.exposeFunction('cleanVpnWsClosed', () => {
      lifecycle.emit('close');
    });

    await page.setContent(buildWsChromeDualBridgePageHtml(opts.wsUrl, localWsUrl), {
      waitUntil: 'domcontentloaded',
    });

    const bridge = await localClientPromise;

    await new Promise((resolve, reject) => {
      const to = setTimeout(
        () => reject(new Error('ws-chrome: таймаут WebSocket к exit')),
        120000,
      );
      lifecycle.once('_chromeWsOpen', () => {
        clearTimeout(to);
        resolve(undefined);
      });
      lifecycle.once('close', () => {
        clearTimeout(to);
        reject(new Error('ws-chrome: WebSocket закрыт до готовности'));
      });
    });

    return { bridge, browser, page, localWss };
  }

  const bridge = new EventEmitter();

  await page.exposeFunction('cleanVpnBrowserToNode', (data) => {
    try {
      const buf = bufferFromPuppeteerExpose(data);
      bridge.emit('message', buf, true);
    } catch (err) {
      bridge.emit('error', err);
    }
  });
  await page.exposeFunction('cleanVpnWsReady', () => {
    bridge.emit('_chromeWsOpen');
  });
  await page.exposeFunction('cleanVpnWsClosed', () => {
    bridge.emit('close');
  });

  console.log('[clean-vpn] ws-chrome: данные через Puppeteer/CDP (медленный путь)');

  if (opts.pageMode === 'goto') {
    const url = opts.gotoUrl;
    if (!url) throw new Error('ws-chrome: пустой goto URL');
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 120000 });
  } else {
    await page.setContent(buildWsChromeCdpEmbeddedPageHtml(opts.wsUrl), {
      waitUntil: 'domcontentloaded',
    });
  }

  await new Promise((resolve, reject) => {
    const to = setTimeout(
      () => reject(new Error('ws-chrome: таймаут WebSocket к exit')),
      120000,
    );
    bridge.once('_chromeWsOpen', () => {
      clearTimeout(to);
      resolve(undefined);
    });
    bridge.once('close', () => {
      clearTimeout(to);
      reject(new Error('ws-chrome: WebSocket закрыт до готовности'));
    });
  });

  bridge.send = (pkt) => {
    const bytes = Array.from(pkt);
    void page
      .evaluate((arr) => {
        if (typeof window.__cleanVpnSend === 'function') {
          window.__cleanVpnSend(new Uint8Array(arr));
        }
      }, bytes)
      .catch((e) => bridge.emit('error', e));
  };

  return { bridge, browser, page, localWss: null };
}

/**
 * Страница rtc-chrome: сигналинг WS + RTCPeerConnection + DataChannel + локальный WS к Node.
 */
function buildRtcChromeEmbeddedPageHtml(
  signalingWsUrl,
  localWsUrl,
  iceServers,
  iceTransportPolicy,
) {
  const sig = JSON.stringify(signalingWsUrl);
  const loc = JSON.stringify(localWsUrl);
  const ice = JSON.stringify(iceServers);
  const pol = JSON.stringify(iceTransportPolicy);
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
(function () {
  var OPEN = 1;
  var iceServers = ${ice};
  var iceTransportPolicy = ${pol};
  var sigWs = new WebSocket(${sig});
  var localWs = new WebSocket(${loc});
  localWs.binaryType = 'arraybuffer';
  var pc = new RTCPeerConnection({
    iceServers: iceServers,
    iceTransportPolicy: iceTransportPolicy,
    bundlePolicy: 'max-bundle',
  });
  var vpnDc = null;
  var dcBuf = [];
  var localBuf = [];
  var didReady = false;
  var remoteOk = false;
  var candPend = [];

  function tryReady() {
    if (didReady) return;
    if (!vpnDc || vpnDc.readyState !== 'open') return;
    if (localWs.readyState !== OPEN) return;
    didReady = true;
    if (window.cleanVpnRtcReady) window.cleanVpnRtcReady();
  }

  function signalClose() {
    if (window.cleanVpnRtcClosed) window.cleanVpnRtcClosed();
  }

  function flushDcToLocal() {
    while (dcBuf.length && localWs.readyState === OPEN && vpnDc && vpnDc.readyState === 'open') {
      localWs.send(dcBuf.shift());
    }
  }
  function flushLocalToDc() {
    while (localBuf.length && vpnDc && vpnDc.readyState === 'open') {
      try {
        vpnDc.send(localBuf.shift());
      } catch (e) {
        if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
        return;
      }
    }
  }

  function attachDcPipe() {
    if (!vpnDc) return;
    vpnDc.binaryType = 'arraybuffer';
    vpnDc.onopen = function () {
      flushLocalToDc();
      tryReady();
    };
    vpnDc.onmessage = function (ev) {
      var d = ev.data;
      if (localWs.readyState !== OPEN) {
        dcBuf.push(d);
        return;
      }
      localWs.send(d);
    };
    vpnDc.onclose = signalClose;
    vpnDc.onerror = function () {};
    if (vpnDc.readyState === 'open') {
      flushLocalToDc();
      tryReady();
    }
  }

  localWs.onopen = function () {
    flushDcToLocal();
    tryReady();
  };
  localWs.onmessage = function (ev) {
    var d = ev.data;
    if (!vpnDc || vpnDc.readyState !== 'open') {
      localBuf.push(d);
      return;
    }
    try {
      vpnDc.send(d);
    } catch (e) {
      if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
    }
  };
  localWs.onclose = signalClose;
  localWs.onerror = function () {};

  pc.ondatachannel = function (ev) {
    var ch = ev.channel;
    if (ch.label !== 'clean-vpn') {
      try { ch.close(); } catch (e) {}
      return;
    }
    vpnDc = ch;
    attachDcPipe();
    tryReady();
  };

  pc.onicecandidate = function (e) {
    if (!e.candidate) return;
    if (sigWs.readyState !== OPEN) return;
    try {
      sigWs.send(
        JSON.stringify({
          type: 'candidate',
          candidate: e.candidate.candidate,
          mid: e.candidate.sdpMid || '0',
        }),
      );
    } catch (err) {}
  };

  function flushCandPend() {
    var i;
    for (i = 0; i < candPend.length; i++) {
      var msg = candPend[i];
      if (!msg.candidate) continue;
      pc.addIceCandidate({ candidate: msg.candidate, sdpMid: msg.mid || null }).catch(function () {});
    }
    candPend = [];
  }

  async function handleSigMsg(msg) {
    try {
      if (msg.type === 'offer') {
        await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        remoteOk = true;
        flushCandPend();
        var ans = await pc.createAnswer();
        await pc.setLocalDescription(ans);
        if (sigWs.readyState === OPEN) {
          sigWs.send(JSON.stringify({ type: 'answer', sdp: pc.localDescription.sdp }));
        }
      } else if (msg.type === 'answer') {
        await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
        remoteOk = true;
        flushCandPend();
      } else if (msg.type === 'candidate') {
        if (!msg.candidate) return;
        if (!remoteOk) {
          candPend.push(msg);
          return;
        }
        await pc.addIceCandidate({ candidate: msg.candidate, sdpMid: msg.mid || null });
      }
    } catch (e) {
      if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
    }
  }

  sigWs.onmessage = function (ev) {
    var msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (e) {
      return;
    }
    void handleSigMsg(msg);
  };
  sigWs.onclose = signalClose;
  sigWs.onerror = function () {};

  sigWs.onopen = function () {
    try {
      sigWs.send(JSON.stringify({ type: 'clean-vpn-ready' }));
    } catch (e) {
      if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
    }
  };
})();
</script></body></html>`;
}

/**
 * Puppeteer + Chrome: WebRTC DataChannel к exit (сигналинг как у --type=webrtc), данные через локальный WS.
 * @param {{
 *   signalingWsUrl: string,
 *   iceServers: Array<{ urls: string|string[], username?: string, credential?: string }>,
 *   iceMode: string,
 *   executablePath?: string|null,
 * }} opts
 */
async function createRtcChromeClientBridge(opts) {
  const localWss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve, reject) => {
    localWss.once('error', reject);
    localWss.once('listening', resolve);
  });
  const ad = localWss.address();
  if (!ad || typeof ad === 'string') {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    throw new Error('rtc-chrome: не удалось получить адрес локального WSS');
  }
  const localWsUrl = `ws://127.0.0.1:${ad.port}/`;

  let puppeteerMod;
  try {
    puppeteerMod = await import('puppeteer');
  } catch (e) {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    throw new Error('Для --type=rtc-chrome установите: npm install puppeteer', { cause: e });
  }
  const puppeteer = puppeteerMod.default ?? puppeteerMod;
  const launchArgs = [];
  if (
    process.env.CLEAN_VPN_PUPPETEER_NO_SANDBOX === '1' ||
    (typeof process.getuid === 'function' && process.getuid() === 0)
  ) {
    launchArgs.push('--no-sandbox', '--disable-setuid-sandbox');
  }
  const launchOpts = {
    headless: true,
    args: launchArgs,
  };
  let executablePath =
    opts.executablePath || process.env.PUPPETEER_EXECUTABLE_PATH || null;
  if (!executablePath) {
    const sys = resolveLinuxArmSystemChromium();
    if (sys) {
      executablePath = sys;
      console.log(`[clean-vpn] rtc-chrome: используем системный браузер ${sys}`);
    }
  }
  if (executablePath) {
    launchOpts.executablePath = executablePath;
  }
  let browser;
  try {
    browser = await puppeteer.launch(launchOpts);
  } catch (launchErr) {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    const hint = `rtc-chrome: не удалось запустить браузер (${launchErr?.message || launchErr}).
См. подсказки для ws-chrome в шапке скрипта и https://pptr.dev/troubleshooting`;
    throw new Error(hint, { cause: launchErr });
  }
  const page = await browser.newPage();
  const lifecycle = new EventEmitter();

  console.log('[clean-vpn] rtc-chrome: локальный WS-мост 127.0.0.1 + WebRTC в Chrome');

  let localConnDone = false;
  const localClientPromise = new Promise((resolve, reject) => {
    const to = setTimeout(
      () => reject(new Error('rtc-chrome: таймаут подключения локального WS моста')),
      180000,
    );
    localWss.on('connection', (ws) => {
      if (localConnDone) {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        return;
      }
      localConnDone = true;
      clearTimeout(to);
      resolve(ws);
    });
  });

  await page.exposeFunction('cleanVpnRtcReady', () => {
    lifecycle.emit('_rtcReady');
  });
  await page.exposeFunction('cleanVpnRtcClosed', () => {
    lifecycle.emit('close');
  });
  await page.exposeFunction('cleanVpnRtcError', (msg) => {
    lifecycle.emit('error', new Error(String(msg)));
  });

  const iceTransportPolicy = opts.iceMode === 'relay' ? 'relay' : 'all';
  await page.setContent(
    buildRtcChromeEmbeddedPageHtml(
      opts.signalingWsUrl,
      localWsUrl,
      opts.iceServers,
      iceTransportPolicy,
    ),
    { waitUntil: 'domcontentloaded' },
  );

  const bridge = await localClientPromise;

  await new Promise((resolve, reject) => {
    const to = setTimeout(
      () => reject(new Error('rtc-chrome: таймаут готовности WebRTC DataChannel')),
      180000,
    );
    const done = () => clearTimeout(to);
    lifecycle.once('_rtcReady', () => {
      done();
      resolve(undefined);
    });
    lifecycle.once('close', () => {
      done();
      reject(new Error('rtc-chrome: соединение закрыто до готовности'));
    });
    lifecycle.once('error', (err) => {
      done();
      reject(err);
    });
  });

  return { bridge, browser, page, localWss };
}

// =============================================================================
// === runExit: tun + NAT, затем ветки по --type ===
// =============================================================================

async function runExit({
  server,
  type,
  extIface,
  configPath,
  iceMode,
  quicCertsDir,
  quicExtCryptoKey,
  tlsCertDir,
  tlsPublicName,
  tlsProbeTarget,
  tlsProbeMaxBytes,
  tlsProbeMaxSeconds,
  tlsProbeFullProxyPerIp,
  tlsServerName,
}) {
  const { host, port } = parseHostPort(server);
  if (type === 'rtc-chrome') {
    throw new Error(
      '[clean-vpn] --type=rtc-chrome только для --role=client; на exit используйте --type=webrtc',
    );
  }
  const tunName = findFreeTunName();
  const { tun, name: ifname } = openTunNative(tunName);
  setupTunIp('exit', ifname);
  const nat = setupExitNat(ifname, extIface);

  /** @type {import('net').Socket|null} */
  let activeTcp = null;
  /** @type {import('ws').WebSocketServer|null} */
  let wss = null;
  /** @type {import('http').Server|null} */
  let httpChromeSrv = null;
  /** @type {import('net').Server|null} */
  let tcpSrv = null;
  /** @type {import('dgram').Socket|null} */
  let udpSock = null;
  /** @type {import('node-datachannel').PeerConnection|null} */
  let webrtcPc = null;
  /** @type {any} */
  let quicEndpoint = null;
  /** @type {any} */
  let quicSession = null;
  /** @type {any} */
  let quicExtServer = null;
  let shuttingDown = false;

  const startBridge = (sock, restBuf, transport) => {
    if (transport === 'tcp' && activeTcp && !activeTcp.destroyed) {
      activeTcp.destroy();
    }
    if (transport === 'tcp') activeTcp = sock;
    attachTunBridge(tun, transport, sock);
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
      if (httpChromeSrv) {
        httpChromeSrv.close();
        httpChromeSrv = null;
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
    try {
      if (quicSession) {
        quicSession.destroy();
        quicSession = null;
      }
    } catch {
      /* ignore */
    }
    try {
      if (quicEndpoint) {
        quicEndpoint.destroy();
        quicEndpoint = null;
      }
    } catch {
      /* ignore */
    }
    const finishExit = () => {
      teardownExitNat(nat.tunName, nat.ext);
      restoreExitSysctl(nat.prevIpForward);
      try {
        tun.close();
      } catch {
        /* ignore */
      }
      console.log('[clean-vpn] exit: остановка');
      process.exit(0);
    };
    try {
      if (quicExtServer) {
        const s = quicExtServer;
        quicExtServer = null;
        void s.stop({ isApp: true, force: true }).then(finishExit, finishExit);
        return;
      }
    } catch {
      /* ignore */
    }
    finishExit();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // --- runExit: --type=websocket ---
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

  // --- runExit: --type=ws-chrome (HTTP GET /clean-vpn-chrome + WebSocket upgrade на том же порту) ---
  if (type === 'ws-chrome') {
    const srv = http.createServer((req, res) => {
      if (
        req.method === 'GET' &&
        (req.url === '/clean-vpn-chrome' || req.url.startsWith('/clean-vpn-chrome?'))
      ) {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(WS_CHROME_BRIDGE_PAGE_HTML);
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('clean-vpn ws-chrome: GET /clean-vpn-chrome');
    });
    wss = new WebSocketServer({ noServer: true });
    wss.on('connection', (ws) => {
      console.log('[clean-vpn] ws-chrome: WebSocket connected');
      wss.clients.forEach((c) => {
        if (c !== ws) c.close();
      });
      startBridge(ws, null, 'websocket');
    });
    srv.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    });
    await new Promise((resolve, reject) => {
      srv.listen(port, host, () => resolve(undefined));
      srv.once('error', reject);
    });
    httpChromeSrv = srv;
    const h = host === '0.0.0.0' ? '*' : host;
    console.log(
      `[clean-vpn] exit ws-chrome http://${h}:${port}/clean-vpn-chrome + ws same port`,
    );
    return;
  }

  // --- runExit: --type=socket | --type=http ---
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

  // --- runExit: --type=tls ---
  if (type === 'tls') {
    if (tlsServerName) {
      console.warn(
        '[clean-vpn] --tls-server-name на exit не используется (только на client). Для цели passthrough задайте --tls-probe-target=host:port.',
      );
    }
    const certsDir = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const creds = loadTlsServerCredentials(certsDir);
    const targetStr = tlsProbeTarget || DEFAULT_TLS_PROBE_TARGET;
    const { host: pHost, port: pPort } = parseHostPort(targetStr);
    const probeShortMaxBytes =
      tlsProbeMaxBytes != null && Number.isFinite(tlsProbeMaxBytes) && tlsProbeMaxBytes >= 0
        ? tlsProbeMaxBytes
        : DEFAULT_TLS_PROBE_MAX_BYTES;
    const probeMaxSeconds =
      tlsProbeMaxSeconds != null && Number.isFinite(tlsProbeMaxSeconds) && tlsProbeMaxSeconds > 0
        ? tlsProbeMaxSeconds
        : DEFAULT_TLS_PROBE_MAX_SECONDS;
    const probeFullProxyPerIp =
      tlsProbeFullProxyPerIp != null &&
      Number.isFinite(tlsProbeFullProxyPerIp) &&
      tlsProbeFullProxyPerIp >= 0
        ? tlsProbeFullProxyPerIp
        : DEFAULT_TLS_PROBE_FULL_PROXY_PER_IP;
    /** @type {Map<string, { day: number, fullCount: number }>} */
    const probeBudget = new Map();
    const tlsExitSecureContext = tls.createSecureContext({
      cert: creds.cert,
      key: creds.key,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3',
    });
    const tlsCtx = {
      startBridge,
      creds,
      tlsPublicName: tlsPublicName || null,
      probeTargetHost: pHost,
      probeTargetPort: pPort,
      probeShortMaxBytes,
      probeMaxSeconds,
      probeFullProxyPerIp,
      probeBudget,
      tlsExitSecureContext,
    };
    tcpSrv = net
      .createServer((sock) => {
        handleTlsExitInbound(sock, tlsCtx);
      })
      .listen(port, host, () => {
        console.log(
          `[clean-vpn] exit TLS ${host}:${port} (ALPN VPN: ${TLS_ALPN_VPN}; публичный SNI: ${tlsPublicName || '—'}; probe → ${pHost}:${pPort}; short ≤${probeShortMaxBytes} B, ≤${probeMaxSeconds}s; full-proxy/(IP·сутки): ${probeFullProxyPerIp})`,
        );
      });
    return;
  }

  // --- runExit: --type=udp ---
  if (type === 'udp') {
    udpSock = dgram.createSocket('udp4');
    udpSock.on('error', (err) => {
      console.error('[clean-vpn] udp socket error:', err.message);
    });
    const udpEp = { sock: udpSock, peer: undefined };
    udpSock.bind(port, host, () => {
      console.log(`[clean-vpn] exit UDP ${host}:${port} (один peer по первому пакету)`);
    });
    attachTunBridge(tun, 'udp-server', udpEp);
    return;
  }

  // --- runExit: --type=webrtc ---
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
          attachTunBridge(tun, 'webrtc-dc', dc);
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

  // --- runExit: --type=quic (node:quic) ---
  if (type === 'quic') {
    assertQuicNodeVersion();
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir);
    const keyObj = createPrivateKey(fs.readFileSync(tlsPaths.keyPath));
    const certBuf = fs.readFileSync(tlsPaths.certPath);
    const quicNs = await importNodeQuic();
    const listen = quicNs.listen ?? quicNs.default?.listen;
    if (typeof listen !== 'function') {
      throw new Error('node:quic: отсутствует listen()');
    }
    quicEndpoint = await listen(
      (session) => {
        try {
          if (quicSession) {
            quicSession.destroy();
          }
        } catch {
          /* ignore */
        }
        quicSession = session;
        let bidiAttached = false;
        session.onstream = (stream) => {
          if (stream.direction !== 'bidi') {
            try {
              stream.destroy();
            } catch {
              /* ignore */
            }
            return;
          }
          if (bidiAttached) {
            try {
              stream.destroy();
            } catch {
              /* ignore */
            }
            return;
          }
          bidiAttached = true;
          console.log('[clean-vpn] QUIC: входящий bidi stream');
          try {
            const sock = quicBidiToSocketLike(stream);
            startBridge(sock, null, 'tcp');
          } catch (e) {
            console.error('[clean-vpn] QUIC stream:', e?.message || e);
          }
        };
      },
      {
        endpoint: { address: `${host}:${port}` },
        alpn: QUIC_ALPN,
        keys: keyObj,
        certs: [certBuf],
      },
    );
    console.log(
      `[clean-vpn] exit QUIC UDP ${host}:${port} (ALPN ${QUIC_ALPN}, TLS из ${certsDir})`,
    );
    return;
  }

  // --- runExit: --type=quic-ext (@infisical/quic) ---
  if (type === 'quic-ext') {
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir);
    const hmacKey = ensureQuicExtHmacKey(certsDir, quicExtCryptoKey);
    const logger = createQuicExtLogger();
    const { QUICServer, events } = await importQuicExt();
    quicExtServer = new QUICServer({
      crypto: {
        key: hmacKey,
        ops: { sign: quicExtSignHMAC, verify: quicExtVerifyHMAC },
      },
      config: {
        key: fs.readFileSync(tlsPaths.keyPath, 'utf8'),
        cert: fs.readFileSync(tlsPaths.certPath, 'utf8'),
        verifyPeer: false,
        applicationProtos: [QUIC_EXT_ALPN],
      },
      logger,
    });

    /** @type {any} */
    let quicExtServerConn = null;
    quicExtServer.addEventListener(events.EventQUICServerConnection.name, (evt) => {
      const connection = evt.detail;
      if (quicExtServerConn && quicExtServerConn !== connection) {
        void quicExtServerConn.stop({ isApp: true, force: true }).catch(() => {});
      }
      quicExtServerConn = connection;
      let bidiAttached = false;
      const onStream = (ev) => {
        const stream = ev.detail;
        if (stream.type !== 'bidi') return;
        if (bidiAttached) {
          void stream.destroy({ force: true });
          return;
        }
        bidiAttached = true;
        console.log('[clean-vpn] QUIC-EXT: входящий bidi stream');
        try {
          const sock = quicBidiToSocketLike(stream);
          startBridge(sock, null, 'tcp');
        } catch (e) {
          console.error('[clean-vpn] QUIC-EXT stream:', e?.message || e);
        }
      };
      connection.addEventListener(events.EventQUICConnectionStream.name, onStream);
      connection.addEventListener(
        events.EventQUICConnectionStopped.name,
        () => {
          connection.removeEventListener(events.EventQUICConnectionStream.name, onStream);
          if (quicExtServerConn === connection) quicExtServerConn = null;
        },
        { once: true },
      );
    });

    await quicExtServer.start({ host, port });
    console.log(
      `[clean-vpn] exit QUIC-EXT UDP ${host}:${port} (ALPN ${QUIC_EXT_ALPN}, @infisical/quic; TLS и ${QUIC_EXT_HMAC_FILE} в ${certsDir})`,
    );
    return;
  }

  throw new Error(`Неизвестный --type=${type}`);
}

// =============================================================================
// === runClient: tun + маршруты, затем ветки по --type ===
// =============================================================================

async function runClient({
  server,
  type,
  splitDefault,
  configPath,
  iceMode,
  quicCertsDir,
  tlsCertDir,
  tlsServerName,
  tlsPublicName,
  wsChromeExecutable,
  wsChromeWsUrl,
  wsChromeUrl,
  wsChromeExitPage,
  wsChromeCdpData,
  rtcChromeExecutable,
}) {
  const { host, port } = parseHostPort(server);
  const tunName = findFreeTunName();
  const { tun, name: ifname } = openTunNative(tunName);
  setupTunIp('client', ifname);
  const routeCtx = await setupClientRoutesAsync(ifname, host, splitDefault);

  /** @type {import('node-datachannel').PeerConnection|null} */
  let webrtcPc = null;
  /** @type {import('ws').WebSocket|null} */
  let webrtcSigWs = null;
  /** @type {any} */
  let quicClientSession = null;
  /** @type {any} */
  let quicExtClient = null;
  /** @type {import('tls').TLSSocket|null} */
  let tlsVpnSocket = null;
  /** @type {any} */
  let wsChromeBrowser = null;
  /** @type {import('ws').WebSocketServer|null} */
  let wsChromeLocalWss = null;

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
    try {
      if (quicClientSession) {
        quicClientSession.destroy();
        quicClientSession = null;
      }
    } catch {
      /* ignore */
    }
    const finishClient = () => {
      teardownClientRoutes(routeCtx);
      try {
        tun.close();
      } catch {
        /* ignore */
      }
      console.log('[clean-vpn] client: остановка');
      process.exit(0);
    };
    try {
      if (wsChromeLocalWss) {
        const w = wsChromeLocalWss;
        wsChromeLocalWss = null;
        try {
          w.close();
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* ignore */
    }
    try {
      if (wsChromeBrowser) {
        const b = wsChromeBrowser;
        wsChromeBrowser = null;
        void b.close().then(finishClient, finishClient);
        return;
      }
    } catch {
      /* ignore */
    }
    try {
      if (quicExtClient) {
        const c = quicExtClient;
        quicExtClient = null;
        void c.destroy({ isApp: true, force: true }).then(finishClient, finishClient);
        return;
      }
    } catch {
      /* ignore */
    }
    try {
      if (tlsVpnSocket) {
        tlsVpnSocket.destroy();
        tlsVpnSocket = null;
      }
    } catch {
      /* ignore */
    }
    finishClient();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // --- runClient: --type=websocket ---
  if (type === 'websocket') {
    const url = `ws://${host}:${port}/`;
    const ws = new WebSocket(url);
    ws.binaryType = 'nodebuffer';
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
    console.log('[clean-vpn] WebSocket connected');
    attachTunBridge(tun, 'websocket', ws);
    return;
  }

  // --- runClient: --type=ws-chrome (Puppeteer + WebSocket в Chrome) ---
  if (type === 'ws-chrome') {
    const wsUrl = wsChromeWsUrl || `ws://${host}:${port}/`;
    const exe = wsChromeExecutable || process.env.PUPPETEER_EXECUTABLE_PATH || null;
    const forceCdp =
      process.env.CLEAN_VPN_WS_CHROME_CDP_DATA === '1' || wsChromeCdpData;
    const useLocalBridge = !forceCdp && !wsChromeUrl;

    let pageMode = 'embedded';
    /** @type {string|null} */
    let gotoUrl = null;
    if (wsChromeUrl) {
      pageMode = 'goto';
      gotoUrl = wsChromeUrl;
    } else if (wsChromeExitPage && forceCdp) {
      pageMode = 'goto';
      gotoUrl = `http://${host}:${port}/clean-vpn-chrome`;
    }

    const { bridge, browser, localWss } = await createWsChromeClientBridge({
      wsUrl,
      executablePath: exe,
      pageMode,
      gotoUrl,
      useLocalBridge,
    });
    wsChromeBrowser = browser;
    if (localWss) wsChromeLocalWss = localWss;
    bridge.on('close', () => {
      console.error('[clean-vpn] ws-chrome: WebSocket закрыт');
      shutdown();
    });
    bridge.on('error', (e) => {
      console.error('[clean-vpn] ws-chrome:', e?.message || e);
    });
    console.log('[clean-vpn] ws-chrome: готово (Puppeteer → WebSocket → exit)');
    attachTunBridge(tun, 'websocket', bridge);
    return;
  }

  // --- runClient: --type=rtc-chrome (Puppeteer + WebRTC DC + локальный WS) ---
  if (type === 'rtc-chrome') {
    const ice = loadWebrtcBrowserIceFromConfig(configPath, iceMode);
    console.log(
      `[clean-vpn] rtc-chrome client: ICE mode=${ice.iceMode}, конфиг=${ice.configPath}`,
    );
    const signalingWsUrl = `ws://${host}:${port}/`;
    const exe = rtcChromeExecutable || process.env.PUPPETEER_EXECUTABLE_PATH || null;
    const { bridge, browser, localWss } = await createRtcChromeClientBridge({
      signalingWsUrl,
      iceServers: ice.iceServers,
      iceMode: ice.iceMode,
      executablePath: exe,
    });
    wsChromeBrowser = browser;
    if (localWss) wsChromeLocalWss = localWss;
    bridge.on('close', () => {
      console.error('[clean-vpn] rtc-chrome: локальный WebSocket закрыт');
      shutdown();
    });
    bridge.on('error', (e) => {
      console.error('[clean-vpn] rtc-chrome:', e?.message || e);
    });
    console.log('[clean-vpn] rtc-chrome: готово (Chrome WebRTC → exit webrtc, TUN ↔ localhost WS)');
    attachTunBridge(tun, 'websocket', bridge);
    return;
  }

  // --- runClient: --type=udp ---
  if (type === 'udp') {
    const udp = dgram.createSocket('udp4');
    await new Promise((resolve, reject) => {
      udp.once('error', reject);
      udp.connect(port, host, () => {
        udp.off('error', reject);
        console.log(`[clean-vpn] UDP «connected» к ${host}:${port}`);
        attachTunBridge(tun, 'udp-client', udp);
        resolve();
      });
    });
    return;
  }

  // --- runClient: --type=webrtc ---
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
        attachTunBridge(tun, 'webrtc-dc', dc);
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

  // --- runClient: --type=quic (node:quic) ---
  if (type === 'quic') {
    assertQuicNodeVersion();
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir);
    const caBuf = fs.readFileSync(tlsPaths.caPath);
    let connectHost = host;
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      connectHost = (await dns.lookup(host, { family: 4 })).address;
    }
    const quicNs = await importNodeQuic();
    const connect = quicNs.connect ?? quicNs.default?.connect;
    if (typeof connect !== 'function') {
      throw new Error('node:quic: отсутствует connect()');
    }
    quicClientSession = await connect(`${connectHost}:${port}`, {
      alpn: QUIC_ALPN,
      ca: caBuf,
      sni: 'clean-vpn',
    });
    console.log('[clean-vpn] QUIC session установлена');
    const stream = await quicClientSession.createBidirectionalStream();
    const sock = quicBidiToSocketLike(stream);
    attachTunBridge(tun, 'tcp', sock);
    return;
  }

  // --- runClient: --type=quic-ext (@infisical/quic) ---
  if (type === 'quic-ext') {
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir);
    const logger = createQuicExtLogger();
    const { QUICClient } = await importQuicExt();
    let connectHost = host;
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      connectHost = (await dns.lookup(host, { family: 4 })).address;
    }
    quicExtClient = await QUICClient.createQUICClient({
      host: connectHost,
      port,
      serverName: 'clean-vpn',
      crypto: { ops: { randomBytes: quicExtRandomBytes } },
      config: {
        ca: fs.readFileSync(tlsPaths.caPath, 'utf8'),
        verifyPeer: true,
        applicationProtos: [QUIC_EXT_ALPN],
      },
      logger,
    });
    console.log('[clean-vpn] QUIC-EXT (@infisical/quic) соединение установлено');
    const stream = quicExtClient.connection.newStream('bidi');
    const sock = quicBidiToSocketLike(stream);
    attachTunBridge(tun, 'tcp', sock);
    return;
  }

  // --- runClient: --type=tls ---
  if (type === 'tls') {
    const certsDir = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const ca = loadTlsClientCaPem(certsDir);
    const hostIsIp = net.isIP(host) !== 0;
    let servername = tlsServerName || tlsPublicName;
    if (!servername) {
      if (hostIsIp) {
        servername = 'clean-vpn';
        console.warn(
          '[clean-vpn] TLS: в --server указан IP — для SNI используется clean-vpn (при другом CN/SAN задайте --tls-server-name=…).',
        );
      } else {
        servername = host;
      }
    }
    let connectHost = host;
    if (!hostIsIp) {
      connectHost = (await dns.lookup(host, { family: 4 })).address;
    }
    console.log(
      `[clean-vpn] TLS client: соединение к ${connectHost}:${port}, SNI servername=${servername}`,
    );
    await new Promise((resolve, reject) => {
      let settled = false;
      /** @type {import('tls').TLSSocket} */
      let sock;
      const finish = (fn) => {
        if (settled) return;
        settled = true;
        try {
          sock.setTimeout(0);
        } catch {
          /* ignore */
        }
        fn();
      };
      sock = tls.connect(
        port,
        connectHost,
        {
          ALPNProtocols: [TLS_ALPN_VPN],
          ca,
          servername,
          rejectUnauthorized: true,
        },
        () => {
          try {
            if (sock.authorizationError) {
              console.error(
                '[clean-vpn] TLS client: проверка сертификата:',
                sock.authorizationError,
              );
            }
            if (sock.alpnProtocol !== TLS_ALPN_VPN) {
              try {
                sock.destroy();
              } catch {
                /* ignore */
              }
              finish(() =>
                reject(
                  new Error(
                    `TLS client: сервер выбрал ALPN ${String(sock.alpnProtocol)} вместо ${TLS_ALPN_VPN} (часто это passthrough на сторонний сайт или не тот порт/хост на exit).`,
                  ),
                ),
              );
              return;
            }
            tlsVpnSocket = sock;
            console.log('[clean-vpn] TLS (VPN) соединение установлено');
            finish(() => resolve(undefined));
          } catch (e) {
            finish(() => reject(e));
          }
        },
      );
      sock.setTimeout(TLS_CLIENT_HANDSHAKE_MS);
      sock.on('timeout', () => {
        finish(() =>
          reject(
            new Error(
              `TLS client: таймаут ${TLS_CLIENT_HANDSHAKE_MS} мс рукопожатия к ${connectHost}:${port}`,
            ),
          ),
        );
        try {
          sock.destroy();
        } catch {
          /* ignore */
        }
      });
      sock.on('error', (err) => {
        console.error(
          '[clean-vpn] TLS client: ошибка сокета до завершения рукопожатия:',
          err?.message || err,
        );
        if (sock.authorizationError) {
          console.error(
            '[clean-vpn] TLS client: authorizationError:',
            sock.authorizationError,
          );
        }
        finish(() => reject(err));
      });
    });
    attachTunBridge(tun, 'tcp', tlsVpnSocket);
    return;
  }

  // --- runClient: --type=socket | --type=http (TCP + опционально GET /clean-vpn) ---
  await new Promise((resolve, reject) => {
    const sock = net.connect(port, host, () => {
      console.log('[clean-vpn] TCP connected');
      if (type === 'socket') {
        attachTunBridge(tun, 'tcp', sock);
        resolve();
        return;
      }
      sock.__isServer = false;
      handleHttpSocket(sock, (rest) => {
        attachTunBridge(tun, 'tcp', sock);
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

// =============================================================================
// === main: разбор argv, вызов runExit / runClient ===
// =============================================================================

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

--type: socket | http | websocket | ws-chrome | rtc-chrome | udp | webrtc | quic | quic-ext | tls
--split-default: только client, IPv4 default через tun (0.0.0.0/1 + 128.0.0.0/1); RFC1918 (10/8, 172.16/12, 192.168/16) через uplink; IPv6 не в туннеле; проверка IP: curl -4 https://ifconfig.me
--ext: только exit, интерфейс в интернет для NAT (иначе из default route)
--config=PATH: для --type=webrtc и rtc-chrome — JSON с iceServers/turnServers (по умолчанию config/default.json от корня репо)
--ice-mode=auto|relay|direct: для webrtc и rtc-chrome — перекрывает iceMode из --config
--quic-certs-dir=DIR: для --type=quic и quic-ext — каталог с ca.pem, cert.pem, key.pem (иначе repo/certs; при отсутствии — openssl)
--quic-ext-crypto-key=PATH: только exit + quic-ext — файл с 32 байтами HMAC-ключа (иначе quic-ext-hmac.key в каталоге сертификатов)
--type=quic: Node.js 25+, node --experimental-quic и бинарь с node_use_quic (см. шапку файла)
--type=quic-ext: npm install @infisical/quic (prebuild под платформу), Node 18+, см. шапку файла
--tls-cert-dir=DIR: для --type=tls — fullchain.pem+privkey.pem (LE) или ca/cert/key как у QUIC
--tls-server-name=HOST: только client + tls — SNI и проверка сертификата; если --server — IP и флаг не задан, SNI=clean-vpn; на exit игнорируется
--tls-public-name=HOST: только exit + tls — SNI «честной» страницы It works! (опционально)
--tls-probe-target=host:port: только exit + tls — passthrough чужих ClientHello (default www.google.com:443)
--tls-probe-max-bytes=N: короткий passthrough, лимит байт обоих направлений (default 49152)
--tls-probe-max-seconds=S: лимит времени passthrough-сессии (default 30)
--tls-probe-full-proxy-per-ip=K: не более K «длинных» passthrough с одного IP за сутки (default 0 = только короткий)
--type=ws-chrome: client — Puppeteer + Chrome держит WS к exit (npm install puppeteer). По умолчанию быстрый локальный WS-мост 127.0.0.1; медленный CDP на пакет: --ws-chrome-cdp-data или CLEAN_VPN_WS_CHROME_CDP_DATA=1. exit ws-chrome — HTTP /clean-vpn-chrome + WS; без CDP клиент с --ws-chrome-exit-page использует setContent (не загрузка страницы с exit). Произвольная страница: --ws-chrome-url=... — только CDP.
--ws-chrome-executable=PATH, --ws-chrome-ws-url=ws://..., --ws-chrome-url=http://... (goto), --ws-chrome-exit-page, --ws-chrome-cdp-data
--type=rtc-chrome: только client — Puppeteer + Chrome WebRTC DataChannel к exit --type=webrtc; локальный WS-мост к TUN; npm install puppeteer; --rtc-chrome-executable=PATH или PUPPETEER_EXECUTABLE_PATH`);
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
