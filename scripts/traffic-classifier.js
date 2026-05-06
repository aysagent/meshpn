import pcap from 'pcap';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const PcapDns = require('pcap/decode/dns.js');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PROTO_TCP = 6;
const PROTO_UDP = 17;

function parseArgs(argv) {
    let iface = null;
    let verbose = false;
    let filter = '';
    let perFlow = false;
    let rawLabels = false;
    let json = false;
    let rulesPath = null;
    let cacheFile = null;
    let showRoute = true;
    for (let i = 2; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--per-flow') {
            perFlow = true;
            continue;
        }
        if (a === '--raw-labels') {
            rawLabels = true;
            continue;
        }
        if (a === '--json') {
            json = true;
            continue;
        }
        if (a === '--no-route') {
            showRoute = false;
            continue;
        }
        if (a === '--show-route') {
            showRoute = true;
            continue;
        }
        if (a === '--verbose' || a === '-v') {
            verbose = true;
            continue;
        }
        if (a.startsWith('--interface=')) {
            iface = a.slice('--interface='.length) || null;
            continue;
        }
        if (a === '--interface' || a === '-i') {
            iface = argv[++i] ?? null;
            continue;
        }
        if (a.startsWith('-i=')) {
            iface = a.slice(3) || null;
            continue;
        }
        if (a.startsWith('--filter=')) {
            filter = a.slice('--filter='.length);
            continue;
        }
        if (a.startsWith('--rules=')) {
            rulesPath = a.slice('--rules='.length) || null;
            continue;
        }
        if (a === '--rules') {
            rulesPath = argv[++i] ?? null;
            continue;
        }
        if (a.startsWith('--cache-file=')) {
            cacheFile = a.slice('--cache-file='.length) || null;
            continue;
        }
        if (a === '--cache-file') {
            cacheFile = argv[++i] ?? null;
            continue;
        }
    }
    if (!iface) {
        iface = process.env.CAPTURE_IF || null;
    }
    return { iface, verbose, filter, perFlow, rawLabels, json, rulesPath, cacheFile, showRoute };
}

const {
    iface: captureIface,
    verbose: verboseMode,
    filter: bpfFilter,
    perFlow: perFlowLog,
    rawLabels: rawLabelsMode,
    json: jsonMode,
    rulesPath: rulesPathArg,
    cacheFile: cacheFileArg,
    showRoute: showRouteFlag,
} = parseArgs(process.argv);

if (!captureIface) {
    console.error(
        'Укажите интерфейс: node scripts/traffic-classifier.js --interface=tun0\n' +
            '  или: -i tun0, либо переменная окружения CAPTURE_IF.\n' +
            'Имена к dst: DNS (UDP/53), TLS SNI (443), HTTP Host (80/8080).\n' +
            'По умолчанию логи группируются по dst IP:port и типу; построчно по потокам: --per-flow\n' +
            'Стабильная метка + сырая: --raw-labels\n' +
            'Маршрутные категории (web/video/voice/bulk/default): --rules <file.json>, --cache-file <file>\n' +
            'JSON-события решений по маршруту: --json (по строке на событие)\n' +
            'Захват обычно нужно запускать с правами root: sudo node ...'
    );
    process.exit(1);
}

const session = pcap.createSession(captureIface, bpfFilter);
const flows = {};
/** Потоки с признаками QUIC (UDP/443), заполняется при захвате */
const quicFlowKeys = new Set();
/** Потоки с признаками STUN/RTP (заполняется при захвате) */
const stunFlowKeys = new Set();
const rtpFlowSeen = new Map();
/** Накопление TCP ClientHello для SNI (ключ потока → Buffer) */
const tlsClientStreams = {};
const TLS_STREAM_CAP = 16384;

/** @type {Map<string, Set<string>>} */
const ipToHosts = new Map();

// ======================================================
// Маршрутные категории и иерархия принятия решения
// ======================================================

const ROUTING_CATEGORIES = ['web', 'video', 'voice', 'bulk', 'default'];

/** Внутренний тип -> маршрутная категория (5 категорий + default fallback). */
const TYPE_TO_ROUTING = {
    web: 'web',
    interactive: 'web',
    quic: 'web',
    dns: 'web',
    dot: 'web',
    video: 'video',
    webrtc: 'voice',
    voice: 'voice',
    bulk: 'bulk',
    unknown: 'default',
};

/** Уверенность для иерархии: rule > early-strong > cache > stat > early-weak > default. */
const SOURCE_CONFIDENCE = {
    rule: 100,
    'early-strong': 80,
    cache: 60,
    stat: 50,
    'early-weak': 30,
    default: 0,
};

/** Решения по потокам: { category, source, confidence, host, dst, lastEmitted }. */
const flowDecisions = new Map();

/** LRU dst:port -> { category, source, ts, host? }. TTL в мс. */
const DST_CACHE_TTL_MS = 30 * 60 * 1000;
const DST_CACHE_MAX = 4096;
const dstCache = new Map();

let routingRules = [];

function loadRoutingRules() {
    const candidates = [];
    if (rulesPathArg) candidates.push(rulesPathArg);
    candidates.push(path.join(__dirname, 'traffic-routing-rules.json'));
    for (const p of candidates) {
        try {
            const raw = fs.readFileSync(p, 'utf8');
            const arr = JSON.parse(raw);
            if (!Array.isArray(arr)) continue;
            const rules = [];
            for (const item of arr) {
                if (!item || typeof item.pattern !== 'string') continue;
                if (!ROUTING_CATEGORIES.includes(item.category)) continue;
                const pat = normalizeHost(item.pattern.replace(/^\*\./, ''));
                if (!pat) continue;
                rules.push({ pattern: pat, category: item.category });
            }
            routingRules = rules;
            return p;
        } catch {
            /* file missing or malformed */
        }
    }
    routingRules = [];
    return null;
}

function categoryByHost(host) {
    if (!host || !routingRules.length) return null;
    const h = normalizeHost(host);
    for (const r of routingRules) {
        if (h === r.pattern || h.endsWith('.' + r.pattern)) return r.category;
    }
    return null;
}

function loadDstCacheFromFile() {
    if (!cacheFileArg) return;
    try {
        const raw = fs.readFileSync(cacheFileArg, 'utf8');
        const arr = JSON.parse(raw);
        if (!Array.isArray(arr)) return;
        const now = Date.now();
        for (const item of arr) {
            if (!item || typeof item.key !== 'string') continue;
            if (!ROUTING_CATEGORIES.includes(item.category)) continue;
            const ts = typeof item.ts === 'number' ? item.ts : now;
            if (now - ts > DST_CACHE_TTL_MS) continue;
            dstCache.set(item.key, { category: item.category, source: 'cache', ts, host: item.host });
        }
    } catch {
        /* missing/malformed cache */
    }
}

function saveDstCacheToFile() {
    if (!cacheFileArg) return;
    try {
        const out = [];
        for (const [key, v] of dstCache) {
            out.push({ key, category: v.category, ts: v.ts, host: v.host });
        }
        fs.writeFileSync(cacheFileArg, JSON.stringify(out));
    } catch {
        /* IO error */
    }
}

function dstKey(ip, port) {
    return `${ip}:${port}`;
}

function dstCacheGet(key) {
    const v = dstCache.get(key);
    if (!v) return null;
    if (Date.now() - v.ts > DST_CACHE_TTL_MS) {
        dstCache.delete(key);
        return null;
    }
    return v;
}

function dstCachePut(key, category, host) {
    if (dstCache.size >= DST_CACHE_MAX) {
        const firstKey = dstCache.keys().next().value;
        if (firstKey !== undefined) dstCache.delete(firstKey);
    }
    dstCache.set(key, { category, source: 'cache', ts: Date.now(), host });
}

function emitDecision(flowKey, decision, eventName) {
    if (!jsonMode) return;
    const line = JSON.stringify({
        ts: Date.now(),
        event: eventName,
        flow: flowKey,
        dst: decision.dst,
        category: decision.category,
        source: decision.source,
        host: decision.host || null,
    });
    process.stdout.write(line + '\n');
}

function recordDecision(flowKey, dstIp, dstPort, category, source, host) {
    const conf = SOURCE_CONFIDENCE[source] ?? 0;
    const dst = dstIp != null && Number.isFinite(dstPort) ? `${dstIp}:${dstPort}` : null;
    const prev = flowDecisions.get(flowKey);
    if (prev) {
        if (conf < prev.confidence) return prev;
        if (
            prev.category === category &&
            prev.source === source &&
            (!host || prev.host === host)
        ) {
            return prev;
        }
    }
    const next = { category, source, confidence: conf, host: host || prev?.host || null, dst };
    flowDecisions.set(flowKey, next);
    if (!prev) emitDecision(flowKey, next, 'first-decision');
    else if (prev.category !== category) emitDecision(flowKey, next, 'category-change');
    return next;
}

function looksLikeStunHeader(buf) {
    if (!buf || buf.length < 20) return false;
    if ((buf[0] & 0xc0) !== 0) return false;
    const cookie = buf.readUInt32BE(4);
    return cookie === 0x2112a442;
}

function looksLikeRtp(buf) {
    if (!buf || buf.length < 12) return false;
    const v = (buf[0] & 0xc0) >> 6;
    if (v !== 2) return false;
    const pt = buf[1] & 0x7f;
    if (pt >= 64 && pt <= 95) return false; // RTCP диапазон
    return true;
}

function rtpCategoryByPayloadType(pt) {
    // Стандартные PT (RFC 3551). Динамические — определяем по pps/размерам отдельно.
    if (pt === 0 || pt === 8 || pt === 9 || pt === 18 || pt === 96 || pt === 97) return 'voice';
    if (pt === 26 || pt === 31 || pt === 32 || pt === 33 || pt === 34) return 'video';
    return null;
}

function noteRtpPacket(flowKey, buf) {
    if (!looksLikeRtp(buf)) return;
    const entry = rtpFlowSeen.get(flowKey) || { count: 0, pts: new Set() };
    entry.count += 1;
    entry.pts.add(buf[1] & 0x7f);
    rtpFlowSeen.set(flowKey, entry);
}

const VOICE_PORTS = new Set([3478, 5349, 3479, 5060, 5061, 5004, 5005, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309]);
const SIP_PORTS = new Set([5060, 5061]);

function earlyCategoryFromEarlyHints(flowKey, dstIp, dstPort, srcPort, isUdp, host) {
    if (host) {
        const c = categoryByHost(host);
        if (c) return { category: c, source: 'rule', host, strong: true };
    }
    if (isUdp && stunFlowKeys.has(flowKey)) {
        return { category: 'voice', source: 'early-strong', strong: true };
    }
    const rtpInfo = rtpFlowSeen.get(flowKey);
    if (isUdp && rtpInfo && rtpInfo.count >= 3) {
        for (const pt of rtpInfo.pts) {
            const c = rtpCategoryByPayloadType(pt);
            if (c) return { category: c, source: 'early-strong', strong: true };
        }
        return { category: 'voice', source: 'early-strong', strong: true };
    }
    const cached = dstIp != null ? dstCacheGet(dstKey(dstIp, dstPort)) : null;
    if (cached) {
        return { category: cached.category, source: 'cache', host: cached.host, strong: false };
    }
    if (isUdp && (VOICE_PORTS.has(dstPort) || VOICE_PORTS.has(srcPort))) {
        return { category: 'voice', source: 'early-weak' };
    }
    if (!isUdp && (SIP_PORTS.has(dstPort) || SIP_PORTS.has(srcPort))) {
        return { category: 'voice', source: 'early-weak' };
    }
    if (isUdp && quicFlowKeys.has(flowKey)) {
        return { category: 'web', source: 'early-weak' };
    }
    if (dstPort === 443 || dstPort === 80 || dstPort === 8080 || dstPort === 8443 || dstPort === 853) {
        return { category: 'web', source: 'early-weak' };
    }
    if (srcPort === 443 || srcPort === 80 || srcPort === 8080 || srcPort === 8443 || srcPort === 853) {
        return { category: 'web', source: 'early-weak' };
    }
    return null;
}

function packetTimeSec(pkt) {
    const h = pkt?.pcap_header;
    if (h && typeof h.tv_sec === 'number') {
        return h.tv_sec + (h.tv_usec ?? 0) * 1e-6;
    }
    return Date.now() * 1e-3;
}

function looksLikeQuicFirstUdpPayload(buf) {
    if (!buf || buf.length < 8) return false;
    if (buf[0] & 0x80) return true;
    const ver = buf.readUInt32BE(1);
    if (ver === 0 || ver === 0x51303434 || (ver >>> 8) === 0xff0000) return true;
    return false;
}

function appendTlsClientStream(flowKey, chunk, serverIp) {
    if (!chunk?.length) return;
    let buf = tlsClientStreams[flowKey];
    if (!buf) buf = Buffer.alloc(0);
    if (buf.length >= TLS_STREAM_CAP) return;
    const room = TLS_STREAM_CAP - buf.length;
    const take = Math.min(chunk.length, room);
    buf = Buffer.concat([buf, chunk.subarray(0, take)]);
    tlsClientStreams[flowKey] = buf;
    const sni = tryParseTlsClientHelloSni(buf);
    if (sni) {
        rememberHostForIp(serverIp, sni);
        delete tlsClientStreams[flowKey];
    } else if (buf.length >= TLS_STREAM_CAP) {
        delete tlsClientStreams[flowKey];
    }
}

function normalizeHost(name) {
    if (!name || typeof name !== 'string') return '';
    return name.replace(/\.$/, '').toLowerCase();
}

function rememberHostForIp(ip, host) {
    const h = normalizeHost(host);
    if (!h || h.length > 253) return;
    let s = ipToHosts.get(ip);
    if (!s) {
        s = new Set();
        ipToHosts.set(ip, s);
    }
    s.add(h);
    if (s.size > 16) {
        const arr = [...s];
        ipToHosts.set(ip, new Set(arr.slice(-12)));
    }
}

/** TLS ClientHello: расширение server_name (0). Только первый фрагмент в буфере. */
function tryParseTlsClientHelloSni(buf) {
    if (!buf || buf.length < 43) return null;
    if (buf[0] !== 0x16) return null;
    const recLen = buf.readUInt16BE(3);
    if (4 + recLen > buf.length || recLen < 42) return null;
    let o = 5;
    if (buf[o] !== 0x01) return null;
    const hsBodyLen = buf.readUIntBE(o + 1, 3);
    o += 4;
    if (o + 34 > buf.length) return null;
    o += 2 + 32;
    const sidLen = buf[o];
    o += 1 + sidLen;
    if (o + 2 > buf.length) return null;
    const cipherLen = buf.readUInt16BE(o);
    o += 2;
    if (o + cipherLen > buf.length) return null;
    o += cipherLen;
    if (o + 1 > buf.length) return null;
    const compLen = buf[o];
    o += 1 + compLen;
    if (o + 2 > buf.length) return null;
    const extLen = buf.readUInt16BE(o);
    o += 2;
    const extEnd = o + extLen;
    if (extEnd > buf.length) return null;
    while (o + 4 <= extEnd) {
        const et = buf.readUInt16BE(o);
        const el = buf.readUInt16BE(o + 2);
        o += 4;
        if (o + el > extEnd) break;
        if (et === 0 && el >= 5) {
            const listLen = buf.readUInt16BE(o);
            let p = o + 2;
            const lim = o + el;
            if (p + listLen > lim) break;
            while (p + 3 <= lim) {
                const nameType = buf[p];
                const nameLen = buf.readUInt16BE(p + 1);
                p += 3;
                if (p + nameLen > lim) break;
                if (nameType === 0 && nameLen > 0) {
                    return buf.subarray(p, p + nameLen).toString('utf8');
                }
                p += nameLen;
            }
        }
        o += el;
    }
    return null;
}

/** A-запись DNS: rdata как строка, Buffer из 4 байт или массив октетов. */
function dnsRdataToIpv4String(rdata) {
    if (!rdata) return null;
    if (typeof rdata === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(rdata)) return rdata;
    if (Buffer.isBuffer(rdata) && rdata.length === 4) {
        return `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
    }
    if (Array.isArray(rdata) && rdata.length === 4) {
        return rdata.map((n) => Number(n) & 0xff).join('.');
    }
    const s = String(rdata);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s;
    return null;
}

/** Первый запрос HTTP/1.x: строка Host: (для портов 80/8080 без TLS). */
function tryParseHttpHostHeader(buf) {
    if (!buf || buf.length < 16) return null;
    const n = Math.min(buf.length, 4096);
    const s = buf.subarray(0, n).toString('latin1');
    const m = /\r\n[Hh][Oo][Ss][Tt]:\s*([^\r\n]+)/.exec(s);
    if (!m) return null;
    let h = m[1].trim();
    if (!h.includes('[')) {
        const portTail = /^(.+):(\d{1,5})$/.exec(h);
        if (portTail && /^\d+$/.test(portTail[2])) h = portTail[1];
    }
    const norm = normalizeHost(h);
    return norm || null;
}

function ingestDnsAndTls(pkt) {
    const ip = extractIPv4(pkt);
    if (!ip || !ip.payload) return;

    const l4 = ip.payload;
    if (ip.protocol === PROTO_UDP && (l4.sport === 53 || l4.dport === 53) && l4.data?.length) {
        try {
            const dns = new PcapDns(null).decode(l4.data, 0);
            if (!dns.header?.isResponse || dns._error) return;
            const answers = dns.answer?.rrs;
            if (!answers?.length) return;
            for (const rr of answers) {
                if (rr.type === 1 && rr.class === 1 && rr.name) {
                    const ipStr = dnsRdataToIpv4String(rr.rdata);
                    if (ipStr) rememberHostForIp(ipStr, rr.name);
                }
            }
        } catch {
            /* malformed DNS */
        }
        return;
    }

    if (ip.protocol === PROTO_TCP && l4.data?.length) {
        const dweb = l4.dport === 80 || l4.dport === 8080;
        const sweb = l4.sport === 80 || l4.sport === 8080;
        if (dweb || sweb) {
            const host = tryParseHttpHostHeader(l4.data);
            if (host) {
                const serverIp = dweb ? String(ip.daddr) : String(ip.saddr);
                rememberHostForIp(serverIp, host);
            }
        }
    }

    if (ip.protocol === PROTO_TCP && l4.data?.length && l4.dport === 443) {
        const flowKey = canonicalFlowKey('tcp', ip, l4.sport, l4.dport);
        appendTlsClientStream(flowKey, l4.data, String(ip.daddr));
    }
}

function parseIpsFromFlowKey(key) {
    const rest = key.replace(/^(tcp|udp):/, '');
    const parts = rest.split('<->');
    if (parts.length !== 2) return [];
    const out = [];
    for (const side of parts) {
        const colon = side.lastIndexOf(':');
        if (colon <= 0) continue;
        out.push(side.slice(0, colon));
    }
    return out;
}

function formatKnownHostsForKey(key) {
    const ips = parseIpsFromFlowKey(key);
    const names = new Set();
    for (const ip of ips) {
        const set = ipToHosts.get(ip);
        if (set) for (const h of set) names.add(h);
    }
    if (names.size === 0) return '';
    return ` names=${[...names].join(',')}`;
}

/** Порты «серверной» стороны для группировки по удалённому IP. */
const WELL_KNOWN_SERVICE_PORTS = new Set([
    20, 21, 22, 25, 53, 80, 110, 143, 443, 853, 993, 995, 8080, 8443, 5201,
]);

function isPrivateIpv4(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 127) return true;
    return false;
}

function parseFlowEndpoints(key) {
    const isUdp = key.startsWith('udp:');
    const rest = key.replace(/^(tcp|udp):/, '');
    const [left, right] = rest.split('<->');
    if (!left || !right) return null;
    const side = s => {
        const c = s.lastIndexOf(':');
        if (c <= 0) return null;
        const port = parseInt(s.slice(c + 1), 10);
        if (!Number.isFinite(port)) return null;
        return { ip: s.slice(0, c), port };
    };
    const a = side(left);
    const b = side(right);
    if (!a || !b) return null;
    return { isUdp, a, b };
}

/**
 * Удалённая сторона (ip:port) для группировки логов.
 * P2P без явного «сервера» — null (каждый поток отдельно).
 * @returns {{ ip: string, port: number } | null}
 */
function inferRemoteEndpoint(key) {
    const ep = parseFlowEndpoints(key);
    if (!ep) return null;
    const { a, b } = ep;
    const aSvc = WELL_KNOWN_SERVICE_PORTS.has(a.port) || a.port <= 1024;
    const bSvc = WELL_KNOWN_SERVICE_PORTS.has(b.port) || b.port <= 1024;
    if (aSvc && !bSvc) return { ip: a.ip, port: a.port };
    if (bSvc && !aSvc) return { ip: b.ip, port: b.port };
    if (aSvc && bSvc) return a.port <= b.port ? { ip: a.ip, port: a.port } : { ip: b.ip, port: b.port };
    const aPriv = isPrivateIpv4(a.ip);
    const bPriv = isPrivateIpv4(b.ip);
    if (aPriv !== bPriv) return aPriv ? { ip: b.ip, port: b.port } : { ip: a.ip, port: a.port };
    return null;
}

function collectNamesForIps(ips) {
    const names = new Set();
    for (const ip of ips) {
        const set = ipToHosts.get(ip);
        if (set) for (const h of set) names.add(h);
    }
    return names;
}

/** IPv4 слой: RAW / Ethernet / SLL / NULL */
function extractIPv4(pkt) {
    const link = pkt.payload;
    if (!link) return null;
    if (link.decoderName === 'ipv4') return link;
    if (link.payload?.decoderName === 'ipv4') return link.payload;
    return null;
}

function l4PayloadSize(ip, l4) {
    if (ip.protocol === PROTO_TCP && l4.dataLength !== undefined) {
        return Math.max(0, l4.dataLength);
    }
    if (ip.protocol === PROTO_UDP) {
        if (l4.data && l4.data.length !== undefined) return l4.data.length;
        if (l4.length !== undefined) return Math.max(0, l4.length - 8);
    }
    return 0;
}

function canonicalFlowKey(protoName, ip, sport, dport) {
    const sa = String(ip.saddr);
    const da = String(ip.daddr);
    const left = `${sa}:${sport}`;
    const right = `${da}:${dport}`;
    const [a, b] = left < right ? [left, right] : [right, left];
    return `${protoName}:${a}<->${b}`;
}

function flowMetaFromPacket(pkt) {
    try {
        const ip = extractIPv4(pkt);
        if (!ip || (ip.protocol !== PROTO_TCP && ip.protocol !== PROTO_UDP)) return null;

        const l4 = ip.payload;
        if (!l4 || l4.sport === undefined || l4.dport === undefined) return null;

        const protoName = ip.protocol === PROTO_TCP ? 'tcp' : 'udp';
        const key = canonicalFlowKey(protoName, ip, l4.sport, l4.dport);
        const size = l4PayloadSize(ip, l4);
        const time = packetTimeSec(pkt);

        return { key, size, time, sport: l4.sport, dport: l4.dport, proto: ip.protocol };
    } catch {
        return null;
    }
}

session.on('packet', raw => {
    const pkt = pcap.decode.packet(raw);
    ingestDnsAndTls(pkt);
    const meta = flowMetaFromPacket(pkt);
    if (!meta) return;

    const ip = extractIPv4(pkt);
    const l4 = ip?.payload;

    if (meta.proto === PROTO_UDP && (meta.dport === 443 || meta.sport === 443)) {
        if (l4?.data && looksLikeQuicFirstUdpPayload(l4.data)) {
            quicFlowKeys.add(meta.key);
        }
    }

    if (meta.proto === PROTO_UDP && l4?.data?.length) {
        if (looksLikeStunHeader(l4.data)) stunFlowKeys.add(meta.key);
        else noteRtpPacket(meta.key, l4.data);
    }

    if (!flows[meta.key]) flows[meta.key] = [];
    flows[meta.key].push({ size: meta.size, time: meta.time, sport: meta.sport, dport: meta.dport });

    if (flows[meta.key].length > 40) flows[meta.key].shift();

    evaluateRoutingForPacket(meta, ip);
});

function evaluateRoutingForPacket(meta, ip) {
    const remote = inferRemoteEndpoint(meta.key);
    const dstIp = remote?.ip ?? null;
    const dstPort = remote?.port ?? null;
    const isUdp = meta.proto === PROTO_UDP;

    let host = null;
    if (dstIp) {
        const set = ipToHosts.get(dstIp);
        if (set) host = set.values().next().value || null;
    }

    const early = earlyCategoryFromEarlyHints(meta.key, dstIp, dstPort, meta.sport, isUdp, host);
    if (early) {
        recordDecision(meta.key, dstIp, dstPort, early.category, early.source, early.host || host);
    } else if (!flowDecisions.has(meta.key)) {
        recordDecision(meta.key, dstIp, dstPort, 'default', 'default', host);
    }
}

function mean(arr) {
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stdDev(arr) {
    const m = mean(arr);
    return Math.sqrt(mean(arr.map(x => (x - m) ** 2)));
}

function flowPorts(flow) {
    const s = new Set();
    for (const p of flow) {
        s.add(p.sport);
        s.add(p.dport);
    }
    return [...s];
}

function hasPort(ports, list) {
    return list.some(pr => ports.includes(pr));
}

const WEB_PORTS = [80, 443, 8080, 8443];

/** Скоринг: разрыв между 1-м и 2-м местом и минимальный балл уверенного класса */
const SCORE_GAP = 0.085;
const SCORE_MIN = 0.3;

const flowHistories = {};
const stableMemo = {};

function clamp01(x) {
    return Math.max(0, Math.min(1, x));
}

function median(arr) {
    if (!arr.length) return 0;
    const s = [...arr].sort((a, b) => a - b);
    const m = Math.floor(s.length / 2);
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function flowPps(times) {
    const span = Math.max(times[times.length - 1] - times[0], 1e-9);
    return (times.length - 1) / span;
}

function stableLabelForFlow(key, rawType) {
    const h = (flowHistories[key] = flowHistories[key] || []);
    h.push(rawType);
    while (h.length > 5) h.shift();

    let candidate = rawType;
    if (h.length >= 2 && h[h.length - 1] === h[h.length - 2]) {
        candidate = rawType;
    } else {
        const cnt = {};
        for (const t of h) cnt[t] = (cnt[t] || 0) + 1;
        const top = Object.entries(cnt).sort((a, b) => b[1] - a[1])[0];
        if (top && top[1] / h.length >= 0.6) candidate = top[0];
        else candidate = stableMemo[key] ?? rawType;
    }
    stableMemo[key] = candidate;
    return candidate;
}

function extractFlowFeatures(flow, key) {
    const sizes = flow.map(p => p.size);
    const times = flow.map(p => p.time);
    const intervals = [];
    for (let i = 1; i < times.length; i++) {
        intervals.push(Math.max(times[i] - times[i - 1], 0));
    }
    const meanSize = mean(sizes);
    const stdSize = stdDev(sizes);
    const meanInterval = intervals.length ? mean(intervals) : 0;
    const stdInterval = intervals.length ? stdDev(intervals) : 0;
    const medInterval = median(intervals.length ? intervals : [0.01]);
    const ports = flowPorts(flow);
    const isUdp = key.startsWith('udp:');
    const isTcp = key.startsWith('tcp:');
    const pps = flowPps(times);
    const largeShare = sizes.filter(s => s >= 1000).length / sizes.length;
    const smallShare = sizes.filter(s => s < 96).length / sizes.length;
    const onWebPort = hasPort(ports, WEB_PORTS);
    return {
        sizes,
        times,
        intervals,
        meanSize,
        stdSize,
        meanInterval,
        stdInterval,
        medInterval,
        pps,
        ports,
        isUdp,
        isTcp,
        largeShare,
        smallShare,
        onWebPort,
    };
}

function scoreWebrtcUdp(f) {
    if (!f.isUdp || hasPort(f.ports, [53])) return 0;
    const p = clamp01((f.pps - 20) / 220) * clamp01((2200 - f.pps) / 2000) * clamp01((1250 - f.meanSize) / 1100);
    const timing = f.medInterval < 0.08 ? 0.9 : f.medInterval < 0.2 ? 0.55 : 0.25;
    return 0.1 + 0.55 * p * timing + 0.15 * clamp01((0.06 - f.stdInterval) / 0.05);
}

function scoreVideoUdp(f) {
    if (!f.isUdp || hasPort(f.ports, [53])) return 0;
    const sizeBand = f.meanSize >= 200 && f.meanSize <= 1450 ? clamp01(1 - Math.abs(f.meanSize - 750) / 650) : 0;
    const steady = clamp01(1 - f.stdSize / 520);
    const rate = f.pps > 8 && f.pps < 1500 ? clamp01(1 - Math.abs(Math.log(f.pps + 1) - Math.log(200)) / 4) : 0.2;
    return 0.15 + 0.4 * sizeBand + 0.25 * steady + 0.2 * rate;
}

function scoreVideoTcp(f) {
    if (!f.isTcp) return 0;
    const loose =
        f.meanSize >= 880 &&
        f.largeShare >= 0.33 &&
        f.stdInterval < 0.22 &&
        f.meanInterval < 0.35;
    if (!loose) return 0;
    const strictTls =
        f.largeShare >= 0.55 &&
        f.meanInterval < 0.14 &&
        f.stdInterval < 0.095 &&
        f.stdSize < 380;
    if (f.onWebPort && !strictTls) return 0.12;
    return strictTls ? 0.92 : 0.58;
}

function scoreWebTcp(f) {
    if (!f.isTcp || !f.onWebPort) return 0;
    const videoTcpLoose =
        f.meanSize >= 880 &&
        f.largeShare >= 0.33 &&
        f.stdInterval < 0.22 &&
        f.meanInterval < 0.35;
    const videoStrict =
        f.largeShare >= 0.55 &&
        f.meanInterval < 0.14 &&
        f.stdInterval < 0.095 &&
        f.stdSize < 380;
    if (videoTcpLoose && (!f.onWebPort || videoStrict)) return 0.08;

    const webShape =
        f.stdInterval > 0.032 ||
        (f.largeShare < 0.42 && f.stdSize > 150) ||
        (f.meanSize < 920 && f.stdInterval > 0.022) ||
        (f.smallShare >= 0.12 && f.largeShare <= 0.66);
    return webShape ? 0.78 : 0.22;
}

function scoreBulkTcp(f) {
    if (!f.isTcp) return 0;
    let s = 0;
    if (f.largeShare >= 0.18 && f.smallShare >= 0.12 && f.meanSize >= 300) s += 0.35;
    if (f.largeShare >= 0.28 && f.meanSize >= 460) s += 0.35;
    if (f.meanSize >= 620) s += 0.35;
    return clamp01(s);
}

function scoreBulkUdp(f) {
    if (!f.isUdp || hasPort(f.ports, [53])) return 0;
    if (f.meanSize < 520 || f.largeShare < 0.35) return 0;
    return clamp01(0.25 + 0.45 * clamp01((f.meanSize - 520) / 700) + 0.35 * clamp01(1 - f.stdSize / Math.max(f.meanSize, 1)));
}

/**
 * Сырая классификация: жёстко quic / dns / dot, далее скоринг webrtc|video|web|bulk vs interactive.
 */
function classifyRaw(flow, key) {
    if (flow.length < 8) return { type: 'unknown', stats: null, rawType: 'unknown' };

    const f = extractFlowFeatures(flow, key);
    const stats = {
        meanSize: f.meanSize,
        stdSize: f.stdSize,
        meanInterval: f.meanInterval,
        stdInterval: f.stdInterval,
        medInterval: f.medInterval,
        pps: f.pps,
        ports: f.ports,
    };

    if (f.isUdp && quicFlowKeys.has(key)) {
        return { type: 'quic', stats, rawType: 'quic' };
    }
    if (f.isUdp && hasPort(f.ports, [53]) && f.meanSize < 512 && (f.medInterval < 0.35 || f.pps < 450)) {
        return { type: 'dns', stats, rawType: 'dns' };
    }
    if (f.isTcp && hasPort(f.ports, [853]) && f.meanSize < 540 && f.medInterval < 0.45) {
        return { type: 'dot', stats, rawType: 'dot' };
    }

    const scores = {
        webrtc: f.isUdp ? scoreWebrtcUdp(f) : 0,
        video: Math.max(f.isUdp ? scoreVideoUdp(f) : 0, scoreVideoTcp(f)),
        web: scoreWebTcp(f),
        bulk: Math.max(scoreBulkTcp(f), scoreBulkUdp(f)),
        interactive: 0.14,
    };

    const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
    const [best, s1] = ranked[0];
    const s2 = ranked[1][1];
    let raw = best;
    if (s1 < SCORE_MIN || s1 - s2 < SCORE_GAP) {
        raw = 'interactive';
    }

    if (raw === 'interactive' && (f.isTcp || f.isUdp)) {
        return { type: 'interactive', stats, rawType: 'interactive' };
    }
    return { type: raw, stats, rawType: raw };
}

/** Промоушен: после статистики обновим решение и кэш dst:port -> category. */
function applyStatToDecision(key, type) {
    if (type === 'unknown') return null;
    const routing = TYPE_TO_ROUTING[type] || 'default';
    const remote = inferRemoteEndpoint(key);
    const dstIp = remote?.ip ?? null;
    const dstPort = remote?.port ?? null;
    let host = null;
    if (dstIp) {
        const set = ipToHosts.get(dstIp);
        if (set) host = set.values().next().value || null;
    }
    const dec = recordDecision(key, dstIp, dstPort, routing, 'stat', host);
    if (routing !== 'default' && dstIp && Number.isFinite(dstPort)) {
        const k = dstKey(dstIp, dstPort);
        const prev = dstCacheGet(k);
        if (!prev || prev.category !== routing) {
            dstCachePut(k, routing, host || prev?.host);
        } else {
            dstCachePut(k, routing, host || prev.host);
        }
    }
    return dec;
}

function decisionRouteSuffix(key) {
    if (!showRouteFlag) return '';
    const dec = flowDecisions.get(key);
    if (!dec) return '';
    return ` route=${dec.category}/${dec.source}`;
}

function decisionRouteSuffixForGroup(g) {
    if (!showRouteFlag) return '';
    if (!g.routes || !g.routes.size) return '';
    if (g.routes.size === 1) {
        const [r] = g.routes;
        return ` route=${r}`;
    }
    return ` route=${[...g.routes].sort().join('|')}`;
}

setInterval(() => {
    console.log('\n--- classification ---');

    if (perFlowLog) {
        for (const [key, flow] of Object.entries(flows)) {
            const { type: rawType, stats } = classifyRaw(flow, key);
            const type = stableLabelForFlow(key, rawType);
            applyStatToDecision(key, type);
            const rawSuffix = rawLabelsMode ? ` (raw=${rawType})` : '';
            const hostSuffix = formatKnownHostsForKey(key);
            const routeSuffix = decisionRouteSuffix(key);
            if (type !== 'unknown') {
                console.log(key, '→', type + hostSuffix + routeSuffix + rawSuffix);
            } else if (verboseMode && stats && flow.length >= 8) {
                console.log(
                    key,
                    '→ unknown' + hostSuffix + routeSuffix + rawSuffix,
                    `(meanPayload=${stats.meanSize.toFixed(0)} stdPayload=${stats.stdSize.toFixed(0)} ` +
                        `int=${stats.meanInterval.toFixed(3)}±${stats.stdInterval.toFixed(3)} ports=${stats.ports.join(',')})`
                );
            }
        }
        return;
    }

    /** @type {Map<string, { count: number, ports: Set<number>, ips: Set<string>, rawTypes: Set<string>, routes: Set<string> }>} */
    const grouped = new Map();

    for (const [key, flow] of Object.entries(flows)) {
        const { type: rawType, stats } = classifyRaw(flow, key);
        const type = stableLabelForFlow(key, rawType);
        applyStatToDecision(key, type);

        if (type === 'unknown') {
            if (!verboseMode || !stats || flow.length < 8) continue;
        }

        const remoteEnd = inferRemoteEndpoint(key);
        const groupKey = remoteEnd ? `${remoteEnd.ip}:${remoteEnd.port}\t${type}` : `_flow\t${key}\t${type}`;
        if (!grouped.has(groupKey)) {
            grouped.set(groupKey, {
                count: 0,
                ports: new Set(),
                ips: new Set(),
                rawTypes: new Set(),
                routes: new Set(),
            });
        }
        const g = grouped.get(groupKey);
        g.count += 1;
        g.rawTypes.add(rawType);
        const dec = flowDecisions.get(key);
        if (dec) g.routes.add(dec.category);
        for (const ip of parseIpsFromFlowKey(key)) g.ips.add(ip);
        const ep = parseFlowEndpoints(key);
        if (ep) {
            if (remoteEnd) {
                if (ep.a.ip === remoteEnd.ip && ep.a.port === remoteEnd.port) g.ports.add(ep.a.port);
                if (ep.b.ip === remoteEnd.ip && ep.b.port === remoteEnd.port) g.ports.add(ep.b.port);
            } else {
                g.ports.add(ep.a.port);
                g.ports.add(ep.b.port);
            }
        }
        g._unknownStats = type === 'unknown' ? stats : g._unknownStats;
        g._sampleKey = key;
    }

    const sortedKeys = [...grouped.keys()].sort();
    for (const gk of sortedKeys) {
        const g = grouped.get(gk);
        const parts = gk.split('\t');
        let remoteIp = null;
        let remotePort = null;
        let flowType;
        if (parts[0] === '_flow') {
            flowType = parts[parts.length - 1];
        } else {
            const hostPort = parts[0];
            const colon = hostPort.lastIndexOf(':');
            remoteIp = hostPort.slice(0, colon);
            remotePort = parseInt(hostPort.slice(colon + 1), 10);
            flowType = parts[1];
        }

        const names = collectNamesForIps([...g.ips]);
        const hostSuffix = names.size ? ` names=${[...names].join(',')}` : '';
        const portsStr = [...g.ports].sort((a, b) => a - b).join(',');
        const portsPart =
            remoteIp != null && Number.isFinite(remotePort) ? '' : portsStr ? ` ports=${portsStr}` : '';
        const cnt = g.count > 1 ? ` ×${g.count}` : '';
        const rawList = g.rawTypes ? [...g.rawTypes].sort().join('|') : '';
        const rawSuffix =
            rawLabelsMode && rawList && (g.rawTypes.size > 1 || rawList !== flowType)
                ? ` (raw=${rawList})`
                : '';
        const routeSuffix = decisionRouteSuffixForGroup(g);

        if (flowType !== 'unknown') {
            if (remoteIp != null && Number.isFinite(remotePort)) {
                console.log(`dst ${remoteIp}:${remotePort} → ${flowType}${cnt}${hostSuffix}${routeSuffix}${portsPart}${rawSuffix}`);
            } else {
                console.log(`${g._sampleKey} → ${flowType}${cnt}${hostSuffix}${routeSuffix}${portsPart}${rawSuffix}`);
            }
        } else if (verboseMode && g._unknownStats) {
            const st = g._unknownStats;
            const label =
                remoteIp != null && Number.isFinite(remotePort) ? `dst ${remoteIp}:${remotePort}` : g._sampleKey;
            console.log(
                `${label} → unknown${cnt}${hostSuffix}${routeSuffix}${portsPart}${rawSuffix}`,
                `(meanPayload=${st.meanSize.toFixed(0)} stdPayload=${st.stdSize.toFixed(0)} ` +
                    `int=${st.meanInterval.toFixed(3)}±${st.stdInterval.toFixed(3)} ports=${st.ports.join(',')})`
            );
        }
    }
}, 3000);

// === Инициализация после определения функций классификатора ===
const _rulesPath = loadRoutingRules();
if (_rulesPath) {
    process.stderr.write(`[classifier] loaded routing rules: ${_rulesPath} (${routingRules.length} entries)\n`);
}
loadDstCacheFromFile();
if (cacheFileArg) {
    setInterval(saveDstCacheToFile, 30 * 1000);
    process.on('exit', () => saveDstCacheToFile());
    process.on('SIGINT', () => {
        saveDstCacheToFile();
        process.exit(0);
    });
    process.on('SIGTERM', () => {
        saveDstCacheToFile();
        process.exit(0);
    });
}
