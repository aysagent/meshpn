import pcap from 'pcap';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const PcapDns = require('pcap/decode/dns.js');

const PROTO_TCP = 6;
const PROTO_UDP = 17;

function parseArgs(argv) {
    let iface = null;
    let verbose = false;
    let filter = '';
    let perFlow = false;
    for (let i = 2; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--per-flow') {
            perFlow = true;
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
    }
    if (!iface) {
        iface = process.env.CAPTURE_IF || null;
    }
    return { iface, verbose, filter, perFlow };
}

const {
    iface: captureIface,
    verbose: verboseMode,
    filter: bpfFilter,
    perFlow: perFlowLog,
} = parseArgs(process.argv);

if (!captureIface) {
    console.error(
        'Укажите интерфейс: node scripts/traffic-classifier.js --interface=tun0\n' +
            '  или: -i tun0, либо переменная окружения CAPTURE_IF.\n' +
            'Имена к dst: DNS (UDP/53), TLS SNI (443), HTTP Host (80/8080).\n' +
            'По умолчанию логи группируются по dst IP:port и типу; построчно по потокам: --per-flow\n' +
            'Захват обычно нужно запускать с правами root: sudo node ...'
    );
    process.exit(1);
}

const session = pcap.createSession(captureIface, bpfFilter);
const flows = {};
/** @type {Map<string, Set<string>>} */
const ipToHosts = new Map();

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

    if (ip.protocol === PROTO_TCP && l4.data?.length && (l4.dport === 443 || l4.sport === 443)) {
        const sni = tryParseTlsClientHelloSni(l4.data);
        if (!sni) return;
        const serverIp = l4.dport === 443 ? String(ip.daddr) : String(ip.saddr);
        rememberHostForIp(serverIp, sni);
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
        const time = Date.now() / 1000;

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

    if (!flows[meta.key]) flows[meta.key] = [];
    flows[meta.key].push({ size: meta.size, time: meta.time, sport: meta.sport, dport: meta.dport });

    if (flows[meta.key].length > 40) flows[meta.key].shift();
});

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

/**
 * Порядок: dns → webrtc → video → web → bulk → interactive.
 * web / video / webrtc — явные эвристики; bulk — тяжёлый поток, если не попали в эти три.
 */
function classify(flow, key) {
    if (flow.length < 8) return { type: 'unknown', stats: null };

    const sizes = flow.map(p => p.size);
    const times = flow.map(p => p.time);
    const intervals = [];
    for (let i = 1; i < times.length; i++) {
        intervals.push(times[i] - times[i - 1]);
    }

    const meanSize = mean(sizes);
    const stdSize = stdDev(sizes);
    const meanInterval = mean(intervals);
    const stdInterval = stdDev(intervals);
    const ports = flowPorts(flow);
    const isUdp = key.startsWith('udp:');
    const isTcp = key.startsWith('tcp:');

    const largeShare = sizes.filter(s => s >= 1000).length / sizes.length;
    const smallShare = sizes.filter(s => s < 96).length / sizes.length;

    const stats = { meanSize, stdSize, meanInterval, stdInterval, ports };

    if (isUdp && hasPort(ports, [53]) && meanSize < 512 && meanInterval < 0.35) {
        return { type: 'dns', stats };
    }

    if (
        isUdp &&
        !hasPort(ports, [53]) &&
        meanInterval < 0.055 &&
        stdInterval < 0.035 &&
        meanSize > 0 &&
        meanSize < 1200
    ) {
        return { type: 'webrtc', stats };
    }

    const onWebPort = hasPort(ports, WEB_PORTS);

    const videoUdp =
        isUdp &&
        !hasPort(ports, [53]) &&
        meanSize >= 200 &&
        meanSize <= 1450 &&
        stdSize < 480 &&
        meanInterval < 0.1 &&
        stdInterval < 0.05;

    // На 443/80 короткий burst TLS (curl, API) совпадал с «видео»: нужен явный ровный поток крупных сегментов.
    const videoTcpLoose =
        isTcp &&
        meanSize >= 900 &&
        largeShare >= 0.35 &&
        stdInterval < 0.18 &&
        meanInterval < 0.28;
    const videoTcpStrictTls =
        largeShare >= 0.56 &&
        meanInterval < 0.12 &&
        stdInterval < 0.082 &&
        stdSize < 360;
    const videoTcp = videoTcpLoose && (!onWebPort || videoTcpStrictTls);

    if (videoUdp || videoTcp) {
        return { type: 'video', stats };
    }

    const webTcp =
        isTcp &&
        onWebPort &&
        !videoTcp &&
        (stdInterval > 0.042 ||
            (largeShare < 0.4 && stdSize > 170) ||
            (meanSize < 900 && stdInterval > 0.032) ||
            (smallShare >= 0.12 && largeShare <= 0.66));

    if (webTcp) {
        return { type: 'web', stats };
    }

    const bulkTcp =
        isTcp &&
        ((largeShare >= 0.18 && smallShare >= 0.12 && meanSize >= 320) ||
            (largeShare >= 0.3 && meanSize >= 480) ||
            meanSize >= 650);

    const bulkUdp =
        isUdp && !hasPort(ports, [53]) && meanSize >= 550 && largeShare >= 0.38 && stdSize < meanSize * 0.65;

    if (bulkTcp || bulkUdp) {
        return { type: 'bulk', stats };
    }

    if (isTcp || isUdp) {
        return { type: 'interactive', stats };
    }

    return { type: 'unknown', stats };
}

setInterval(() => {
    console.log('\n--- classification ---');

    if (perFlowLog) {
        for (const [key, flow] of Object.entries(flows)) {
            const { type, stats } = classify(flow, key);
            const hostSuffix = formatKnownHostsForKey(key);
            if (type !== 'unknown') {
                console.log(key, '→', type + hostSuffix);
            } else if (verboseMode && stats && flow.length >= 8) {
                console.log(
                    key,
                    '→ unknown' + hostSuffix,
                    `(meanPayload=${stats.meanSize.toFixed(0)} stdPayload=${stats.stdSize.toFixed(0)} ` +
                        `int=${stats.meanInterval.toFixed(3)}±${stats.stdInterval.toFixed(3)} ports=${stats.ports.join(',')})`
                );
            }
        }
        return;
    }

    /** @type {Map<string, { count: number, ports: Set<number>, ips: Set<string> }>} */
    const grouped = new Map();

    for (const [key, flow] of Object.entries(flows)) {
        const { type, stats } = classify(flow, key);
        if (type === 'unknown') {
            if (!verboseMode || !stats || flow.length < 8) continue;
        }

        const remoteEnd = inferRemoteEndpoint(key);
        const groupKey = remoteEnd ? `${remoteEnd.ip}:${remoteEnd.port}\t${type}` : `_flow\t${key}\t${type}`;
        if (!grouped.has(groupKey)) {
            grouped.set(groupKey, { count: 0, ports: new Set(), ips: new Set() });
        }
        const g = grouped.get(groupKey);
        g.count += 1;
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

        if (flowType !== 'unknown') {
            if (remoteIp != null && Number.isFinite(remotePort)) {
                console.log(`dst ${remoteIp}:${remotePort} → ${flowType}${cnt}${hostSuffix}${portsPart}`);
            } else {
                console.log(`${g._sampleKey} → ${flowType}${cnt}${hostSuffix}${portsPart}`);
            }
        } else if (verboseMode && g._unknownStats) {
            const st = g._unknownStats;
            const label =
                remoteIp != null && Number.isFinite(remotePort) ? `dst ${remoteIp}:${remotePort}` : g._sampleKey;
            console.log(
                `${label} → unknown${cnt}${hostSuffix}${portsPart}`,
                `(meanPayload=${st.meanSize.toFixed(0)} stdPayload=${st.stdSize.toFixed(0)} ` +
                    `int=${st.meanInterval.toFixed(3)}±${st.stdInterval.toFixed(3)} ports=${st.ports.join(',')})`
            );
        }
    }
}, 3000);
