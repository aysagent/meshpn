import pcap from 'pcap';

const PROTO_TCP = 6;
const PROTO_UDP = 17;

function parseArgs(argv) {
    let iface = null;
    let verbose = false;
    let filter = '';
    for (let i = 2; i < argv.length; i++) {
        const a = argv[i];
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
    return { iface, verbose, filter };
}

const { iface: captureIface, verbose: verboseMode, filter: bpfFilter } = parseArgs(process.argv);

if (!captureIface) {
    console.error(
        'Укажите интерфейс: node scripts/traffic-classifier.js --interface=tun0\n' +
            '  или: -i tun0, либо переменная окружения CAPTURE_IF.\n' +
            'Захват обычно нужно запускать с правами root: sudo node ...'
    );
    process.exit(1);
}

const session = pcap.createSession(captureIface, bpfFilter);
const flows = {};

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

/**
 * Классы по форме трафика, не по приложению:
 * dns — UDP 53, мелкие запросы
 * bulk — устойчивый поток крупных сегментов (iperf/scp/загрузки), TCP или «тяжёлый» UDP
 * realtime — частый ровный UDP с небольшим payload (игры/voip/webrtc)
 * streaming — ровный поток средних UDP или крупный ровный TCP (HLS-подобное по форме)
 * interactive — всё остальное осмысленное (запрос-ответ, смешанные размеры, любые порты)
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

    // TCP: чередование крупных данных и мелких ACK / или много MSS — iperf, передача файлов
    const bulkTcp =
        isTcp &&
        ((largeShare >= 0.18 && smallShare >= 0.12 && meanSize >= 320) ||
            (largeShare >= 0.3 && meanSize >= 480) ||
            meanSize >= 650);

    // UDP: тяжёлый однородный поток (iperf -u и т.п.)
    const bulkUdp =
        isUdp && !hasPort(ports, [53]) && meanSize >= 550 && largeShare >= 0.38 && stdSize < meanSize * 0.65;

    if (bulkTcp || bulkUdp) {
        return { type: 'bulk', stats };
    }

    if (
        isUdp &&
        meanInterval < 0.055 &&
        stdInterval < 0.035 &&
        meanSize > 0 &&
        meanSize < 900
    ) {
        return { type: 'realtime', stats };
    }

    if (
        isUdp &&
        meanSize >= 180 &&
        meanSize <= 1450 &&
        stdSize < 480 &&
        meanInterval < 0.1 &&
        stdInterval < 0.05
    ) {
        return { type: 'streaming', stats };
    }

    if (isTcp && meanSize >= 900 && largeShare >= 0.35 && stdInterval < 0.18 && meanInterval < 0.28) {
        return { type: 'streaming', stats };
    }

    if (isTcp || isUdp) {
        return { type: 'interactive', stats };
    }

    return { type: 'unknown', stats };
}

setInterval(() => {
    console.log('\n--- classification ---');

    for (const [key, flow] of Object.entries(flows)) {
        const { type, stats } = classify(flow, key);
        if (type !== 'unknown') {
            console.log(key, '→', type);
        } else if (verboseMode && stats && flow.length >= 8) {
            console.log(
                key,
                '→ unknown',
                `(meanPayload=${stats.meanSize.toFixed(0)} stdPayload=${stats.stdSize.toFixed(0)} ` +
                    `int=${stats.meanInterval.toFixed(3)}±${stats.stdInterval.toFixed(3)} ports=${stats.ports.join(',')})`
            );
        }
    }
}, 3000);
