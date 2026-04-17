import pcap from 'pcap';

const session = pcap.createSession('tun0', '');
const flows = {};

function getKey(pkt) {
    try {
        const ip = pkt.payload.payload;
        const tcp = ip.payload;
        return `${ip.saddr}:${tcp.sport}-${ip.daddr}:${tcp.dport}-${ip.protocol}`;
    } catch {
        return null;
    }
}

session.on('packet', raw => {
    const pkt = pcap.decode.packet(raw);
    const key = getKey(pkt);
    if (!key) return;

    const size = raw.buf.length;
    const time = Date.now() / 1000;

    if (!flows[key]) flows[key] = [];
    flows[key].push({ size, time });

    if (flows[key].length > 30) flows[key].shift();
});

function classify(flow) {
    if (flow.length < 10) return "unknown";

    const sizes = flow.map(p => p.size);
    const times = flow.map(p => p.time);

    const intervals = [];
    for (let i = 1; i < times.length; i++) {
        intervals.push(times[i] - times[i - 1]);
    }

    const mean = arr => arr.reduce((a,b)=>a+b,0)/arr.length;
    const std = arr => {
        const m = mean(arr);
        return Math.sqrt(mean(arr.map(x => (x - m) ** 2)));
    };

    const meanSize = mean(sizes);
    const stdSize = std(sizes);
    const meanInterval = mean(intervals);
    const stdInterval = std(intervals);

    // WebRTC
    if (meanInterval < 0.05 && stdInterval < 0.02 && meanSize < 1200) {
        return "webrtc";
    }

    // Web
    if (stdInterval > 0.1 && meanSize < 1000) {
        return "web";
    }

    // Video
    if (meanSize > 900 && stdInterval > 0.05) {
        return "video";
    }

    return "unknown";
}

setInterval(() => {
    console.log("\n--- classification ---");

    for (const [key, flow] of Object.entries(flows)) {
        const type = classify(flow);
        if (type !== "unknown") {
            console.log(key, "→", type);
        }
    }

}, 3000);
