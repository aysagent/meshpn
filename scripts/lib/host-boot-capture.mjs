/** Bounded early-boot observer. No packet bodies are stored, decoded or logged. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const captureName = 'clean-vpn-boot-capture';
export const captureDir = '/var/lib/clean-vpn-boot-capture';
export const consumers = ['systemd-networkd.service', 'systemd-networkd.socket',
  'netplan-wpa-wlan0.service', 'wpa_supplicant.service',
  'wpa_supplicant@wlan0.service', 'wpa_supplicant-nl80211@wlan0.service',
  'wpa_supplicant-wired@wlan0.service'];
export const gateText = `# clean-vpn-boot-capture-v1\n[Unit]\nRequires=${captureName}.service\nAfter=${captureName}.service\n`;
export const gatePath = unit => `/etc/systemd/system/${unit}.d/91-clean-vpn-boot-capture.conf`;
export function captureUnit(node) {
  assert.match(node, /^\/[A-Za-z0-9_./-]+$/);
  return `[Unit]
Description=Bounded local capture ready before networkd and WiFi activation
DefaultDependencies=no
RequiresMountsFor=${node} ${captureDir} /usr/local/lib/clean-vpn-boot-capture.mjs
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=notify
NotifyAccess=all
ExecStart=${node} /usr/local/lib/clean-vpn-boot-capture.mjs
RemainAfterExit=yes
TimeoutStartSec=20
TimeoutStopSec=8
KillMode=control-group
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
UMask=0077
`;
}

// tcpdump -i any -y LINUX_SLL2 -w - produces classic pcap with an interface index.
// Parse only network/transport headers; discard every packet immediately.
export class PcapHeaders {
  constructor(onPacket) { this.onPacket = onPacket; this.pending = Buffer.alloc(0); this.header = false; }
  push(bytes) {
    this.pending = Buffer.concat([this.pending, bytes]);
    if (!this.header) {
      if (this.pending.length < 24) return;
      const magic = this.pending.subarray(0, 4).toString('hex');
      assert.ok(['d4c3b2a1', 'a1b2c3d4'].includes(magic), 'unsupported pcap format');
      this.le = magic === 'd4c3b2a1';
      assert.equal(this.u32(20) & 0xffff, 276, 'LINUX_SLL2 required');
      this.pending = this.pending.subarray(24); this.header = true;
    }
    while (this.pending.length >= 16) {
      const n = this.u32(8); assert.ok(n <= 128, 'oversized capture record');
      if (this.pending.length < 16 + n) break;
      this.onPacket(this.pending.subarray(16, 16 + n));
      this.pending = this.pending.subarray(16 + n);
    }
  }
  u32(offset) { return this.le ? this.pending.readUInt32LE(offset) : this.pending.readUInt32BE(offset); }
  finish() { assert.ok(this.header && this.pending.length === 0, 'missing/truncated pcap'); }
}

export function classifyPacket(packet, exitIp) {
  if (packet.length < 20) return { category: 'unparsed' };
  const ifindex = packet.readUInt32BE(4), outbound = packet[10] === 4;
  const ether = packet.readUInt16BE(0), ip = packet.subarray(20);
  const result = { ifindex, outbound, etherType: `0x${ether.toString(16).padStart(4, '0')}`,
    category: 'other-link-protocol' };
  if (ether === 0x0806) return { ...result, category: 'arp' };
  let protocol, offset, dest, privateDestination = false;
  if (ether === 0x0800 && ip.length >= 20 && ip[0] >> 4 === 4) {
    result.family = 4;
    offset = (ip[0] & 15) * 4; protocol = ip[9]; dest = [...ip.subarray(16, 20)].join('.');
    if (offset < 20 || (ip.readUInt16BE(6) & 0x3fff)) return { ...result, category: 'fragment-review' };
    privateDestination = ip[16] === 10 || (ip[16] === 172 && ip[17] >= 16 && ip[17] <= 31)
      || (ip[16] === 192 && ip[17] === 168) || (ip[16] === 169 && ip[17] === 254);
  } else if (ether === 0x86dd && ip.length >= 40 && ip[0] >> 4 === 6) {
    result.family = 6;
    offset = 40; protocol = ip[6];
    dest = Array.from({ length: 8 }, (_, i) => ip.readUInt16BE(24 + i * 2).toString(16)).join(':');
    result.destination = dest; result.nextHeader = protocol; result.hopLimit = ip[7];
    privateDestination = (ip[24] === 0xfe && (ip[25] & 0xc0) === 0x80) || (ip[24] & 0xfe) === 0xfc;
    const linkDestination = (ip[24] === 0xfe && (ip[25] & 0xc0) === 0x80)
      || (ip[24] === 0xff && (ip[25] & 15) === 2);
    if (protocol === 58 && ip.length > 40 && linkDestination
        && ((ip[7] === 255 && [133, 134, 135, 136].includes(ip[40])) || (ip[7] === 1 && ip[40] === 143)))
      return { ...result, category: 'icmpv6-link-control' };
    // Linux MLDv2 membership report: fixed Router Alert hop-by-hop header.
    // Other extension chains remain review-only, not silently skipped.
    const linkSource = ip.subarray(8,24).every(b => b === 0) || (ip[8] === 0xfe && (ip[9] & 0xc0) === 0x80);
    if (protocol === 0 && ip.length >= 49 && ip[7] === 1 && linkSource
        && dest === 'ff02:0:0:0:0:0:0:16'
        && ip.subarray(40,48).toString('hex') === '3a00050200000100' && ip[48] === 143)
      return { ...result, category: 'mldv2-link-control' };
    if (![6, 17, 58].includes(protocol)) return { ...result, category: 'ipv6-extension-review' };
  } else return result;
  result.destination = dest;
  if ([6, 17].includes(protocol)) {
    if (ip.length < offset + 4) return { ...result, category: 'unparsed' };
    const sourcePort = ip.readUInt16BE(offset), port = ip.readUInt16BE(offset + 2);
    result.port = port; result.protocol = protocol === 6 ? 'tcp' : 'udp';
    if ([53, 853].includes(port)) return { ...result, category: 'direct-dns-or-dot' };
    // Endpoint classification only: no DNS payload parsing or new allowlist entry.
    if (protocol === 17 && port === 5353
        && (dest === '224.0.0.251' || dest === 'ff02:0:0:0:0:0:0:fb'))
      return { ...result, category: 'mdns-local-review' };
    if (ether === 0x0800 && protocol === 17 && sourcePort === 68 && port === 67)
      return { ...result, category: 'dhcp4' };
    if (ether === 0x86dd && protocol === 17 && sourcePort === 546 && port === 547)
      return { ...result, category: 'dhcp6' };
    if (ether === 0x0800 && dest === exitIp && protocol === 6 && port === 443)
      return { ...result, category: 'exit-tls' };
  }
  return { ...result, category: privateDestination ? 'local-destination-review' : 'unexpected-egress' };
}

export function captureTrafficNeedsReview(counts) {
  return Object.keys(counts).some(k => !['arp', 'icmpv6-link-control', 'mldv2-link-control',
    'dhcp4', 'dhcp6', 'exit-tls'].includes(k));
}

const command = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 5000, maxBuffer: 256 * 1024 });
const mono = () => Number(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]);
const bootId = () => fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
const linkState = () => {
  try { return { present: true, ifindex: Number(fs.readFileSync('/sys/class/net/wlan0/ifindex')),
    up: Boolean(Number(fs.readFileSync('/sys/class/net/wlan0/flags', 'utf8')) & 1) }; }
  catch (e) { if (e.code === 'ENOENT') return { present: false, up: false }; throw e; }
};
const writeReport = report => {
  const tmp = `${captureDir}/report.tmp`;
  const fd = fs.openSync(tmp, 'w', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(report, null, 2) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, `${captureDir}/report.json`);
};
export async function observe() {
  const config = JSON.parse(fs.readFileSync(`${captureDir}/config.json`, 'utf8'));
  assert.equal(config.schema, 1); assert.match(config.exitIp, /^\d+\.\d+\.\d+\.\d+$/);
  const report = { schema: 1, classifierVersion: 2, kind: captureName, bootId: bootId(), startedMonotonic: mono(),
    status: 'starting', interface: 'wlan0', windowSeconds: 90, counts: {}, samples: [],
    limitations: ['local-observation-not-on-wire-proof', 'no-initramfs-coverage',
      'bounded-window-no-active-probes', 'not-a-proof-against-other-network-managers',
      'private-destinations-and-unparsed-traffic-require-review', 'no-packet-bodies-stored'] };
  let child, timer, readyTimer, killTimer, poll, error, intentionalStop = false;
  let stderr = '', bytes = 0, ready = false, pendingReady = false;
  const stop = why => { error ||= why; child?.kill('SIGINT'); killTimer ||= setTimeout(() => child?.kill('SIGKILL'), 3000); };
  const signal = () => stop('interrupted');
  process.on('SIGTERM', signal); process.on('SIGINT', signal);
  try {
    assert.notEqual(report.bootId, config.installedBootId, 'armed for NEXT boot only; do not start now');
    report.initialLink = linkState();
    assert.ok(!report.initialLink.up, 'wlan0 already UP before capture: cannot certify early start');
    const parser = new PcapHeaders(packet => {
      assert.ok(packet.length >= 20, 'truncated SLL2 header');
      const p = classifyPacket(packet, config.exitIp), link = linkState();
      if (!p.outbound || p.ifindex !== link.ifindex) return;
      report.counts[p.category] = (report.counts[p.category] || 0) + 1;
      if (report.samples.length < 32 && !report.samples.some(s => JSON.stringify(s) === JSON.stringify(p))) report.samples.push(p);
    });
    child = spawn('tcpdump', ['-i', 'any', '-y', 'LINUX_SLL2', '-Q', 'out', '-nn', '-s', '128', '-U', '-w', '-', '-Z', 'root'],
      { env: { ...process.env, LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'] });
    readyTimer = setTimeout(() => stop('capture readiness timeout'), 12000);
    child.stdout.on('data', b => {
      try { bytes += b.length; assert.ok(bytes <= 16 * 1024 * 1024, 'capture byte budget exceeded'); parser.push(b); }
      catch (e) { stop(e.message); }
    });
    child.stderr.on('data', b => {
      stderr += b.toString(); if (stderr.length > 8192) return stop('capture diagnostic limit');
      if (!ready && !pendingReady && /listening on any, link-type LINUX_SLL2/.test(stderr)) {
        pendingReady = true;
        try {
          report.linkAtReady = linkState();
          assert.ok(!report.linkAtReady.up, 'wlan0 raised before capture readiness');
          report.readyMonotonic = mono(); report.status = 'capturing'; writeReport(report);
          command('systemd-notify', ['--ready']); ready = true; clearTimeout(readyTimer);
          poll = setInterval(() => {
            if (!report.firstUpObservedMonotonic && linkState().up) report.firstUpObservedMonotonic = mono();
          }, 100);
          timer = setTimeout(() => { intentionalStop = true; child.kill('SIGINT');
            killTimer = setTimeout(() => child.kill('SIGKILL'), 3000); }, report.windowSeconds * 1000);
        } catch (e) { stop(e.message); }
      }
    });
    const [code, sig] = await new Promise((res, rej) => { child.once('error', rej); child.once('close', (...v) => res(v)); });
    report.captureExit = { code, signal: sig };
    assert.ok(ready && intentionalStop && !error && code === 0, error || 'capture ended unexpectedly');
    parser.finish();
    const dropped = stderr.match(/(\d+) packets dropped by kernel/);
    assert.ok(dropped, 'capture loss statistics missing'); report.droppedPackets = Number(dropped[1]);
    report.consumerTiming = {};
    for (const unit of consumers) {
      const properties = command('systemctl', ['show', unit, '--property=LoadState,ActiveState,ExecMainStartTimestampMonotonic,ActiveEnterTimestampMonotonic,Requires,After']);
      const fields = Object.fromEntries(properties.trim().split('\n').map(l => [l.slice(0,l.indexOf('=')), l.slice(l.indexOf('=')+1)]));
      report.consumerTiming[unit] = fields;
      if (fields.LoadState !== 'loaded') continue;
      for (const key of ['Requires', 'After']) assert.ok(fields[key]?.split(/\s+/).includes(`${captureName}.service`), `missing effective ${key} gate: ${unit}`);
      const started = Number(fields[unit.endsWith('.socket') ? 'ActiveEnterTimestampMonotonic' : 'ExecMainStartTimestampMonotonic']);
      if (started) assert.ok(started >= report.readyMonotonic * 1e6, `consumer started before capture ready: ${unit}`);
    }
    const review = captureTrafficNeedsReview(report.counts);
    report.status = report.droppedPackets || !report.firstUpObservedMonotonic || !Object.keys(report.counts).length
      ? 'inconclusive' : review ? 'traffic-review-required' : 'no-unexpected-egress-observed';
  } catch (e) {
    report.status = 'inconclusive'; report.error = error || e.message;
    // Only startup is a gate. A bounded observer failure after READY must not
    // tear down an already running network via Requires= propagation.
    process.exitCode = ready ? 0 : 1;
  }
  finally {
    for (const t of [timer, readyTimer, killTimer, poll]) clearTimeout(t);
    if (child && child.exitCode === null) child.kill('SIGKILL');
    process.off('SIGTERM', signal); process.off('SIGINT', signal);
    report.finishedMonotonic = mono(); writeReport(report);
    console.log(JSON.stringify({ status: report.status, report: `${captureDir}/report.json` }));
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await observe();
