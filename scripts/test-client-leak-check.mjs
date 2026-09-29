import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { collectLeakCheck, parseLeakCheckArgs, captureSummary, parseIpv6Probe, ipv6CurlArgs, V6_TARGET } from './lib/client-leak-check.mjs';
import { DIAGNOSTIC_ENV } from './lib/dns-diagnostic.mjs';

const options = { exitIp: '154.62.226.216', tun: 'tun0', probe: true };
const ok = stdout => ({ code: 0, signal: null, reason: null, stdout, stderr: '', durationMs: 1 });
const stats = '10 packets captured\n10 packets received by filter\n0 packets dropped by kernel\n';
const v6 = '2001:4860::123';
const trace = `ip=${v6}\nsecret=must-not-appear\nLEAK_CHECK_METRICS\t200\t${V6_TARGET}\t${v6}\t0\n`;
function fixture({ dnsLeak = false, noise = false, drops = false, emptyTun = false, captureFailure = false, noTun = false, https = true, routeChange = false } = {}) {
  const calls = [], names = [], finishes = []; let captures = 0, internetCalls = 0;
  return { calls, names, finishes, settle: async () => {}, run: async (file, args, opts) => {
    calls.push({ file, args, opts });
    if (opts.signal.aborted) return { ...ok(''), code: null, reason: 'aborted' };
    if (file === 'git') return ok('5478fcc\n');
    if (file === 'tcpdump') return ok('tcpdump fixture\n');
    if (file === 'ip') {
      if (args.includes('addr')) return ok(JSON.stringify([
        ...(!noTun ? [{ ifname: 'tun0', flags: ['UP'], addr_info: [{ family: 'inet', local: '10.99.0.2' }] }] : []),
        { ifname: 'wlan0', flags: ['UP'], addr_info: [{ family: 'inet6', local: v6 }] }]));
      if (args.at(-1) === '1.0.0.1') internetCalls++;
      return ok(JSON.stringify([{ dev: args.at(-1) === '1.0.0.1' && !(routeChange && internetCalls > 1) ? 'tun0' : 'wlan0' }]));
    }
    if (file === 'dig') { names.push(args.find(a => a.startsWith('cv-')).slice(0, -1)); return ok(';; status: NXDOMAIN,\n'); }
    assert.equal(file, 'curl'); return https ? ok(trace) : { ...ok(''), code: 7 };
  }, capture: async (iface, filter, signal) => {
    captures++; if (captureFailure && captures === 2) throw Error('no tcpdump');
    assert.ok(filter.includes('dst port 53')); assert.ok(signal);
    return { finish: async () => {
      finishes.push(iface);
      return { ...ok((iface === 'tun0' && !emptyTun || iface === 'wlan0' && dnsLeak ? names.map(n => `IP 10.0.0.1.123 > 1.1.1.1.53: 1+ A? ${n}.\n`).join('') : '') +
        (iface === 'wlan0' && noise ? 'IP 1.2.3.4.111 > 1.1.1.1.53: A? unrelated-private.example.\n' : '')),
      stderr: drops ? stats.replace('0 packets dropped', '2 packets dropped') : stats };
    } };
  } };
}

test('leak CLI is strict and requires explicit exit; rejects arbitrary capture and mutation flags', () => {
  assert.deepEqual(parseLeakCheckArgs(['--probe', '--exit-ip=154.62.226.216']), options);
  for (const a of [[], ['--exit-ip=127.0.0.1'], ['--exit-ip=10.1.2.3'], ['--tun=lo'], ['--filter=x'], ['--apply'], ['--probe', '--probe']]) assert.throws(() => parseLeakCheckArgs(a));
});
test('inspection never captures or probes; missing TUN refuses active check', async () => {
  for (const [opts, f] of [[{ ...options, probe: false }, fixture()], [options, fixture({ noTun: true })]]) {
    const r = await collectLeakCheck(opts, f);
    assert.ok(['inspection-only', 'inconclusive'].includes(r.status)); assert.equal(f.finishes.length, 0);
    assert.ok(f.calls.every(c => ['ip', 'git'].includes(c.file)));
  }
});
test('unique DNS probes have positive TUN control; direct IPv6 HTTPS confirms bypass', async () => {
  const f = fixture(), r = await collectLeakCheck(options, f);
  assert.equal(r.status, 'bypass-or-uplink-traffic-observed'); assert.equal(r.ipv6.status, 'bypass-confirmed');
  assert.equal(r.dnsObservation, 'probes-seen-on-TUN-not-on-uplink'); assert.equal(new Set(f.names).size, 8);
  assert.equal(r.dns.filter(d => d.resolver === 'system').length, 4);
  assert.deepEqual(f.finishes, ['tun0', 'wlan0']); assert.doesNotMatch(JSON.stringify(r), /must-not-appear/);
  for (const c of f.calls) { assert.deepEqual(c.opts.env, DIAGNOSTIC_ENV); assert.ok(c.opts.timeoutMs <= 12000); }
});
test('probe DNS on uplink is reported independently of IPv6 success', async () => {
  const r = await collectLeakCheck(options, fixture({ dnsLeak: true, https: false }));
  assert.equal(r.dnsObservation, 'probe-DNS-on-uplink'); assert.equal(r.ipv6.status, 'not-established');
  assert.equal(r.status, 'bypass-or-uplink-traffic-observed');
});
test('unrelated port53 traffic is review evidence, not attributed to generated probes', async () => {
  const r = await collectLeakCheck(options, fixture({ noise: true }));
  assert.equal(r.dnsObservation, 'other-port53-traffic-on-uplink-review');
  assert.doesNotMatch(JSON.stringify(r), /unrelated-private/);
});
for (const scenario of [{ drops: true }, { emptyTun: true }, { routeChange: true }]) test(`uncertain capture/routes never imply clean DNS ${JSON.stringify(scenario)}`, async () => {
  const r = await collectLeakCheck(options, fixture({ ...scenario, https: false }));
  assert.equal(r.dnsObservation, 'inconclusive'); assert.equal(r.status, 'inconclusive');
});
test('second capture startup failure cleans up first and starts no probes', async () => {
  const f = fixture({ captureFailure: true }), r = await collectLeakCheck(options, f);
  assert.deepEqual(f.finishes, ['tun0']); assert.equal(r.status, 'inconclusive'); assert.equal(r.dns.length, 0);
});
test('aborted collection never reports success or starts probes', async () => {
  const controller = new AbortController(); controller.abort(); const f = fixture();
  const r = await collectLeakCheck(options, { ...f, signal: controller.signal });
  assert.equal(r.status, 'aborted'); assert.equal(f.names.length, 0);
});
test('abort during probes still closes both captures and cannot become a clean observation', async () => {
  const controller = new AbortController(), f = fixture(), run = f.run;
  const r = await collectLeakCheck(options, { ...f, signal: controller.signal, run: async (...args) => {
    if (args[0] === 'dig') controller.abort();
    return run(...args);
  } });
  assert.equal(r.status, 'aborted'); assert.equal(r.dnsObservation, 'inconclusive');
  assert.deepEqual(f.finishes, ['tun0', 'wlan0']);
});
test('capture validity requires clean exit and known zero drops; IPv6 packet count preserved', () => {
  const r = { ...ok(`IP6 ${v6}.123 > ${V6_TARGET}.443: Flags [S]\n`), stderr: stats };
  assert.equal(captureSummary(r, []).healthy, true); assert.equal(captureSummary(r, []).ipv6TargetOutboundPackets, 1);
  for (const patch of [{ code: 1 }, { signal: 'SIGKILL' }, { reason: 'capture-output-limit' }, { stderr: '' }])
    assert.equal(captureSummary({ ...r, ...patch }, []).healthy, false);
});
test('IPv6 HTTPS requires valid TLS and real IPv6; no interface forced and no proxy/redirect/insecure', () => {
  assert.equal(parseIpv6Probe(ok(trace)).status, 'https-connected');
  for (const r of [{ ...ok(trace), code: 60 }, ok(trace.replace('\t0\n', '\t20\n')), ok(trace.replace('200\t', '302\t')), ok('')]) assert.equal(parseIpv6Probe(r).status, 'not-established');
  const args = ipv6CurlArgs(); assert.equal(args[0], '-q'); assert.ok(args.includes('--ipv6')); assert.ok(args.includes(`cloudflare-dns.com:443:[${V6_TARGET}]`));
  for (const flag of ['--interface', '--insecure', '--location']) assert.ok(!args.includes(flag));
});
test('CLI help performs no probes', () => {
  const r = spawnSync(process.execPath, ['scripts/clean-vpn-client-leak-check.mjs', '--help'], { timeout: 5000, encoding: 'utf8' });
  assert.equal(r.status, 0); assert.match(r.stdout, /intentionally tests/);
});
