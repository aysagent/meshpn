import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { child, exec } from './browser-lab-driver.mjs';
import { assertBrowserNamespace, namespaceResources } from './browser-soak.mjs';
import { startTransparentDnsLab, queryLabDns } from './transparent-dns-lab.mjs';
import { makeDnsQuery, fixtureDnsAnswer, validateDnsResponse } from './lab-dns-wire.mjs';
import { DNS_PCAP_FIELDS, auditDnsPcap, assertDnsCaptureExit } from './dns-lab-pcap.mjs';
import { dnsWave, drainDns, assertDnsIdle, assertDnsResources } from './dns-soak.mjs';

async function captureSmoke(lab, directory, marker, signal) {
  const control = dgram.createSocket('udp4'); let capture, stopped;
  control.on('error', () => {});
  control.on('message', (query, peer) => {
    try { control.send(fixtureDnsAnswer(query), peer.port, peer.address); } catch { /* timeout fails the audit */ }
  });
  try {
    control.bind(0, '127.0.0.1'); await once(control, 'listening');
    const pcap = join(directory, 'dns.pcap');
    capture = child(process.env.MESHPN_TCPDUMP || 'tcpdump', ['-i', 'lo', '-n', '-U', '-s', '0', '-c', '20000', '-w', pcap, 'tcp or udp'],
      { env: { ...process.env, LC_ALL: 'C' } });
    let diagnostics = '';
    capture.proc.stderr.on('data', (chunk) => { diagnostics = (diagnostics + chunk).slice(-65536); });
    stopped = new Promise((resolve) => capture.proc.once('close', (code, signal) => resolve({ code, signal })));
    await capture.waitFor(/listening on lo/, 5000); signal.throwIfAborted();
    const query = makeDnsQuery(`${marker}.dns-lab.test`);
    validateDnsResponse(await queryLabDns(control.address().port, query), query);
    await dnsWave(lab, queryLabDns, `${marker}.dns-lab.test`, 2, signal);
    // Drain libpcap's kernel buffer before SIGINT. -U alone is not immediate mode.
    await delay(1200); await capture.stop('SIGINT');
    const exit = await stopped, captured = assertDnsCaptureExit(exit.code, exit.signal, diagnostics);
    const size = (await stat(pcap)).size; assert.ok(size > 24 && size < 8 * 1024 * 1024);
    const args = ['-n', '-r', pcap, '-o', 'tcp.relative_sequence_numbers:TRUE', '-o', 'tls.keylog_file:',
      '-T', 'fields', '-E', 'occurrence=f', ...DNS_PCAP_FIELDS.flatMap((field) => ['-e', field])];
    const { stdout } = await exec(process.env.MESHPN_TSHARK || 'tshark', args, { maxBuffer: 16 * 1024 * 1024 });
    const audit = auditDnsPcap(stdout, { stubPort: lab.stub.port, controlPort: control.address().port,
      protectedPorts: [lab.relay.clientPort, lab.relay.exitPort, lab.relay.originPort, lab.resolverPort], marker });
    assert.equal(audit.packets, captured, 'tshark omitted packets');
    return { ...audit, fileBytes: size, coverage: 'short-smoke-both-directions-all-namespace-tcp-udp' };
  } finally {
    await capture?.stop();
    await new Promise((resolve) => { control.close(resolve); });
  }
}

export async function runDnsSoak(options, directory, ready = () => {}) {
  assertBrowserNamespace();
  const links = JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout);
  assert.deepEqual(links.map((link) => link.ifname), ['lo']);
  const controller = new AbortController(), abort = () => controller.abort();
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  const report = { schema: 1, status: 'failed', seconds: options.seconds, concurrency: options.concurrency,
    warmupWaves: 10, waves: 0, samples: [], totals: { replies: 0, servfail: 0, nxdomain: 0, truncated: 0, restarts: 0 } };
  let lab, phase = 'startup';
  try {
    const marker = `secret-${randomBytes(12).toString('hex')}`, name = `${marker}.dns-lab.test`;
    // Capture uses two explicit clients even when the measured soak is single-client.
    lab = await startTransparentDnsLab({ timeoutMs: 200, maxInflight: Math.max(2, options.concurrency), maxTcpConnections: Math.max(2, options.concurrency) });
    phase = 'pcap';
    report.pcap = await captureSmoke(lab, directory, marker, controller.signal);
    phase = 'warmup';
    const warmupHighWater = { rss: 0, heapUsed: 0 };
    for (let i = 0; i < report.warmupWaves; i++) {
      await dnsWave(lab, queryLabDns, name, options.concurrency, controller.signal);
      await delay(20); const sample = namespaceResources(); assertDnsResources(sample);
      for (const key of Object.keys(warmupHighWater)) warmupHighWater[key] = Math.max(warmupHighWater[key], sample.worker.memory[key]);
    }
    report.baseline = { ...namespaceResources(), warmupHighWater }; assertDnsResources(report.baseline);
    phase = 'measured'; ready(); const start = performance.now(); let nextSample = 0;
    do {
      const totals = await dnsWave(lab, queryLabDns, name, options.concurrency, controller.signal);
      for (const key of Object.keys(totals)) report.totals[key] += totals[key];
      report.waves++; await delay(25);
      const resources = namespaceResources(); report.lastResources = resources;
      assertDnsResources(resources, report.baseline);
      const elapsedMs = Math.round(performance.now() - start);
      if (elapsedMs >= nextSample) { report.samples.push({ elapsedMs, resources }); nextSample += 5000; }
    } while (performance.now() - start < options.seconds * 1000);
    report.measuredMs = Math.round(performance.now() - start);
    report.samples.push({ elapsedMs: report.measuredMs, resources: report.lastResources });
    await drainDns(lab); controller.signal.throwIfAborted(); report.status = 'passed';
  } catch (error) {
    report.status = controller.signal.aborted ? 'aborted' : 'failed';
    // Do not serialize assertion actual/expected, payloads, QNAME or raw tool output.
    report.failure = { phase, code: String(error.code ?? error.name).slice(0, 80) };
  } finally {
    try {
      await lab?.close(); await delay(30);
      const resources = namespaceResources();
      report.final = { owned: lab ? { dns: lab.stats(), relay: lab.relay.stats() } : null, resources };
      if (lab) assertDnsIdle(lab);
      assertDnsResources(resources, undefined, true);
    } catch { report.status = 'failed'; report.cleanupFailed = true; }
    if (controller.signal.aborted && !report.cleanupFailed) report.status = 'aborted';
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
  }
  return report;
}
