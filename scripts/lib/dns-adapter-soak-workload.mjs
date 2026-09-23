import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { child, exec } from './browser-lab-driver.mjs';
import { assertBrowserNamespace, namespaceResources } from './browser-soak.mjs';
import { startAdapterSoakLab } from './dns-adapter-soak-lab.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { makeDnsQuery, fixtureDnsAnswer, validateDnsResponse } from './lab-dns-wire.mjs';
import { assertDnsCaptureExit } from './dns-lab-pcap.mjs';
import { ADAPTER_PCAP_FIELDS, auditAdapterPcap } from './dns-adapter-pcap.mjs';
import { adapterWave, drainAdapter, assertAdapterIdle, emptyAdapterTotals } from './dns-adapter-soak.mjs';
import { assertDnsResources } from './dns-soak.mjs';

async function capture(lab, directory, name, marker, options, signal) {
  const control = dgram.createSocket('udp4'); let proc, bound = false;
  control.on('error', () => {});
  control.on('message', (q, peer) => { try { control.send(fixtureDnsAnswer(q), peer.port, peer.address); } catch {} });
  try {
    control.bind(0, '127.0.0.1'); await once(control, 'listening'); bound = true;
    const pcap = join(directory, 'adapter.pcap');
    proc = child(process.env.MESHPN_TCPDUMP || 'tcpdump', ['-i', 'lo', '-n', '-U', '-s', '0', '-c', '20000', '-w', pcap, 'tcp or udp'],
      { env: { ...process.env, LC_ALL: 'C' } });
    let diagnostics = '';
    proc.proc.stderr.on('data', (chunk) => { diagnostics = (diagnostics + chunk).slice(-65536); });
    const closed = new Promise((resolve) => proc.proc.once('close', (code, signal) => resolve({ code, signal })));
    await proc.waitFor(/listening on lo/, 5000); signal.throwIfAborted();
    const q = makeDnsQuery(name); validateDnsResponse(await queryLabDns(control.address().port, q), q);
    await adapterWave(lab, name, options.concurrency, signal);
    // Explicit TCP and AAAA successes even for concurrency=1.
    for (const [tcp, type] of [[true, 1], [false, 28], [true, 28]]) {
      const packet = makeDnsQuery(name, type);
      assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, packet, { tcp }), packet).counts[0], 1);
    }
    await drainAdapter(lab); await delay(1200); await proc.stop('SIGINT');
    const stopped = await closed, count = assertDnsCaptureExit(stopped.code, stopped.signal, diagnostics);
    const size = (await stat(pcap)).size; assert.ok(size > 24 && size < 8 * 1024 * 1024);
    const { stdout } = await exec(process.env.MESHPN_TSHARK || 'tshark', ['-n', '-r', pcap, '-o', 'tcp.relative_sequence_numbers:TRUE',
      '-o', 'tls.keylog_file:', '-T', 'fields', '-E', 'occurrence=f', ...ADAPTER_PCAP_FIELDS.flatMap((f) => ['-e', f])], { maxBuffer: 16 * 1024 * 1024 });
    const result = auditAdapterPcap(stdout, { endpoints: { ...lab.endpoints, control: { address: '127.0.0.1', port: control.address().port } }, marker });
    assert.equal(result.packets, count); return { ...result, fileBytes: size, coverage: 'short-smoke-both-directions-all-namespace-tcp-udp' };
  } finally { await proc?.stop(); if (bound) await new Promise((resolve) => control.close(resolve)); else try { control.close(); } catch {} }
}

export async function runAdapterSoak(options, directory, ready = () => {}) {
  assertBrowserNamespace();
  const controller = new AbortController(), abort = () => controller.abort();
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  const report = { schema: 1, kind: 'dns-exit-adapter', status: 'failed', seconds: options.seconds, concurrency: options.concurrency,
    family: options.family, modeTag: options.modeTag, warmupWaves: 10, waves: 0, samples: [], totals: emptyAdapterTotals() };
  let lab, phase = 'startup';
  try {
    const marker = `secret-${randomBytes(12).toString('hex')}`, name = `${marker}.dns-lab.test`;
    lab = await startAdapterSoakLab(options, directory); phase = 'pcap';
    report.pcap = await capture(lab, directory, name, marker, options, controller.signal);
    phase = 'warmup'; const warmupHighWater = { rss: 0, heapUsed: 0 };
    for (let i = 0; i < report.warmupWaves; i++) {
      await adapterWave(lab, name, options.concurrency, controller.signal); await delay(20);
      const r = namespaceResources(); assertDnsResources(r);
      for (const k of Object.keys(warmupHighWater)) warmupHighWater[k] = Math.max(warmupHighWater[k], r.worker.memory[k]);
    }
    report.baseline = { ...namespaceResources(), warmupHighWater }; report.baselineCounters = lab.stats().stub;
    const initial = lab.stats();
    report.baselineTraffic = { attempts: initial.attempts, bodies: initial.resolverBodies, connections: initial.transport.connections };
    phase = 'measured'; ready(); const start = performance.now(); let nextSample = 0;
    do {
      const totals = await adapterWave(lab, name, options.concurrency, controller.signal);
      for (const k of Object.keys(totals)) report.totals[k] += totals[k]; report.waves++; await delay(25);
      const resources = namespaceResources(), owned = lab.stats(); assertAdapterIdle(owned); assertDnsResources(resources, report.baseline);
      const elapsedMs = Math.round(performance.now() - start);
      report.last = { elapsedMs, resources, owned };
      if (elapsedMs >= nextSample) { report.samples.push(report.last); nextSample += 5000; }
    } while (performance.now() - start < options.seconds * 1000);
    report.measuredMs = Math.round(performance.now() - start); report.samples.push(report.last); delete report.last;
    controller.signal.throwIfAborted(); report.status = 'passed';
  } catch (error) {
    report.status = controller.signal.aborted ? 'aborted' : 'failed';
    report.failure = { phase, code: String(error.code ?? error.name).slice(0, 80) };
  } finally {
    try {
      await lab?.close(); await delay(30); const resources = namespaceResources();
      report.final = { owned: lab?.stats() ?? null, resources };
      if (lab) assertAdapterIdle(report.final.owned); assertDnsResources(resources, undefined, true);
    } catch { report.status = 'failed'; report.cleanupFailed = true; }
    if (controller.signal.aborted && !report.cleanupFailed) report.status = 'aborted';
    process.off('SIGINT', abort); process.off('SIGTERM', abort);
  }
  return report;
}
