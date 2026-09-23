#!/usr/bin/env node
/** Independent DNS pcap + bounded soak. Never uses the host network namespace. */
import assert from 'node:assert/strict';
import { mkdtemp, open, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { child } from './lib/browser-lab-driver.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { dnsSoakOptions, assertDnsSoakResult } from './lib/dns-soak.mjs';
import { runDnsSoak } from './lib/dns-soak-workload.mjs';

async function main() {
  const worker = process.argv[2] === '--isolated';
  const options = dnsSoakOptions(process.argv.slice(worker ? 3 : 2));
  if (options.help) {
    console.log('Usage: node scripts/transparent-dns-soak.mjs [--seconds=1..600] [--concurrency=1..8] [--report=/new/file.json]\nDefaults: 60 seconds, concurrency 4 after independent pcap and ten warmup waves.\nRequires Linux user/net/mount/PID namespaces, ip, tcpdump, tshark (MESHPN_TCPDUMP/MESHPN_TSHARK).\nPrivate loopback only; no TUN, system DNS, firewall, downloads or TLS bypass.\nRaw pcap removed; exclusive 0600 report, no QNAME/keys. Sampled budgets, not proof of no leaks.'); return;
  }
  process.umask(0o077); delete process.env.SSLKEYLOGFILE;
  if (worker) {
    console.log = console.warn = console.error = () => {};
    const result = await runDnsSoak(options, process.env.MESHPN_DNS_SOAK_DIR, () => process.stdout.write('DNS_SOAK_READY\n'));
    process.stdout.write(`DNS_SOAK_RESULT ${JSON.stringify(result)}\n`);
    process.exitCode = result.status === 'passed' ? 0 : 1; return;
  }
  const path = options.report ? resolve(options.report) : join(await mkdtemp(join(tmpdir(), 'meshpn-dns-soak-report-')), 'report.json');
  const file = await open(path, 'wx', 0o600), report = { schema: 1, status: 'failed', requested: options,
    startedAt: new Date().toISOString(), node: process.version,
    workerV8: { maxOldSpaceMiB: 64, maxSemiSpaceMiB: 8 },
    limitations: ['loopback-fixture-only', 'pcap-smoke-not-whole-soak', 'sampled-resource-budgets', 'not-production-dns'] };
  let directory, proc, stopping, reason, timer, aborted = false;
  const stop = (why) => { reason ??= why; if (proc) stopping ??= proc.stop().catch(() => { reason = 'cleanup-failed'; }); };
  const abort = () => { aborted = true; stop('aborted'); };
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  console.log(`[dns-soak] ${options.seconds}s; report=${path}`);
  try {
    assert.equal(process.platform, 'linux');
    const env = cleanEnvironment(process.env);
    const git = await runCommand('git', ['rev-parse', 'HEAD'], { env });
    const dirty = await runCommand('git', ['status', '--porcelain'], { env });
    assert.equal(git.code, 0); assert.equal(dirty.code, 0);
    report.repository = { revision: git.stdout.trim(), dirty: Boolean(dirty.stdout.trim()) };
    if (aborted) throw new Error('ABORTED');
    directory = await mkdtemp(join(tmpdir(), 'meshpn-dns-soak-private-'));
    proc = child('unshare', [...namespaceArgs, 'sh', '-eu', '-c', 'ulimit -c 0; ip link set lo up; exec "$@"', 'dns-soak',
      process.execPath, '--max-old-space-size=64', '--max-semi-space-size=8', fileURLToPath(import.meta.url),
      '--isolated', `--seconds=${options.seconds}`, `--concurrency=${options.concurrency}`],
    { env: { ...env, MESHPN_DNS_SOAK_DIR: directory, MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'),
      MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
    const closed = new Promise((resolve) => proc.proc.once('close', (code, signal) => resolve({ code, signal })));
    timer = setTimeout(() => stop('deadline'), (options.seconds + 45) * 1000);
    let buffer = '', bytes = 0, count = 0, ready = false;
    proc.proc.on('error', () => stop('spawn-error'));
    const budget = (chunk) => { bytes += Buffer.byteLength(chunk); if (bytes > 1024 * 1024) { stop('output-limit'); return false; } return true; };
    proc.proc.stderr.on('data', budget);
    proc.proc.stdout.setEncoding('utf8');
    proc.proc.stdout.on('data', (chunk) => {
      if (!budget(chunk)) return; buffer += chunk;
      let end;
      while ((end = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        if (line === 'DNS_SOAK_READY' && !ready) { ready = true; console.log('[dns-soak] measured workload ready'); }
        else if (line.startsWith('DNS_SOAK_RESULT ')) {
          try { report.result = JSON.parse(line.slice(16)); count++; } catch { stop('invalid-result'); }
        } else stop('unexpected-output');
      }
    });
    if (aborted) stop('aborted');
    report.worker = { ...await closed, reason: reason ?? null, closed: true }; await stopping;
    assert.equal(reason, undefined); assert.equal(buffer, ''); assert.equal(count, 1); assert.ok(ready);
    assert.equal(report.worker.code, 0); assert.equal(report.worker.signal, null);
    assertDnsSoakResult(report.result, options);
    report.status = 'passed';
  } catch { report.status = aborted ? 'aborted' : 'failed'; }
  finally {
    clearTimeout(timer);
    if (aborted) report.status = 'aborted';
    try { await proc?.stop(); if (directory) await rm(directory, { recursive: true, force: true }); report.privateFilesRemoved = true; }
    catch { report.status = 'failed'; report.cleanupFailed = true; }
    report.finishedAt = new Date().toISOString();
    try { await file.writeFile(`${JSON.stringify(report, null, 2)}\n`); }
    finally { await file.close(); process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
  }
  console.log(`[dns-soak] ${report.status.toUpperCase()}; report=${path}`);
  process.exitCode = report.status === 'passed' ? 0 : 1;
}
main().catch(() => { console.error('[dns-soak] FAILED (arguments, report path or namespace)'); process.exitCode = 1; });
