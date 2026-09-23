/** Persistent loopback workload. No browser, external target, TUN or runtime policy changes. */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readdirSync, readFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { setTimeout as delay, setImmediate as immediate } from 'node:timers/promises';
import { startTransparentTlsLab, requestThroughLab, assertRelayTrace } from './transparent-tls-lab.mjs';
import { startLabConnectProxy } from './transparent-connect-lab.mjs';
import { slowReaderCase } from './transparent-slow-reader.mjs';
import { h2FlowMatrix } from './transparent-h2-flow.mjs';

export function soakOptions(args) {
  const result = { seconds: 300, concurrency: 4, profile: 'basic' };
  const seen = new Set();
  for (const arg of args) {
    if (arg === '--help') { result.help = true; continue; }
    const match = /^--(seconds|concurrency|report|profile)=(.+)$/.exec(arg);
    if (!match || seen.has(match[1])) throw new Error('invalid or duplicate soak argument');
    seen.add(match[1]);
    if (['report', 'profile'].includes(match[1])) result[match[1]] = match[2];
    else {
      if (!/^[1-9]\d*$/.test(match[2])) throw new Error('soak limits must be positive integers');
      result[match[1]] = Number(match[2]);
    }
  }
  if (result.seconds < 1 || result.seconds > 3600) throw new Error('seconds must be 1..3600');
  if (result.concurrency < 2 || result.concurrency > 12) throw new Error('concurrency must be 2..12');
  if (!['basic', 'slow-reader', 'h2-flow'].includes(result.profile)) throw new Error('profile must be basic, slow-reader or h2-flow');
  return result;
}

export function assertIdle(lab, proxy) {
  for (const key of ['sockets', 'heldResponses', 'h2Sessions', 'pendingClients', 'relaySessions', 'relayTimers', 'cleanupFailures', 'slowStreams', 'slowStreamTimers', 'h2FlowStreams', 'h2FlowTimers']) {
    assert.equal(lab[key], 0, `lab ${key} did not drain`);
  }
  for (const key of ['clients', 'upstreams', 'headerTimers', 'relaySessions', 'relayTimers', 'cleanupFailures']) {
    assert.equal(proxy[key], 0, `proxy ${key} did not drain`);
  }
}

// Only counts, never FD targets, environment values or TLS/session material.
export function resources() {
  const active = {};
  for (const type of process.getActiveResourcesInfo()) active[type] = (active[type] ?? 0) + 1;
  const children = readFileSync(`/proc/self/task/${process.pid}/children`, 'utf8').trim();
  return { memory: process.memoryUsage(), fds: readdirSync('/proc/self/fd').length,
    children: children ? children.split(/\s+/).length : 0, active };
}

export function memoryTrend(samples) {
  assert.ok(samples.length > 0, 'memory trend requires samples');
  const result = {};
  for (const key of ['rss', 'heapUsed', 'external', 'arrayBuffers']) {
    const values = samples.map((s) => s.resources.memory[key]);
    const meanTime = samples.reduce((sum, s) => sum + s.elapsedMs, 0) / samples.length;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const denominator = samples.reduce((sum, s) => sum + (s.elapsedMs - meanTime) ** 2, 0);
    const slope = denominator ? samples.reduce((sum, s, i) => sum + (s.elapsedMs - meanTime) * (values[i] - mean), 0) / denominator : 0;
    result[key] = { first: values[0], last: values.at(-1), peak: Math.max(...values),
      delta: values.at(-1) - values[0], bytesPerMinute: Math.round(slope * 60_000) };
  }
  return result;
}

export function assertResources(current, baseline) {
  assert.equal(current.children, 0, 'workload must not spawn children');
  assert.ok(current.fds <= baseline.fds, 'idle file descriptors grew after warmup');
  // Safety tripwire, sampled between waves; not an instantaneous or OS-enforced limit.
  assert.ok(current.memory.rss <= 512 * 1024 * 1024, 'soak worker exceeded 512 MiB RSS');
}

export async function runSoak(options, { signal, emit = () => {} } = {}) {
  // Programmatic use has the same bounds as the public CLI.
  const { seconds, concurrency, profile } = soakOptions([`--seconds=${options.seconds}`, `--concurrency=${options.concurrency}`, `--profile=${options.profile ?? 'basic'}`]);
  const result = { schema: 1, status: 'failed', seconds, concurrency, profile, warmupWaves: 0, waves: 0,
    totals: { echoes: 0, echoBytes: 0, helloAborts: 0, uploadAborts: 0, slowHellos: 0, slowHeaders: 0 }, samples: [] };
  if (profile === 'slow-reader') result.slowReaders = {};
  if (profile === 'h2-flow') result.h2Flow = { tlsConnections: 0, healthyEchoes: 0, cases: {} };
  const sockets = new Set(), requests = new Set(), timers = new Set();
  let lab, proxy, phase = 'setup', measuredStart, waveTimer, failure;
  const error = (code) => Object.assign(new Error(code), { code });
  const own = (socket) => {
    sockets.add(socket); socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket)); return socket;
  };
  const cancel = (reason) => {
    failure ??= reason;
    for (const timer of timers) clearInterval(timer);
    timers.clear();
    for (const req of requests) req.destroy(reason);
    for (const socket of sockets) socket.destroy(reason);
  };
  const aborted = () => cancel(error('SOAK_ABORTED'));
  const check = () => { if (failure) throw failure; if (signal?.aborted) throw error('SOAK_ABORTED'); };
  signal?.addEventListener('abort', aborted, { once: true });
  async function until(predicate, ms = 5000) {
    const end = performance.now() + ms;
    while (!predicate()) {
      check(); if (performance.now() > end) throw error('SOAK_OBSERVATION_TIMEOUT');
      await delay(10);
    }
    check();
  }
  async function idle() {
    await until(() => {
      try { assertIdle(lab.stats(), proxy.stats()); return sockets.size + requests.size + timers.size === 0; }
      catch { return false; }
    });
    // Let queued close callbacks / handle destruction settle before FD sampling.
    await immediate(); await immediate();
    assertIdle(lab.stats(), proxy.stats());
  }
  function tunnel() {
    check();
    return new Promise((resolve, reject) => {
      const req = http.request({ host: proxy.host, port: proxy.port, method: 'CONNECT', path: proxy.authority,
        headers: { host: proxy.authority }, agent: false });
      requests.add(req); req.once('close', () => requests.delete(req));
      req.once('error', reject);
      req.once('connect', (res, socket, head) => {
        own(socket);
        if (res.statusCode !== 200 || head.length) { socket.destroy(); reject(error('SOAK_CONNECT')); }
        else resolve(socket);
      });
      req.end();
    });
  }
  async function echo(i) {
    const socket = await tunnel();
    try {
      const body = Buffer.alloc(64 * 1024, i % 251);
      const response = await requestThroughLab(lab, { httpVersion: i % 2 ? '2' : '1.1',
        body, path: '/echo', tlsOptions: { socket } });
      assert.deepEqual(response.body, body);
      result.totals.echoes++; result.totals.echoBytes += body.length;
    } finally { socket.destroy(); }
  }
  function traces(expected) {
    const hellos = lab.captures.filter((c) => c.stage === 'client');
    assert.equal(hellos.length, expected);
    for (const hello of hellos) assertRelayTrace(lab, hello.id);
    lab.captures.length = 0;
  }
  function drip(socket, first) {
    socket.write(first);
    const timer = setInterval(() => { if (!socket.destroyed) socket.write(Buffer.from([0x61])); }, 30);
    timers.add(timer);
    socket.once('close', () => { clearInterval(timer); timers.delete(timer); });
  }
  async function wave() {
    check();
    waveTimer = setTimeout(() => cancel(error('SOAK_WAVE_TIMEOUT')), 20_000);
    try {
      phase = 'echo';
      lab.runtimeErrors.length = 0;
      await Promise.all(Array.from({ length: concurrency }, (_, i) => echo(i)));
      await idle(); traces(concurrency);
      assert.equal(lab.runtimeErrors.length, 0);

      phase = 'hello-abort';
      const originBefore = lab.stats().originConnections;
      const partials = await Promise.all(Array.from({ length: concurrency }, tunnel));
      // Wait until the lab owns every accepted connection, then abort real partial TLS.
      await until(() => lab.stats().pendingClients === concurrency);
      for (const socket of partials) { socket.resume(); socket.write(Buffer.from([0x16, 3, 3, 2, 0, 1])); socket.end(); }
      await idle(); assert.equal(lab.stats().originConnections, originBefore);
      result.totals.helloAborts += concurrency;

      phase = 'upload-abort';
      const before = lab.stats().requests;
      const count = Math.max(1, Math.floor(concurrency / 2));
      const uploads = await Promise.all(Array.from({ length: count }, async () => {
        const socket = own(tls.connect({ socket: await tunnel(), servername: 'localhost', ca: lab.cert,
          minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], rejectUnauthorized: true }));
        await once(socket, 'secureConnect'); assert.equal(socket.authorized, true);
        socket.write(`POST /echo HTTP/1.1\r\nHost: ${proxy.authority}\r\nContent-Length: 1048576\r\n\r\n`);
        socket.write(Buffer.alloc(16 * 1024)); return socket;
      }));
      await until(() => lab.stats().requests === before + count);
      for (const socket of uploads) socket.destroy();
      await idle(); traces(count); result.totals.uploadAborts += count;

      phase = 'slow-hello';
      lab.runtimeErrors.length = 0;
      const slow = await Promise.all(Array.from({ length: 2 }, tunnel));
      for (const socket of slow) { socket.resume(); drip(socket, Buffer.from([0x16, 3, 3, 2, 0])); }
      await idle();
      assert.equal(lab.runtimeErrors.filter((e) => e.role === 'client' && e.code === 'TLS_RELAY_HELLO_TIMEOUT').length, 2);
      result.totals.slowHellos += 2;

      phase = 'slow-header';
      await Promise.all(Array.from({ length: 2 }, async () => {
        const socket = own(net.connect(proxy.port, proxy.host));
        let reply = '';
        socket.on('data', (chunk) => {
          if (reply.length + chunk.length > 4096) cancel(error('SOAK_REPLY_LIMIT'));
          else reply += chunk;
        });
        const closed = new Promise((resolve) => socket.once('close', resolve));
        await once(socket, 'connect'); drip(socket, 'CONNECT ');
        await closed; assert.match(reply, /^HTTP\/1\.1 408 /);
      }));
      await idle(); result.totals.slowHeaders += 2;

      phase = 'recovery';
      lab.runtimeErrors.length = 0;
      await echo(1); await idle(); traces(1);
      assert.equal(lab.runtimeErrors.length, 0);
      if (profile === 'slow-reader') {
        for (const direction of ['forward', 'reverse']) for (const outcome of ['resume', 'timeout']) {
          phase = `slow-reader-${direction}-${outcome}`;
          lab.runtimeErrors.length = 0;
          const metrics = await slowReaderCase({ lab, tunnel, own, until, signal, direction, outcome,
            onBlocked: emit,
            healthy: () => Promise.all(Array.from({ length: concurrency }, (_, i) => echo(i))) });
          await idle(); traces(concurrency + 1);
          const total = result.slowReaders[`${direction}-${outcome}`] ??= { cases: 0, bytes: 0, pressureSamples: 0, maxReadable: 0, maxWritable: 0 };
          total.cases++; total.bytes += metrics.bytes; total.pressureSamples += metrics.pressureSamples;
          total.maxReadable = Math.max(total.maxReadable, metrics.maxReadable);
          total.maxWritable = Math.max(total.maxWritable, metrics.maxWritable);
          if (metrics.timeout) total.timeout = metrics.timeout;
        }
      }
      if (profile === 'h2-flow') {
        phase = 'h2-flow'; lab.runtimeErrors.length = 0;
        const matrix = await h2FlowMatrix({ lab, proxy, tunnel, own, until, concurrency, signal, emit });
        await idle(); traces(1);
        result.h2Flow.tlsConnections += matrix.tlsConnections; result.h2Flow.healthyEchoes += matrix.healthyEchoes;
        for (const [key, item] of Object.entries(matrix.cases)) {
          const total = result.h2Flow.cases[key] ??= { cases: 0, bytes: 0, zeroWindowSamples: 0,
            maxReadable: 0, maxWritable: 0, healthyWhileBlocked: 0, healthyAfter: 0, heldSurvived: 0 };
          for (const field of ['cases', 'bytes', 'zeroWindowSamples', 'healthyWhileBlocked', 'healthyAfter', 'heldSurvived']) total[field] += item[field];
          for (const field of ['maxReadable', 'maxWritable']) total[field] = Math.max(total[field], item[field]);
          if (item.rstCode !== undefined) total.rstCode = item.rstCode;
        }
      }
      lab.diagnostics.length = 0;
    } finally { clearTimeout(waveTimer); }
  }
  try {
    check();
    const limits = { helloTimeoutMs: 300, ...(profile === 'slow-reader' ? { writeTimeoutMs: 2000 } : {}) };
    lab = await startTransparentTlsLab({ sessionTimeoutMs: 0, slowStreams: profile === 'slow-reader',
      h2Flow: profile === 'h2-flow', holdResponses: profile === 'h2-flow',
      clientLimits: limits, exitLimits: limits });
    proxy = await startLabConnectProxy(lab, { headerTimeoutMs: 300, maxConnections: 16,
      ...(profile === 'slow-reader' ? { closeTimeoutMs: 10_000 } : {}) });
    for (let i = 0; i < 3; i++) { await wave(); result.warmupWaves++; }
    measuredStart = performance.now();
    result.baseline = resources();
    const sample = () => {
      const point = { elapsedMs: Math.round(performance.now() - measuredStart), wave: result.waves,
        resources: resources(), lab: lab.stats(), proxy: proxy.stats() };
      assertResources(point.resources, result.baseline);
      result.samples.push(point); emit({ type: 'sample', ...point });
    };
    sample();
    while (performance.now() - measuredStart < seconds * 1000) {
      await wave(); result.waves++;
      // Every wave checks FDs, even when the time-series sample is not retained.
      const current = resources();
      assertResources(current, result.baseline);
      if (performance.now() - measuredStart - result.samples.at(-1).elapsedMs >= 5000) sample();
      await delay(250, undefined, { signal });
    }
    sample(); result.measuredMs = Math.round(performance.now() - measuredStart);
    result.memoryTrend = memoryTrend(result.samples); result.status = 'passed';
  } catch (cause) {
    result.status = signal?.aborted ? 'aborted' : 'failed';
    result.failure = { phase, code: failure?.code ?? cause.code ?? 'SOAK_FAILURE' };
    if (cause.h2Flow) result.failure.h2Flow = cause.h2Flow;
    result.atFailure = { lab: lab?.stats(), proxy: proxy?.stats(), workloadSockets: sockets.size,
      workloadTimers: timers.size, workloadRequests: requests.size };
  } finally {
    clearTimeout(waveTimer);
    signal?.removeEventListener('abort', aborted);
    cancel(error('SOAK_CLEANUP'));
    try {
      await proxy?.close(); await lab?.close();
      await immediate(); await immediate();
      result.final = { lab: lab?.stats(), proxy: proxy?.stats(), resources: resources(),
        workloadSockets: sockets.size, workloadTimers: timers.size, workloadRequests: requests.size };
      if (lab && proxy) assertIdle(result.final.lab, result.final.proxy);
      assert.equal(sockets.size + timers.size + requests.size, 0);
      if (result.baseline) assertResources(result.final.resources, result.baseline);
      for (const type of ['TCPSocketWrap', 'TCPServerWrap', 'Timeout', 'ProcessWrap']) {
        assert.equal(result.final.resources.active[type] ?? 0, 0, `worker retained ${type} after shutdown`);
      }
    } catch {
      result.status = 'failed'; result.cleanupFailed = true;
    }
  }
  return result;
}
