/** Fixed, bounded benchmark metadata contract. No payloads or raw tool output. */
import fs from 'node:fs';
import { isIPv4 } from 'node:net';
import { requireTrial as check } from './native-radxa-trial.mjs';

export const benchmarkPhases = ['bench-old', 'bench-native', 'bench-restored'];
const exact = (v, keys) => v && !Array.isArray(v) && typeof v === 'object'
  && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const number = (v, max) => Number.isFinite(v) && v >= 0 && v <= max;
export function validateBenchmarkResult(v, request) {
  check(exact(v, ['token', 'phase', 'exitBefore', 'exitAfter', 'serverIp', 'warmup', 'download', 'upload', 'elapsedMs'])
    && v.token === request.token && v.phase === request.phase && benchmarkPhases.includes(v.phase), 'invalid_benchmark_result');
  check([null, '154.62.226.216'].includes(v.exitBefore) && [null, '154.62.226.216'].includes(v.exitAfter)
    && (v.serverIp === null || isIPv4(v.serverIp)) && typeof v.warmup === 'boolean'
    && Number.isSafeInteger(v.elapsedMs) && number(v.elapsedMs, 120000), 'invalid_benchmark_result');
  const reduce = (group, upload) => {
    check(exact(group, ['seconds', 'streams']) && number(group.seconds, 40)
      && Array.isArray(group.streams) && [0, 4].includes(group.streams.length), 'invalid_benchmark_group');
    const cap = upload ? 1048576 : 8388608, limit = upload ? 30 : 20;
    const streams = group.streams.map(s => {
      check(exact(s, ['code', 'reason', 'httpStatus', 'tlsVerify', 'bytes', 'seconds', 'remoteIp'])
        && (s.code === null || Number.isInteger(s.code) && number(s.code, 255))
        && [null, 'timeout', 'spawn_failed', 'output_limit', 'invalid_metrics'].includes(s.reason)
        && Number.isInteger(s.httpStatus) && number(s.httpStatus, 599)
        && Number.isInteger(s.tlsVerify) && number(s.tlsVerify, 1000)
        && Number.isSafeInteger(s.bytes) && number(s.bytes, cap)
        && number(s.seconds, limit + 2) && (s.remoteIp === null || isIPv4(s.remoteIp)), 'invalid_benchmark_stream');
      // Downloads cut at the time limit still measure bytes delivered. Upload
      // requires a successful final response, not merely bytes queued by curl.
      const passed = !s.reason && s.httpStatus === 200 && s.tlsVerify === 0 && s.remoteIp === v.serverIp
        && s.seconds > 0 && group.seconds + 0.1 >= s.seconds
        && (upload ? s.code === 0 && s.bytes === cap
          : (s.code === 0 && s.bytes === cap || s.code === 28 && s.seconds >= limit - 1 && s.bytes >= 65536));
      return { ...s, passed, timeLimited: s.code === 28 };
    });
    const passed = group.seconds > 0 && streams.length === 4 && streams.every(s => s.passed);
    const bytes = streams.reduce((n, s) => n + s.bytes, 0);
    return { status: passed ? 'passed' : 'failed', seconds: group.seconds, bytes,
      mbps: passed ? bytes * 8 / 1e6 / group.seconds : null,
      shortSample: passed && group.seconds < 3, streams };
  };
  const download = reduce(v.download, false), upload = reduce(v.upload, true);
  const passed = v.serverIp !== null && v.warmup && v.exitBefore && v.exitAfter
    && download.status === 'passed' && upload.status === 'passed';
  return { phase: v.phase, status: passed ? 'passed' : 'failed', serverIp: v.serverIp,
    exitBefore: v.exitBefore, exitAfter: v.exitAfter, warmup: v.warmup, download, upload, elapsedMs: v.elapsedMs };
}

export function readProcess(pid, read = file => fs.readFileSync(file, 'utf8')) {
  check(Number.isSafeInteger(pid) && pid > 0, 'invalid_cpu_root');
  const text = read(`/proc/${pid}/stat`), end = text.lastIndexOf(') ');
  check(end > 0, 'invalid_proc_stat');
  const fields = text.slice(end + 2).trim().split(/\s+/);
  const ticks = Number(fields[11]) + Number(fields[12]), start = Number(fields[19]);
  const rssKiB = Number(read(`/proc/${pid}/status`).match(/^VmRSS:\s+(\d+) kB$/m)?.[1] ?? 0);
  const children = read(`/proc/${pid}/task/${pid}/children`).trim().split(/\s+/).filter(Boolean).map(Number);
  check(Number.isSafeInteger(ticks) && ticks >= 0 && Number.isSafeInteger(start) && start > 0
    && Number.isSafeInteger(rssKiB) && rssKiB >= 0
    && children.every(n => Number.isSafeInteger(n) && n > 0), 'invalid_proc_stat');
  return { ticks, start, rssKiB, children };
}

// Average CPU for the whole peer phase, including warmup and RPC delays, NOT
// load-only CPU. Process tree includes Node and helpers on BOTH implementations.
export function sampleTrialCpu(pid, hz, { read = readProcess, now = () => performance.now(),
  every = setInterval, cancel = clearInterval } = {}) {
  check(Number.isSafeInteger(hz) && hz > 0 && hz <= 10000, 'invalid_clock_ticks');
  const records = new Map(), began = now();
  let rootStart, samples = 0, rootMissing = false, missedProcesses = 0, peakRssKiB = 0, processPeak = 0;
  const sample = () => {
    const seen = new Set(); let rss = 0;
    const visit = p => {
      if (seen.has(p)) return;
      if (seen.size >= 128) { rootMissing = true; return; }
      seen.add(p);
      try {
        const s = read(p);
        if (p === pid) { rootStart ??= s.start; if (rootStart !== s.start) rootMissing = true; }
        const key = `${p}:${s.start}`, previous = records.get(key);
        records.set(key, { first: previous?.first ?? s.ticks, last: s.ticks });
        rss += s.rssKiB; s.children.forEach(visit);
      } catch { if (p === pid) rootMissing = true; else missedProcesses++; }
    };
    visit(pid); samples++; peakRssKiB = Math.max(peakRssKiB, rss); processPeak = Math.max(processPeak, seen.size);
  };
  sample(); const timer = every(sample, 250);
  return () => {
    cancel(timer); sample(); const seconds = (now() - began) / 1000;
    const ticks = [...records.values()].reduce((n, s) => n + s.last - s.first, 0);
    const complete = !rootMissing && seconds > 0 && ticks >= 0;
    return { status: complete ? 'sampled' : 'incomplete', seconds, cpuSeconds: complete ? ticks / hz : null,
      meanOneCorePercent: complete ? 100 * ticks / hz / seconds : null, peakRssKiB, processPeak, samples,
      missedProcesses, intervalMs: 250, clockTicksPerSecond: hz,
      scope: 'client-process-tree-whole-phase-including-warmup-and-rpc; short-lived-helpers-may-be-missed; not-kernel-or-exit-cpu' };
  };
}
