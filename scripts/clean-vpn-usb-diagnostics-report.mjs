#!/usr/bin/env node
/** Read-only summary of a completed, validated diagnostics report. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertUsbSoakEvidence } from './lib/usb-soak-evidence.mjs';

export function summarizeUsbDiagnostics(report) {
  assert.equal(report.status, 'passed', 'completed successful report required');
  assert.ok(report.nativeDiagnostics, 'native diagnostics required');
  assertUsbSoakEvidence(report);
  const events = report.boots[0].events;
  const samples = events.filter(e => e.event === 'socket-sample');
  const faults = events.filter(e => e.event === 'soak-fault');
  const memories = events.filter(e => ['resources', 'quiescent-memory', 'allocator-trim'].includes(e.event));
  const beforeTrim = memories.at(-2).nodeMemory, afterTrim = memories.at(-1).nodeMemory;
  const mib = bytes => Number((bytes / 1048576).toFixed(3));
  const timeline = faults.filter(e => e.action === 'restore').map(restore => {
    const recovered = faults.find(e => e.cycle === restore.cycle && e.scenario === restore.scenario && e.action === 'recovered');
    const during = samples.filter(e => e.observedMonotonicMs >= restore.observedMonotonicMs
      && e.observedMonotonicMs <= recovered.observedMonotonicMs);
    const pick = e => e && ({ sequence: e.sequence, secondsAfterRestore: (e.observedMonotonicMs - restore.observedMonotonicMs) / 1000,
      host: e.host, exit: e.exit });
    return { cycle: restore.cycle, scenario: restore.scenario, recoverySeconds: recovered.recoveryMs / 1000,
      firstResponseSeconds: Number.isFinite(recovered.firstResponseMs) ? recovered.firstResponseMs / 1000 : null,
      restoreToRecoveredSeconds: (recovered.observedMonotonicMs - restore.observedMonotonicMs) / 1000,
      samplesDuringRecovery: during.length, first: pick(during[0]), last: pick(during.at(-1)) };
  });
  return {
    status: 'validated-lab-observation', bootId: report.boots[0].bootId,
    checks: events.filter(e => e.event === 'check').length,
    socketSamples: samples.length, timeline,
    memory: memories.map(e => ({ label: e.label ?? (e.event === 'quiescent-memory' ? `quiet-${e.quietSeconds}s` : e.event),
      rssMiB: mib(e.nodeMemory.rss), heapUsedMiB: mib(e.nodeMemory.heapUsed), fds: e.fds,
      native: e.nodeMemory.nativeMemory })),
    trim: { result: afterTrim.nativeMemory.trimmed, rssDropFromGcSnapshotMiB: mib(beforeTrim.rss - afterTrim.rss),
      observationSeconds: (afterTrim.monotonicMs - beforeTrim.monotonicMs) / 1000,
      deferredFinalizersBetweenSnapshots: afterTrim.nativeMemory.externalFinalized - beforeTrim.nativeMemory.externalFinalized,
      inUseBefore: beforeTrim.nativeMemory.inUse, inUseAfter: afterTrim.nativeMemory.inUse },
    limitations: ['synthetic-QEMU-not-physical-WiFi', 'ss-fields-kept-raw-no-RTO-unit-assumption',
      'namespace-snapshots-not-atomic', 'trim-only-after-workload-not-a-production-fix',
      'post-GC-to-trim-delta-includes-deferred-finalizers-not-trim-alone',
      'allocator-reclamation-not-proof-of-absence-of-all-leaks'],
  };
}
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    assert.equal(process.argv.length, 3, 'usage: node scripts/clean-vpn-usb-diagnostics-report.mjs REPORT.json');
    console.log(JSON.stringify(summarizeUsbDiagnostics(JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))), null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
