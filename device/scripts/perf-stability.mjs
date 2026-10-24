// P4 local USB stress with concurrent admin reads. No WAN or network changes.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
import {discoverBoard,checkLocalRoute} from './perf-network.mjs';
import {cleanStatus} from './perf-runner.mjs';
import {stats} from './perf-lib.mjs';

export async function stability({minutes = 15, out, adminURL = 'http://192.168.10.1/'} = {}) {
  if (!out || !Number.isFinite(minutes) || minutes < 0.1 || minutes > 120) throw Error('Require --out and --minutes 0.1..120');
  await fs.mkdir(path.dirname(path.resolve(out)), {recursive: true}); await fs.mkdir(out);
  const r = {started: new Date().toISOString(), status: 'running', minutes, measurements: []};
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try {
    const board = await discoverBoard({paths: 'usb', localOnly: true, adminURL}, controller.signal, console.log);
    assert.equal(board.initial.board, 'waveshare_esp32_p4_wifi6');
    assert.equal(board.initial.vpn.enabled, false, 'Restore VPN settings before baseline stress');
    await checkLocalRoute(board.paths[0], controller.signal);
    r.before = cleanStatus(board.initial); const boot = board.initial.boot_count;
    const end = Date.now() + minutes * 60000;
    let i = 0;
    while (Date.now() < end) {
      if (controller.signal.aborted) throw Error('Interrupted');
      const m = {run: i++, started: new Date().toISOString()};
      const transfer = board.download();
      // Observe API availability while the single HTTP worker is streaming.
      const reader = (async () => { await delay(100); const started = performance.now();
        const s = await board.status(); return {ms: performance.now() - started, s}; })();
      const outcomes = await Promise.allSettled([transfer, reader]);
      if (outcomes.some(v => v.status === 'rejected')) throw outcomes.find(v => v.status === 'rejected').reason;
      Object.assign(m, outcomes[0].value); m.admin_ms = outcomes[1].value.ms;
      const s = outcomes[1].value.s;
      assert.equal(s.boot_count, boot, 'Board rebooted under load');
      assert(s.usb.host_ready && s.wifi.connected, 'USB or STA disconnected');
      m.status = cleanStatus(s);
      await fs.appendFile(path.join(out, 'measurements.ndjson'), JSON.stringify(m) + '\n');
      r.measurements.push({run: m.run, seconds: m.seconds, receiver_mbps: m.receiver_mbps, admin_ms: m.admin_ms});
      if (i % 10 === 0) console.log(`P4 stability: ${i} downloads; last ${m.receiver_mbps.toFixed(2)} Mbit/s; admin ${m.admin_ms.toFixed(0)} ms`);
      await delay(i % 10 === 0 ? 5000 : 1000, undefined, {signal: controller.signal});
    }
    await delay(3000); r.after = cleanStatus(await board.status());
    assert.equal(r.after.boot_count, boot);
    r.status = 'completed';
  } catch (e) { r.status = 'failed'; r.error = e.message; }
  finally {
    r.ended = new Date().toISOString();
    r.receiver_mbps = stats(r.measurements.map(m => m.receiver_mbps));
    r.admin_latency_ms = stats(r.measurements.map(m => m.admin_ms));
    await fs.writeFile(path.join(out, 'result.json'), JSON.stringify(r, null, 2));
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
  }
  return r;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const o = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    const key = {'--minutes': 'minutes', '--out': 'out', '--admin-url': 'adminURL'}[process.argv[i]];
    if (!key || !process.argv[i + 1]) throw Error('Unknown option or missing value');
    o[key] = key === 'minutes' ? Number(process.argv[i + 1]) : process.argv[i + 1];
  }
  const r = await stability(o); console.log(JSON.stringify({status: r.status, error: r.error, mbps: r.receiver_mbps, admin_ms: r.admin_latency_ms}));
  process.exitCode = r.status === 'completed' ? 0 : 1;
}
