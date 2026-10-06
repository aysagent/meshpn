import { setTimeout as delay } from 'node:timers/promises';

// Short requests separated by > legacy's observed 5s idle timeout exercise
// both traffic and demand reconnect. No response body is retained in reports.
export async function probeNativeHold({ seconds, session, probe, report,
  cancelled = () => false, now = () => performance.now(), sleep = delay }) {
  Object.assign(report, { status: seconds ? 'running' : 'not-requested', samples: [],
    intervalSeconds: 10, scope: 'host-tun-https-with-idle-gaps-not-usb-or-leak-acceptance' });
  if (!seconds) return;
  const start = now(), deadline = start + seconds * 1000;
  let next = start;
  const check = (ok, code) => { if (!ok) throw Error(code); };
  try {
    while (now() < deadline) {
      check(!cancelled(), 'cancelled'); check(session.healthy(), 'native_exited_during_trial');
      check(!(session.diagnostics().stateCounts?.peer_address > 0), 'native_peer_address_rejected');
      if (now() >= next) {
        const atMs = Math.round(now() - start), began = now();
        let ok = false;
        try { ok = await probe(Math.max(1, Math.min(5000, Math.floor(deadline - now())))); } catch { /* Fixed result only. */ }
        report.samples.push({ atMs, passed: ok === true, seconds: (now() - began) / 1000 });
        check(!cancelled(), 'cancelled'); check(session.healthy(), 'native_exited_during_trial');
        check(ok === true, 'native_hold_https_failed');
        next = now() + 10000;
      }
      await sleep(Math.max(0, Math.min(250, next - now(), deadline - now())));
    }
    check(!cancelled(), 'cancelled'); check(session.healthy(), 'native_exited_during_trial');
    // A successful curl must not hide a rejected foreign packet anywhere in
    // this trial, including the smoke immediately preceding the hold.
    check(!(session.diagnostics().stateCounts?.peer_address > 0), 'native_peer_address_rejected');
    report.status = 'passed';
  } catch (e) { report.status = 'failed'; throw e; }
  finally {
    report.seconds = (now() - start) / 1000;
    report.passed = report.samples.filter(s => s.passed).length;
    report.failed = report.samples.length - report.passed;
    // Complete cumulative counts, not just the last 48 events. These include
    // startup/smoke and are explicitly not interpreted as all being failures.
    report.sessionStateCounts = session.diagnostics().stateCounts;
  }
}
