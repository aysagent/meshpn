/** One browser/profile + persistent client/exit/origin; no packet capture or downloads. */
import assert from 'node:assert/strict';
import { setTimeout as delay, setImmediate as immediate } from 'node:timers/promises';
import { launchBrowser, exec } from './browser-lab-driver.mjs';
import { browserOrigin } from './browser-lab-origin.mjs';
import { startTransparentTlsLab, assertRelayTrace } from './transparent-tls-lab.mjs';
import { startLabConnectProxy } from './transparent-connect-lab.mjs';
import { assertIdle } from './transparent-soak.mjs';
import { assertBrowserNamespace, namespaceResources, assertBrowserResources, waitBrowserCleanup } from './browser-soak.mjs';

export async function runBrowserSoak(options, directory, emit) {
  assertBrowserNamespace();
  const { stdout } = await exec('ip', ['-j', 'link', 'show']);
  assert.deepEqual(JSON.parse(stdout).map((link) => link.ifname), ['lo']);
  const { browser: kind, seconds, concurrency } = options;
  assert.ok(['chrome', 'firefox'].includes(kind));
  const result = { schema: 1, browser: kind, seconds, concurrency, status: 'failed', launches: 0,
    warmupWaves: 0, waves: 0, samples: [], totals: { echoes: 0, echoBytes: 0, aborted: 0,
      heldCompleted: 0, drains: 0, connections: 0, clientHellos: 0 } };
  const controller = new AbortController();
  let lab, proxy, browser, proc, stopping, phase = 'setup', waveTimer, timedOut = false;
  const stopBrowser = () => !browser && !proc ? Promise.resolve() : stopping ??= browser ? browser.close() : proc.stop();
  const abort = () => { controller.abort(); void stopBrowser().catch(() => {}); };
  process.once('SIGTERM', abort); process.once('SIGINT', abort);
  const check = () => { if (controller.signal.aborted) throw Object.assign(new Error('BROWSER_SOAK_ABORTED'), { code: 'BROWSER_SOAK_ABORTED' }); };
  async function until(predicate, ms = 5000) {
    const end = performance.now() + ms;
    while (!predicate()) {
      check(); if (performance.now() > end) throw Object.assign(new Error('BROWSER_SOAK_OBSERVATION'), { code: 'BROWSER_SOAK_OBSERVATION' });
      await delay(10, undefined, { signal: controller.signal });
    }
    check();
  }
  async function idle() {
    await until(() => { try { assertIdle(lab.stats(), proxy.stats()); return true; } catch { return false; } });
    await immediate(); await immediate();
  }
  async function drainAndTrace(before) {
    await lab.drainOriginHttp2(); await idle();
    assert.equal(lab.stats().tlsConnections - before.tlsConnections, 1);
    assert.equal(lab.stats().originConnections - before.originConnections, 1);
    assert.equal(proxy.stats().tunnels - result.totals.connections, 1);
    const hellos = lab.captures.filter((item) => item.stage === 'client');
    assert.equal(hellos.length, 1); assert.equal(lab.captures.length, 3);
    assertRelayTrace(lab, hellos[0].id);
    assert.equal(lab.runtimeErrors.length, 0);
    result.totals.connections++; result.totals.drains++; result.totals.clientHellos += 3;
    lab.captures.length = 0; lab.diagnostics.length = 0;
  }
  async function wave() {
    check();
    waveTimer = setTimeout(() => { timedOut = true; abort(); }, 30_000);
    const before = lab.stats();
    try {
      phase = 'echo';
      assert.deepEqual(await browser.evaluate(`Promise.all(Array.from({ length: ${concurrency} }, async (_, i) => {
        const body = String(i % 10).repeat(65536);
        const response = await fetch('/echo', { method: 'POST', body, cache: 'no-store' });
        return response.status === 200 && await response.text() === body;
      }))`), Array(concurrency).fill(true));
      phase = 'held';
      await browser.evaluate(`(() => {
        window.soakControllers = Array.from({ length: ${concurrency} }, () => new AbortController());
        window.soakResults = Promise.all(window.soakControllers.map(async (controller) => {
          try {
            const res = await fetch('/hold', { method: 'POST', body: 'admitted', signal: controller.signal, cache: 'no-store' });
            return res.status === 200 && await res.text() === 'released' ? 'ok' : 'bad-response';
          } catch (error) { return error.name; }
        })); return true;
      })()`);
      await until(() => lab.stats().heldResponses === concurrency);
      emit({ type: 'held', browser: kind });
      await delay(100, undefined, { signal: controller.signal });
      const cancelled = Math.floor(concurrency / 2);
      phase = 'abort-streams';
      await browser.evaluate(`(() => { window.soakControllers.slice(0, ${cancelled}).forEach(c => c.abort()); return true; })()`);
      await until(() => lab.stats().heldResponses === concurrency - cancelled);
      lab.releaseHeldResponses();
      assert.deepEqual(await browser.evaluate('window.soakResults'), [...Array(cancelled).fill('AbortError'), ...Array(concurrency - cancelled).fill('ok')]);
      await browser.evaluate('(() => { delete window.soakControllers; delete window.soakResults; return true; })()');
      await until(() => lab.stats().heldResponses === 0);
      phase = 'info';
      const info = await browser.evaluate(`(async () => ({ info: await (await fetch('/', { cache: 'no-store' })).json(),
        ua: navigator.userAgent, sameProfile: window.soakIdentity === localStorage.getItem('soakIdentity') }))()`);
      assert.equal(info.sameProfile, true); assert.equal(info.info.userAgent, info.ua);
      assert.equal(info.info.httpVersion, '2.0'); assert.equal(info.info.tlsVersion, 'TLSv1.3');
      assert.equal(lab.stats().requests - before.requests, 2 * concurrency + 1, 'unexpected request/replay');
      phase = 'drain'; await drainAndTrace(before);
      result.totals.echoes += concurrency; result.totals.echoBytes += concurrency * 65536;
      result.totals.aborted += cancelled; result.totals.heldCompleted += concurrency - cancelled;
    } finally { clearTimeout(waveTimer); }
  }
  try {
    const { caPath, originTls } = await browserOrigin(directory); check();
    lab = await startTransparentTlsLab({ originTls, sessionTimeoutMs: 0, holdResponses: true });
    proxy = await startLabConnectProxy(lab);
    phase = 'launch-browser'; check();
    browser = await launchBrowser(kind, { directory, proxy, trusted: true, caPath,
      onProcess(value) { proc = value; result.launches++; if (controller.signal.aborted) void proc.stop(); } });
    check(); result.version = browser.version;
    phase = 'navigate';
    const before = lab.stats();
    await browser.navigate(`https://${proxy.authority}/browser`);
    const end = performance.now() + 10_000;
    while (!(await browser.evaluate('document.title === "Transparent TLS lab"'))) {
      check(); if (performance.now() > end) throw new Error('document deadline'); await delay(25);
    }
    await browser.evaluate('(() => { window.soakIdentity = crypto.randomUUID(); localStorage.setItem("soakIdentity", window.soakIdentity); return true; })()');
    await drainAndTrace(before);
    for (let i = 0; i < 3; i++) {
      await wave(); result.warmupWaves++; phase = 'resources'; assertBrowserResources(namespaceResources());
    }
    const started = performance.now();
    result.baseline = namespaceResources(); assertBrowserResources(result.baseline);
    const sample = () => {
      const resources = namespaceResources(); assertBrowserResources(resources, result.baseline);
      const point = { elapsedMs: Math.round(performance.now() - started), wave: result.waves, resources };
      result.samples.push(point); emit({ type: 'sample', browser: kind, ...point });
    };
    sample();
    while (performance.now() - started < seconds * 1000) {
      await wave(); result.waves++;
      phase = 'resources'; assertBrowserResources(namespaceResources(), result.baseline);
      if (performance.now() - started - result.samples.at(-1).elapsedMs >= 5000) sample();
      await delay(250, undefined, { signal: controller.signal });
    }
    sample(); result.measuredMs = Math.round(performance.now() - started); result.status = 'passed';
  } catch (error) {
    result.status = controller.signal.aborted && !timedOut ? 'aborted' : 'failed';
    result.failure = { phase, code: timedOut ? 'BROWSER_SOAK_WAVE_TIMEOUT' : error.code ?? 'BROWSER_SOAK_FAILURE' };
    if (typeof error.actual === 'number' || typeof error.actual === 'boolean') result.failure.actual = error.actual;
    if (typeof error.expected === 'number' || typeof error.expected === 'boolean') result.failure.expected = error.expected;
    try { result.atFailure = { resources: namespaceResources(), lab: lab?.stats(), proxy: proxy?.stats() }; }
    catch (resourceError) { result.resourceError = resourceError.code ?? 'RESOURCE_SNAPSHOT'; }
  } finally {
    clearTimeout(waveTimer);
    // Keep attempting every cleanup even if an earlier one fails.
    for (const close of [stopBrowser, () => proxy?.close(), () => lab?.close()]) {
      try { await close(); } catch { result.cleanupFailed = true; }
    }
    await immediate(); await immediate();
    try {
      result.final = { ...await waitBrowserCleanup(), lab: lab?.stats(), proxy: proxy?.stats() };
      assert.equal(result.final.resources.tree.live, 1);
      if (lab && proxy) assertIdle(result.final.lab, result.final.proxy);
      for (const key of ['TCPSocketWrap', 'TCPServerWrap', 'Timeout', 'ProcessWrap']) assert.equal(result.final.resources.worker.active[key] ?? 0, 0);
    } catch (error) { result.cleanupFailed = true; result.cleanupError = error.code ?? 'CLEANUP_SNAPSHOT'; }
    if (result.cleanupFailed) result.status = 'failed';
    process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort);
  }
  return result;
}
