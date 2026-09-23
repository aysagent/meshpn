#!/usr/bin/env node
/** Linux rootless real-browser + real-pcap acceptance test; no host traffic capture. */
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, readlink, stat, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startTransparentTlsLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';
import { startLabConnectProxy } from './lib/transparent-connect-lab.mjs';
import { child, exec, launchBrowser, BROWSER_SCENARIOS } from './lib/browser-lab-driver.mjs';
import { PCAP_FIELDS, parseBrowserPcap, assertBrowserPcap } from './lib/browser-lab-pcap.mjs';

const self = fileURLToPath(import.meta.url);
const mode = process.argv[2] ?? 'all';
if (!['all', 'chrome', 'firefox', '--isolated'].includes(mode)) throw new Error('Usage: node scripts/transparent-browser-lab.mjs [all|chrome|firefox]');
if (process.platform !== 'linux' || typeof WebSocket !== 'function') throw new Error('Requires Linux and Node 22+');

if (mode !== '--isolated') {
  // Only lo exists in this new network namespace. No host DNS/routes/firewall edits.
  // Keep the real UID so the browser sandbox stays enabled (no --no-sandbox).
  const parentNet = await readlink('/proc/self/ns/net');
  const runner = child('unshare', ['--user', '--map-current-user', '--net', '--mount', '--keep-caps',
    'sh', '-eu', '-c', 'ip link set lo up; exec "$@"', 'browser-lab',
    process.execPath, self, '--isolated', mode], { env: { ...process.env, MESHPN_PARENT_NETNS: parentNet }, stdio: ['ignore', 'pipe', 'pipe'] });
  runner.proc.stdout.pipe(process.stdout); runner.proc.stderr.pipe(process.stderr);
  runner.proc.once('error', (error) => console.error(`Cannot start isolated browser lab: ${error.message}`));
  const signal = () => { void runner.stop(); };
  process.once('SIGINT', signal); process.once('SIGTERM', signal);
  await new Promise((resolve) => runner.proc.once('close', (code) => { process.exitCode = code ?? 1; resolve(); }));
  process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal);
} else {
  process.umask(0o077);
  // Never inherit TLS secret logging from a developer shell into this lab.
  delete process.env.SSLKEYLOGFILE;
  // Refuse a bare invocation of the internal entry point in the host namespace.
  assert.notEqual(await readlink('/proc/self/ns/net'), process.env.MESHPN_PARENT_NETNS, 'private network namespace required');
  assert.ok(process.env.MESHPN_PARENT_NETNS, 'use the public launcher');
  const { stdout: links } = await exec('ip', ['-j', 'link', 'show']);
  assert.deepEqual(JSON.parse(links).map((link) => link.ifname), ['lo']);
  const kinds = process.argv[3] === 'all' ? ['chrome', 'firefox'] : [process.argv[3]];
  assert.ok(kinds.every((kind) => ['chrome', 'firefox'].includes(kind)));
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-browser-lab-'));
  const deadline = setTimeout(() => { console.error('Browser lab deadline exceeded'); process.kill(process.pid, 'SIGTERM'); }, 180_000);
  const cleanups = new Set();
  let cleanupPromise;
  function cleanup() {
    return cleanupPromise ??= (async () => {
      const errors = [];
      for (const close of [...cleanups].reverse()) {
        try { await close(); } catch (error) { errors.push(error); }
      }
      await rm(directory, { recursive: true, force: true });
      if (errors.length) throw new AggregateError(errors, 'browser lab cleanup');
    })();
  }
  const onSignal = () => { void cleanup().finally(() => process.exit(1)); };
  process.once('SIGINT', onSignal); process.once('SIGTERM', onSignal);
  try {
    const tshark = process.env.MESHPN_TSHARK || 'tshark';
    const { stdout: fields } = await exec(tshark, ['-G', 'fields'], { maxBuffer: 32 * 1024 * 1024 });
    for (const name of ['tls.handshake.ja3', 'tls.handshake.ja4']) assert.ok(fields.includes(`\t${name}\t`), `tshark missing ${name}`);
    // Firefox correctly rejects CA:TRUE used as a TLS end entity. Keep old
    // fixtures unchanged; generate a real CA/leaf pair just for this run.
    const caPath = join(directory, 'ca.pem'), caKey = join(directory, 'ca.key');
    const certPath = join(directory, 'leaf.pem'), keyPath = join(directory, 'leaf.key');
    const csr = join(directory, 'leaf.csr');
    await exec('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=meshpn-ephemeral-browser-lab', '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', caKey, '-out', caPath]);
    await exec('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE',
      '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth',
      '-keyout', keyPath, '-out', csr]);
    await exec('openssl', ['x509', '-req', '-in', csr, '-CA', caPath, '-CAkey', caKey,
      '-set_serial', '2', '-days', '1', '-copy_extensions', 'copy', '-out', certPath]);
    const originTls = { cert: await readFile(certPath), key: await readFile(keyPath) };
    for (const kind of kinds) for (const scenario of BROWSER_SCENARIOS) {
      const trusted = scenario !== 'untrusted';
      const retryGroup = kind === 'firefox' ? 'P-384' : 'P-256';
      const caseDir = join(directory, `${kind}-${scenario}`);
      await mkdir(caseDir, { mode: 0o700 });
      const lab = await startTransparentTlsLab({ sessionTimeoutMs: 30_000,
        holdResponses: scenario === 'parallel-abort',
        originTls: { ...originTls, ...(scenario === 'hrr' ? { ecdhCurve: retryGroup } : {}) } });
      cleanups.add(lab.close);
      const proxy = await startLabConnectProxy(lab);
      cleanups.add(proxy.close);
      const pcap = join(caseDir, 'loopback.pcap');
      const ports = { client: lab.clientPort, exit: lab.exitPort, origin: lab.originPort };
      const capture = child(process.env.MESHPN_TCPDUMP || 'tcpdump', [
        '-i', 'lo', '-n', '-U', '-s', '0', '-c', '10000', '-w', pcap,
        `tcp and (${Object.values(ports).map((port) => `port ${port}`).join(' or ')})`,
      ]);
      const stopCapture = () => capture.stop('SIGINT');
      cleanups.add(stopCapture);
      await capture.waitFor(/listening on lo/);
      let stopBrowserProcess;
      const browser = await launchBrowser(kind, { directory: caseDir, proxy, trusted, caPath,
        onProcess: (proc) => { stopBrowserProcess = () => proc.stop(); cleanups.add(stopBrowserProcess); },
      });
      cleanups.delete(stopBrowserProcess);
      cleanups.add(browser.close);
      const expectations = new Map();
      function expectConnection({ hrr = false, offered = false, resumed = false } = {}) {
        const fresh = lab.captures.filter((hello) => hello.stage === 'client' && hello.flight === 1 && !expectations.has(hello.id));
        assert.equal(fresh.length, 1, 'exactly one new browser TLS connection per phase');
        expectations.set(fresh[0].id, { hrr, offered, resumed });
        for (let flight = 1; flight <= (hrr ? 2 : 1); flight++) assertRelayTrace(lab, fresh[0].id, flight);
        if (hrr) {
          const wire = lab.captures.filter((hello) => hello.stage === 'exit' && hello.id === fresh[0].id);
          assert.equal(wire.length, 2);
          assert.equal(wire[1].sni, wire[0].sni, 'CH2 reuses the original enc-SNI route token');
        }
      }
      async function echoAndInfo() {
        const result = await browser.evaluate(`(async () => {
          const body = 'browser-native-payload:'.repeat(4096);
          const echo = await (await fetch('/echo', { method: 'POST', body, cache: 'no-store' })).text();
          const info = await (await fetch('/', { cache: 'no-store' })).json();
          return { echo: echo === body, info, userAgent: navigator.userAgent };
        })()`);
        assert.equal(result.echo, true);
        assert.equal(result.info.httpVersion, '2.0');
        assert.equal(result.info.tlsVersion, 'TLSv1.3');
        assert.equal(result.info.userAgent, result.userAgent);
        return result.info;
      }
      const url = `https://${proxy.authority}/browser`;
      if (!trusted) {
        await assert.rejects(browser.navigate(url), /ERR_CERT_AUTHORITY_INVALID|MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT|SEC_ERROR_UNKNOWN_ISSUER/);
        assert.equal(lab.stats().requests, 0, 'untrusted connection must not send HTTP');
        expectConnection();
      } else {
        await browser.navigate(url);
        // CDP Page.navigate precedes load. Wait for the expected document, not a fixed sleep.
        const until = Date.now() + 10_000;
        while (!(await browser.evaluate('document.title === "Transparent TLS lab"'))) {
          if (Date.now() > until) throw new Error('browser document deadline');
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
        assert.equal((await echoAndInfo()).sessionReused, false);
        expectConnection({ hrr: scenario === 'hrr' });
        assert.equal(lab.stats().tlsConnections, 1);
        if (scenario === 'parallel-abort') {
          async function held(count) {
            const deadline = Date.now() + 3000;
            while (lab.stats().heldResponses !== count) {
              if (Date.now() > deadline) throw new Error(`held responses never reached ${count}`);
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
          }
          for (let wave = 0; wave < 4; wave++) {
            await browser.evaluate(`(() => {
              window.labControllers = Array.from({ length: 8 }, () => new AbortController());
              window.labResults = Promise.all(window.labControllers.map(async (controller) => {
                try {
                  const response = await fetch('/hold', { signal: controller.signal, cache: 'no-store' });
                  return response.status === 200 && await response.text() === 'released' ? 'ok' : 'bad-response';
                } catch (error) { return error.name; }
              }));
              return true;
            })()`);
            await held(8); // prove all aborted requests actually reached the origin
            await browser.evaluate('(() => { window.labControllers.slice(0, 4).forEach(c => c.abort()); return true; })()');
            await held(4);
            lab.releaseHeldResponses();
            assert.deepEqual(await browser.evaluate('window.labResults'), [...Array(4).fill('AbortError'), ...Array(4).fill('ok')]);
            await held(0);
            const results = await browser.evaluate(`Promise.all(Array.from({ length: 8 }, async (_, i) => {
              const body = String(i).repeat(65536);
              const response = await fetch('/echo', { method: 'POST', body, cache: 'no-store' });
              return response.status === 200 && await response.text() === body;
            }))`);
            assert.deepEqual(results, Array(8).fill(true));
          }
          assert.equal((await echoAndInfo()).httpVersion, '2.0');
          assert.equal(lab.stats().tlsConnections, 1, 'HTTP/2 stream aborts must not destroy the TLS connection');
        }
        if (['resumption', 'resumption-hrr', 'ticket-rejection'].includes(scenario)) {
          const resumed = scenario !== 'ticket-rejection';
          // Separate cold profiles for acceptance/rejection: a browser may consume
          // its only ticket on resume and offer no PSK on a third connection.
          if (!resumed) lab.rotateTicketKeys();
          if (scenario === 'resumption-hrr') lab.setOriginGroups(retryGroup);
          await lab.drainOriginHttp2();
          assert.equal((await echoAndInfo()).sessionReused, resumed, 'new TLS connection must match ticket acceptance policy');
          expectConnection({ offered: true, resumed, hrr: scenario === 'resumption-hrr' });
          assert.equal(lab.stats().tlsConnections, 2);
          assert.equal(lab.stats().resumedTlsConnections, resumed ? 1 : 0);
        }
      }
      assert.ok(proxy.stats().tunnels > 0, 'browser must actually use CONNECT');
      assert.equal(proxy.stats().tunnels, expectations.size, 'no hidden CONNECT retry');
      assert.equal(lab.stats().originConnections, expectations.size, 'HRR does not create another origin connection');
      await browser.close(); cleanups.delete(browser.close);
      // tcpdump capture buffer is not flushed by -U until packets reach userspace.
      await new Promise((resolve) => setTimeout(resolve, 1100));
      await stopCapture(); cleanups.delete(stopCapture);
      assert.ok((await stat(pcap)).size > 24, 'nonempty real network capture');
      const args = ['-r', pcap, ...Object.values(ports).flatMap((port) => ['-d', `tcp.port==${port},tls`]),
        '-Y', 'tls.handshake.type==1 || tls.handshake.type==2', '-T', 'fields', '-E', 'occurrence=a',
        ...PCAP_FIELDS.flatMap((field) => ['-e', field])];
      const { stdout } = await exec(tshark, args);
      const checked = assertBrowserPcap(parseBrowserPcap(stdout, ports), lab.captures, expectations);
      await proxy.close(); cleanups.delete(proxy.close);
      await lab.close(); cleanups.delete(lab.close);
      assert.equal(proxy.stats().clients + proxy.stats().upstreams + proxy.stats().headerTimers + lab.stats().sockets + lab.stats().heldResponses, 0);
      console.log(`PASS ${browser.version} ${scenario}: ${trusted ? 'verified TLS1.3 + HTTP/2 + echo + native UA' : 'untrusted certificate rejected before HTTP'}; ${expectations.size} connections, ${checked} ClientHellos independently checked by tshark`);
      console.log(`BROWSER_RESULT ${JSON.stringify({ schema: 1, kind, scenario, version: browser.version,
        connections: expectations.size, clientHellos: checked })}`);
    }
  } finally {
    clearTimeout(deadline); await cleanup();
    process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal);
  }
}
