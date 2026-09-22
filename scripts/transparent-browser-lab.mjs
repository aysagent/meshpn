#!/usr/bin/env node
/** Linux rootless real-browser + real-pcap acceptance test; no host traffic capture. */
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, readlink, stat, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startTransparentTlsLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';
import { startLabConnectProxy } from './lib/transparent-connect-lab.mjs';
import { child, exec, launchBrowser } from './lib/browser-lab-driver.mjs';

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
  const deadline = setTimeout(() => { console.error('Browser lab deadline exceeded'); process.kill(process.pid, 'SIGTERM'); }, 120_000);
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
    for (const kind of kinds) for (const trusted of [false, true]) {
      const caseDir = join(directory, `${kind}-${trusted}`);
      await mkdir(caseDir, { mode: 0o700 });
      const lab = await startTransparentTlsLab({ sessionTimeoutMs: 30_000, originTls });
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
      const url = `https://${proxy.authority}/browser`;
      if (!trusted) {
        await assert.rejects(browser.navigate(url), /ERR_CERT_AUTHORITY_INVALID|MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT|SEC_ERROR_UNKNOWN_ISSUER/);
        assert.equal(lab.stats().requests, 0, 'untrusted connection must not send HTTP');
      } else {
        await browser.navigate(url);
        // CDP Page.navigate precedes load. Wait for the expected document, not a fixed sleep.
        const until = Date.now() + 10_000;
        while (!(await browser.evaluate('document.title === "Transparent TLS lab"'))) {
          if (Date.now() > until) throw new Error('browser document deadline');
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
        const result = await browser.evaluate(`(async () => {
          const body = 'browser-native-payload:'.repeat(4096);
          const echo = await (await fetch('/echo', { method: 'POST', body })).text();
          const info = await (await fetch('/')).json();
          return { echo: echo === body, info, userAgent: navigator.userAgent };
        })()`);
        assert.equal(result.echo, true);
        assert.equal(result.info.httpVersion, '2.0');
        assert.equal(result.info.tlsVersion, 'TLSv1.3');
        assert.equal(result.info.userAgent, result.userAgent);
        assertRelayTrace(lab);
      }
      assert.ok(proxy.stats().tunnels > 0, 'browser must actually use CONNECT');
      await browser.close(); cleanups.delete(browser.close);
      // tcpdump capture buffer is not flushed by -U until packets reach userspace.
      await new Promise((resolve) => setTimeout(resolve, 1100));
      await stopCapture(); cleanups.delete(stopCapture);
      assert.ok((await stat(pcap)).size > 24, 'nonempty real network capture');
      const args = ['-r', pcap, ...Object.values(ports).flatMap((port) => ['-d', `tcp.port==${port},tls`]),
        '-Y', 'tls.handshake.type==1', '-T', 'fields', '-E', 'occurrence=f',
        ...['tcp.dstport', 'tls.handshake.random', 'tls.handshake.extensions_server_name', 'tls.handshake.ja3', 'tls.handshake.ja4'].flatMap((field) => ['-e', field])];
      const { stdout } = await exec(tshark, args);
      const rows = stdout.trim().split('\n').map((line) => line.split('\t'));
      let checked = 0;
      for (const hello of lab.captures) {
        assert.equal(hello.flight, 1, 'this browser baseline expects no HRR');
        const row = rows.find(([port, random]) => Number(port) === ports[hello.stage] && random.replaceAll(':', '') === hello.id);
        assert.ok(row, `pcap missing ${hello.stage} ClientHello`);
        assert.equal(row[2], hello.sni, `${hello.stage} independent SNI`);
        assert.equal(row[3], hello.ja3, `${hello.stage} independent JA3`);
        assert.equal(row[4], hello.ja4, `${hello.stage} independent JA4`);
        checked++;
      }
      assert.ok(checked >= 3, 'all three relay stages captured');
      assert.deepEqual(new Set(lab.captures.map((hello) => hello.stage)), new Set(Object.keys(ports)));
      for (const hello of lab.captures.filter((hello) => hello.stage === 'client')) assertRelayTrace(lab, hello.id);
      await proxy.close(); cleanups.delete(proxy.close);
      await lab.close(); cleanups.delete(lab.close);
      assert.equal(proxy.stats().clients + proxy.stats().upstreams + proxy.stats().headerTimers + lab.stats().sockets, 0);
      console.log(`PASS ${browser.version}: ${trusted ? 'verified TLS1.3 + HTTP/2 + echo + native UA' : 'untrusted certificate rejected before HTTP'}; ${checked} ClientHellos independently checked by tshark`);
    }
  } finally {
    clearTimeout(deadline); await cleanup();
    process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal);
  }
}
