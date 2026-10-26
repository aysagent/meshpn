#!/usr/bin/env node
/** Run ONLY inside a disposable, network-disabled Linux browser container. */
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import puppeteer from 'puppeteer-core';
import { browserOrigin } from './lib/browser-lab-origin.mjs';
import { startBrowserCapture } from './lib/native-browser-capture-server.mjs';

const args = process.argv.slice(2), output = args[0], count = Number(args[1] ?? 20);
assert.ok(args.length >= 1 && args.length <= 2 && path.isAbsolute(output), 'absolute output required');
assert.ok(Number.isInteger(count) && count >= 3 && count <= 32, '3..32 samples required');
assert.equal(process.platform, 'linux');
assert.equal(process.env.CVPN_DISPOSABLE_BROWSER_LAB, '1', 'disposable container required');
assert.deepEqual(Object.keys(os.networkInterfaces()).sort(), ['lo'], 'network-disabled container required');
const dir = await fs.mkdtemp('/tmp/cvpn-browser-capture-');
const flags = ['--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking',
  '--no-first-run', '--no-default-browser-check', '--no-proxy-server'];
let browser, server;
try {
  const origin = await browserOrigin(dir);
  // Initialize before Chromium: launching it first may create the NSS DB itself.
  const db = '/home/node/.pki/nssdb';
  const certutilOptions = { stdio: 'pipe', timeout: 5000, maxBuffer: 16384 };
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${db}`], certutilOptions);
  const open = async label => {
    browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true,
      userDataDir: path.join(dir, label), pipe: true, args: flags, timeout: 20000 });
    return browser;
  };
  const initial = await open('untrusted');
  const version = await initial.version();
  const metadata = { schema: 1, id: 'chromium-linux-cold', identity: { browser: 'Chromium', version,
    versionSource: 'browser-protocol', platform: process.platform, architecture: process.arch },
    context: { scenario: 'cold', isolation: 'fresh-process-per-sample', certificateValidation: 'enabled',
      http: 'h2', proxy: 'none', echMode: 'grease', extensionOrder: 'permuted', padding: 'optional' } };
  server = await startBrowserCapture({ ...origin.originTls, metadata, maxSamples: count, lifetimeMs: 600000 });
  const untrustedPage = await initial.newPage();
  await assert.rejects(untrustedPage.goto(server.url, { waitUntil: 'load', timeout: 15000 }), /CERT_AUTHORITY_INVALID/);
  assert.equal(server.snapshot().samples.length, 0);
  await browser.close(); browser = null;
  // NSS belongs solely to this disposable container, never the host's trust store.
  execFileSync('certutil', ['-A', '-d', `sql:${db}`, '-n', 'cvpn-ephemeral-capture', '-t', 'C,,', '-i', origin.caPath], certutilOptions);
  let launchArguments;
  for (let i = 0; i < count; i++) {
    await open(`sample-${i}`);
    assert.equal(await browser.version(), version);
    launchArguments ??= browser.process().spawnargs.slice(1).map(arg => arg.startsWith('--user-data-dir=') ? '--user-data-dir=<fresh-temporary-profile>' : arg);
    const page = await browser.newPage();
    const response = await page.goto(server.url, { waitUntil: 'load', timeout: 15000 });
    assert.equal(response.status(), 200);
    assert.match(await page.content(), /ClientHello сохранён/);
    assert.equal(server.snapshot().samples.length, i + 1);
    // Refreshing the same connection must not manufacture another cold sample.
    await page.reload({ waitUntil: 'load', timeout: 15000 });
    assert.equal(server.snapshot().samples.length, i + 1);
    if (i === count - 1) {
      const downloaded = await page.evaluate(async url => JSON.parse(await (await fetch(url)).text()), server.bundleUrl);
      assert.equal(downloaded.contentSha256, server.snapshot().contentSha256);
    }
    await browser.close(); browser = null;
    console.error(`browser capture ${i + 1}/${count}`);
  }
  const bundle = server.snapshot();
  assert.equal(bundle.samples.length, count);
  assert.equal(bundle.assessment.http2CompleteSamples,count);
  assert.ok(bundle.samples.every(s=>s.http2.headers.names.includes('user-agent')));
  const report = { schema: 1, kind: 'clean-vpn-browser-capture-lab-report',
    captureEndpoint: { implementation: 'Node TLS -> loopback cleartext H2', node: process.version, openssl: process.versions.openssl,
      name: 'localhost', h2Settings: {maxConcurrentStreams:4,maxHeaderListSize:8192}, alps: 'not-negotiated', tls: 'TLSv1.3-only', alpn: ['h2'], sessionTickets: 'disabled',
      certificate: 'ephemeral RSA-2048 leaf and private CA', clientCaValidation: 'enabled-no-bypass',
      note: 'Private test CA and automation flags are capture conditions, not a stock public-Web browser baseline.' },
    validation: { untrustedCertificateRejected: true, trustedH2Navigations: count,
      sameConnectionReloadDeduplicated: true, downloadMatchesMemory: true, http2PrefixCaptured: true, sensitiveHeadersRedacted: true,
      network: 'container-loopback-only', browserSandbox: 'disabled-inside-disposable-unprivileged-container',
      hostTrustStoreChanged: false, physicalHostsTouched: false },
    browserLaunchArguments: launchArguments,
    packages: execFileSync('dpkg-query', ['-W', '-f=${Package}=${Version}\n', 'chromium', 'libnss3', 'libnss3-tools'], { encoding: 'utf8' }).trim().split('\n'), bundle };
  await fs.writeFile(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ status: 'capture-complete', samples: count, compatibility: bundle.assessment.status,
    unsupported: bundle.assessment.unsupported, output }));
} finally {
  await browser?.close(); await server?.close(); await fs.rm(dir, { recursive: true, force: true });
}
