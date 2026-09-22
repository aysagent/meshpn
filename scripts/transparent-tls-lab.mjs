#!/usr/bin/env node
/** Explicit loopback TLS relay lab; never imports clean-vpn.js or configures the OS. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  LAB_CERT_PATH, startTransparentTlsLab, requestThroughLab, assertRelayTrace,
} from './lib/transparent-tls-lab.mjs';

function usage() {
  console.log(`Usage: node scripts/transparent-tls-lab.mjs [--serve] [--client-port=N] [--exit-port=N] [--origin-port=N]

Default: start loopback client + exit + HTTPS origin, verify HTTP/1.1 and HTTP/2,
compare real ClientHello/JA3/JA4 at three points, then close everything.
--serve: after self-check stay running for manual curl; Ctrl+C closes all sockets.
Ports default to 0 (OS-assigned); explicit ports must be 1024..65535.
Only 127.0.0.1 is used. No TUN, root, npm dependencies or firewall changes.
The checked-in certificate/private key are TEST ONLY. Never use them in production.`);
}

function parseArgs(argv) {
  const out = { serve: false, clientPort: 0, exitPort: 0, originPort: 0 };
  for (const arg of argv) {
    if (arg === '--serve') out.serve = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else {
      const match = /^--(client|exit|origin)-port=(\d+)$/.exec(arg);
      if (!match) throw new Error(`Unknown argument: ${arg}`);
      out[`${match[1]}Port`] = Number(match[2]);
    }
  }
  return out;
}

const shellQuote = (text) => `'${text.replaceAll("'", "'\\''")}'`;

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) return usage();
  const lab = await startTransparentTlsLab({ ...opts, sessionTimeoutMs: 30_000 });
  let stop;
  const stopped = new Promise((resolve) => { stop = resolve; });
  const onSignal = () => { stop(); void lab.close(); };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  try {
    for (const httpVersion of ['1.1', '2']) {
      const body = randomBytes(256 * 1024);
      const response = await requestThroughLab(lab, { httpVersion, body, path: '/echo' });
      assert.deepEqual(response.body, body, `HTTP/${httpVersion} echo`);
      const report = assertRelayTrace(lab);
      console.log(`[lab] PASS HTTP/${httpVersion} ${response.tlsVersion}, verified certificate, ${body.length} byte echo`);
      console.log(`[lab] ClientHello restored; JA3=${report.ja3} JA4=${report.ja4}`);
      console.log(`[lab] TLS record lengths ${JSON.stringify(report.records)}`);
    }
    if (opts.serve) {
      console.log(`LAB_READY ${JSON.stringify({
        host: lab.host, clientPort: lab.clientPort, exitPort: lab.exitPort,
        originPort: lab.originPort, ca: LAB_CERT_PATH,
      })}`);
      console.log(`[lab] curl --noproxy '*' --connect-to localhost:${lab.originPort}:127.0.0.1:${lab.clientPort} --cacert ${shellQuote(LAB_CERT_PATH)} https://localhost:${lab.originPort}/`);
      console.log('[lab] Loopback only. Ctrl+C stops the lab. Idle test sockets expire after 30 seconds.');
      await stopped;
    }
  } finally {
    await lab.close();
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    console.log('[lab] Closed all listeners and tracked sockets.');
  }
}

main().catch((error) => {
  console.error(`[lab] FAIL: ${error.stack ?? error}`);
  process.exitCode = 1;
});
