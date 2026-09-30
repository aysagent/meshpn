/** Invoked only by the synthetic network consumer inside the VM client netns. */
import assert from 'node:assert/strict';
import { readFileSync, readlinkSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { exchangePlainDns } from './dns-tunnel-forwarder.mjs';
import { makeDnsQuery, parseDns } from './lab-dns-wire.mjs';

assert.match(readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.host-boot-order=1(?:\s|$)/);
assert.match(readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
assert.equal(readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
assert.notEqual(readlinkSync('/proc/self/ns/net'), readlinkSync('/proc/1/ns/net'));
assert.equal(process.getuid(), 0);
const directory = process.argv[2];
assert.match(directory, /^\/tmp\/host-systemd-[A-Za-z0-9]+$/);
const ca = readFileSync(`${directory}/fullchain.pem`);
async function query(host) {
  return new Promise(resolve => {
    let finished = false;
    const done = value => { if (!finished) { finished = true; clearTimeout(timer); resolve(value); } };
    const q = https.get({ host, port: 18443, servername: 'origin.test', ca, agent: false }, r => {
      let body = '';
      r.on('data', b => { body += b; if (body.length > 1024) q.destroy(Error('oversize')); });
      r.on('end', () => done(r.statusCode === 200 ? body : 'BAD_HTTP'));
      r.on('error', () => done('BLOCKED'));
    });
    const timer = setTimeout(() => { q.destroy(); done('BLOCKED'); }, 5000);
    q.on('error', () => done('BLOCKED'));
  });
}
const probes = { ipv4: await query('1.0.0.1'), ipv6: await query('2606:4700:4700::1111') };
try {
  const b = await exchangePlainDns({ server: '1.1.1.1', localAddress: '0.0.0.0', query: makeDnsQuery('boot-order.test'), timeoutMs: 5000 });
  const r = parseDns(b).records.find(r => r.type === 1);
  probes.dns = r ? [...b.subarray(r.offset, r.offset + 4)].join('.') : 'NOANSWER';
} catch { probes.dns = 'BLOCKED'; }
writeFileSync('/run/host-boot-observer.json', JSON.stringify(probes), { flag: 'wx', mode: 0o600 });
