/** Public-contract client -> numeric exit -> pinned resolver, isolated from host uplink. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { namespaceArgs } from './lib/browser-soak.mjs';

for (const modeTag of ['transparent-tls', 'combo-tls']) for (const family of [4, 6]) {
  test(`DNS adapter public IPv${family}/${modeTag}: large TCP/DoH, EDNS, Age, CA, failover, cleanup`, { timeout: 20000 }, async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'meshpn-dns-adapter-real-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const source = `
      import {runPinnedDnsRouteLab} from './scripts/lib/dns-upstream-route-lab.mjs';
      process.umask(0o077); delete process.env.SSLKEYLOGFILE;
      console.log = console.error = console.warn = () => {};
      try {
        const result = await runPinnedDnsRouteLab(process.env.MESHPN_ROUTE_DIR, '${modeTag}', ${family}, {adapter: true});
        process.stdout.write('DNS_ADAPTER_RESULT ' + JSON.stringify(result) + '\\n');
      } catch (error) { process.stderr.write('DNS_ADAPTER_FAILED ' + (error.code ?? error.name)); process.exitCode = 1; }
    `;
    const result = await runCommand('unshare', [...namespaceArgs, 'sh', '-eu', '-c', 'ulimit -c 0; ip link set lo up; exec "$@"',
      'dns-adapter', process.execPath, '--input-type=module', '-e', source], { timeoutMs: 15000,
      env: { ...cleanEnvironment(process.env), MESHPN_ROUTE_DIR: directory,
        MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const lines = result.stdout.trim().split('\n'); assert.equal(lines.length, 1); assert.ok(lines[0].startsWith('DNS_ADAPTER_RESULT '));
    const report = JSON.parse(lines[0].slice(19));
    assert.equal(report.status, 'passed'); assert.equal(report.family, family); assert.equal(report.modeTag, modeTag);
    assert.equal(report.adapter, true); assert.equal(report.requests, 15);
    assert.equal(report.tcpAttempts, 26); assert.equal(report.dnsCalls, 0); assert.equal(report.resolverBodies, 11);
    assert.equal(report.resources.tree.live, 1); assert.ok(!result.stdout.includes('private-pinned'));
  });
}
