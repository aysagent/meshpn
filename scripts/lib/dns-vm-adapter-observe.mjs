/** VM-only preload. Persist only bounded numeric/redacted failures in PrivateTmp. */
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, openSync, writeSync, ftruncateSync, closeSync, constants } from 'node:fs';
import { channel } from 'node:diagnostics_channel';
import { vmBootOptions } from './dns-vm-protocol.mjs';

const { phase } = vmBootOptions(readFileSync('/proc/cmdline', 'utf8'));
const coupled = ['coupled', 'coupled-cut', 'coupled-inspect'].includes(phase);
assert.ok(phase === 'systemd' || coupled);
assert.match(readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
assert.equal(readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
assert.equal(process.ppid, 1); assert.ok(process.getuid() > 0);
assert.ok(readdirSync('/sys/class/net').every((name) => ['lo', 'dnsfixture'].includes(name)
  || coupled && /^cvdns[a-f0-9]{8}$/.test(name)));
assert.ok(process.argv.includes('--systemd-notify'));
const records = []; let fd;
channel('clean-vpn.dns.query-failure').subscribe((record) => {
  try {
    const memory = process.memoryUsage();
    records.push({ ...record, rss: memory.rss, heapUsed: memory.heapUsed });
    // The VM unit owns a persistent bounded-read sink, unlike PrivateTmp on
    // failed service startup. Emit only the same redacted diagnostic fields.
    if (records.length <= 16) process.stderr.write(`DNS_VM_ADAPTER_FAILURE ${JSON.stringify(records.at(-1))}\n`);
    if (records.length > 16) records.shift();
    const body = Buffer.from(JSON.stringify(records)); assert.ok(body.length < 16384);
    fd ??= openSync('/tmp/dns-vm-adapter-failures.json', constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    assert.equal(writeSync(fd, body, 0, body.length, 0), body.length); ftruncateSync(fd, body.length);
  } catch { /* Diagnostics must not turn a DNS failure into an observer crash. */ }
});
process.once('exit', () => { if (fd !== undefined) closeSync(fd); });
