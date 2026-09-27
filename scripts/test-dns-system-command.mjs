import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { assertDnsSystemCommands, createDnsSystemCommands, runLockedDnsCommand, inspectDnsSystemExecutable } from './lib/dns-system-command.mjs';

const moduleUrl = new URL('./lib/dns-system-command.mjs', import.meta.url).href;
const prelude = `import { runLockedDnsCommand } from ${JSON.stringify(moduleUrl)};
import { readFile, readdir } from 'node:fs/promises';
let lockFd;
for (const name of await readdir('/proc/self/fdinfo')) {
  try { if ((await readFile('/proc/self/fdinfo/'+name,'utf8')).includes('FLOCK')) lockFd=Number(name); }
  catch(e) { if(e.code!=='ENOENT') throw e; }
}
const run = (code, options={}) => runLockedDnsCommand(process.execPath, ['-e',code], {lockFd,...options});
`;
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-command-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const lock = join(dir, 'lock'); await writeFile(lock, '', { mode: 0o600 });
  const args = (js) => ['-n', '-E', '75', '-F', lock, process.execPath, '--input-type=module', '-e', prelude + js];
  return { dir, lock, args, run: (js) => runCommand('/usr/bin/flock', args(js), { timeoutMs: 15000 }) };
}
test('locked child receives only fixed environment and the inherited lock', async (t) => {
  const f = await fixture(t);
  const r = await f.run(`process.env.MESHPN_SECRET='must-not-escape';
console.log((await run('console.log(JSON.stringify({env:process.env,fd:require("fs").fstatSync(3).isFile()}))')).stdout);`);
  assert.equal(r.code, 0, r.stderr); const v = JSON.parse(r.stdout);
  assert.equal(v.fd, true); assert.equal(v.env.MESHPN_SECRET, undefined);
  assert.deepEqual(Object.keys(v.env).sort(), ['LANG','LC_ALL','PATH','SYSTEMD_COLORS','SYSTEMD_PAGER','SYSTEMD_PAGERSECURE']);
});
for (const [label, code, options, error] of [
  ['exit', 'console.error("PRIVATE-MARKER");process.exit(7)', {}, 'DNS_COMMAND_FAILED'],
  ['signal', 'process.kill(process.pid,"SIGTERM")', {}, 'DNS_COMMAND_FAILED'],
  ['timeout', 'setInterval(()=>{},1000)', { timeoutMs: 100 }, 'DNS_COMMAND_TIMEOUT'],
  ['stdout cap', 'process.stdout.write("x".repeat(4096))', { maxBytes: 32 }, 'DNS_COMMAND_OUTPUT'],
  ['stderr cap', 'process.stderr.write("x".repeat(4096))', { maxBytes: 32 }, 'DNS_COMMAND_OUTPUT'],
  ['encoding', 'process.stdout.write(Buffer.from([255]))', {}, 'DNS_COMMAND_ENCODING'],
]) test(`bounded command: ${label}`, async (t) => {
  const f = await fixture(t), r = await f.run(`try { await run(${JSON.stringify(code)},${JSON.stringify(options)}); process.exitCode=99; }
catch(e) { console.log(e.message); }`);
  assert.equal(r.code, 0, r.stderr); assert.equal(r.stdout.trim(), error); assert.equal(r.stderr, '');
});
test('spawn failure and abort are redacted and bounded', async (t) => {
  const f = await fixture(t), r = await f.run(`
try { await runLockedDnsCommand('/no-such-dns-command-PRIVATE-MARKER',[],{lockFd}); } catch(e) { console.log(e.message); }
const ac=new AbortController(); setTimeout(()=>ac.abort(),100);
try { await run('setInterval(()=>{},1000)',{signal:ac.signal}); } catch(e) { console.log(e.message); }`);
  assert.equal(r.code, 0, r.stderr); assert.equal(r.stdout, 'DNS_COMMAND_SPAWN\nDNS_COMMAND_ABORTED\n');
});
test('no lock, invalid argv, fake runner and absent authority are refused', async () => {
  for (const options of [{}, { lockFd: 0 }, { lockFd: 99999 }])
    await assert.rejects(runLockedDnsCommand(process.execPath, ['-e', 'process.exit(99)'], options), { code: 'DNS_COMMAND_REFUSED' });
  await assert.rejects(runLockedDnsCommand('node', [], {}), { code: 'DNS_COMMAND_REFUSED' });
  assert.throws(() => assertDnsSystemCommands({ run() {} }));
  let checked = false;
  await assert.rejects(createDnsSystemCommands({ assertAuthority: async () => { checked = true; throw new Error('NO_AUTHORITY'); } }), /NO_AUTHORITY/);
  assert.equal(checked, true);
});
test('read-only executable inventory refuses invalid spelling, untrusted files and fake authority', async (t) => {
  assert.throws(() => assertDnsSystemCommands({ actual: '/usr/bin/true', entries: [] }));
  for (const path of ['true', '.', '/usr/bin/../bin/true', '/usr//bin/true', null])
    await assert.rejects(inspectDnsSystemExecutable(path), /absolute normalized executable path required/);
  await assert.rejects(inspectDnsSystemExecutable('/'));
  const f = await fixture(t), path = join(f.dir, 'untrusted'); await writeFile(path, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  await assert.rejects(inspectDnsSystemExecutable(path));
});
test('a shared lock cannot authorize commands', async (t) => {
  const f = await fixture(t);
  const r = await runCommand('/usr/bin/flock', ['-s', ...f.args(`try { await run('process.exit(99)'); } catch(e) { console.log(e.code); }`)]);
  assert.equal(r.code, 0, r.stderr); assert.equal(r.stdout.trim(), 'DNS_COMMAND_REFUSED');
});
test('helper retains serialization after controller SIGKILL until helper exits', { timeout: 15000 }, async (t) => {
  const f = await fixture(t), marker = join(f.dir, 'ready'), done = join(f.dir, 'done');
  const childCode = `require('fs').writeFileSync(${JSON.stringify(marker)},String(process.pid));
setTimeout(()=>require('fs').writeFileSync(${JSON.stringify(done)},'done'),2000);`;
  const controller = spawn('/usr/bin/flock', f.args(`await run(${JSON.stringify(childCode)});`), { stdio: ['ignore','pipe','pipe'] });
  let stderr=''; controller.stderr.on('data', (b) => { stderr += b; });
  const closed = once(controller, 'close'); let helper;
  t.after(async () => { controller.kill('SIGKILL'); if(helper) { try { process.kill(helper,'SIGKILL'); } catch(e) { if(e.code!=='ESRCH') throw e; } } });
  const end = performance.now()+5000;
  for (;;) {
    try { helper=Number(await readFile(marker,'utf8')); break; }
    catch(e) { if(e.code!=='ENOENT') throw e; assert.ok(performance.now()<end, stderr); await delay(20); }
  }
  controller.kill('SIGKILL');
  assert.equal((await runCommand('/usr/bin/flock',['-n','-E','75',f.lock,'/usr/bin/true'])).code,75);
  await closed;
  for (;;) {
    const acquired = await runCommand('/usr/bin/flock',['-n','-E','75',f.lock,'/usr/bin/true']);
    if(acquired.code===0) break;
    assert.equal(acquired.code,75); assert.ok(performance.now()<end); await delay(20);
  }
  assert.equal(await readFile(done,'utf8'),'done'); helper=undefined;
});
