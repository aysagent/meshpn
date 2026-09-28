import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { runTunnelDnsCommand } from './lib/dns-tunnel-command.mjs';
import { openTunnelDnsJournal } from './lib/dns-tunnel-journal.mjs';

test('command timeout kills a stuck helper and retains actionable signal/status diagnostics', () => {
  const start = performance.now();
  assert.throws(() => runTunnelDnsCommand(process.execPath, ['-e', 'process.on("SIGTERM",()=>{});setInterval(()=>{},1000)'],
    { timeoutMs: 100 }), e => e.code === 'ETIMEDOUT' && e.signal === 'SIGKILL' && /signal=SIGKILL/.test(e.message));
  assert.ok(performance.now() - start < 4000);
  assert.throws(() => runTunnelDnsCommand(process.execPath, ['-e', 'process.stderr.write("specific failure");process.exit(1)']),
    e => e.status === 1 && /specific failure/.test(e.message));
});

test('repeated foreground-group SIGINT does not kill an in-flight helper or lose its inherited lock', { timeout: 15000 }, async t => {
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'meshpn-dns-signal-'));
  const marker = join(directory, 'helper-ready');
  const helper = `require('node:fs').writeFileSync(${JSON.stringify(marker)},String(process.pid));setTimeout(()=>console.log('HELPER_DONE'),1200)`;
  const code = `
    import {openTunnelDnsJournal} from './scripts/lib/dns-tunnel-journal.mjs';
    import {runTunnelDnsCommand} from './scripts/lib/dns-tunnel-command.mjs';
    const j=openTunnelDnsJournal(${JSON.stringify(join(directory, 'journal'))},{coordinate:false});
    let stopping=false; const keep=setInterval(()=>{},1000);
    process.on('SIGINT',()=>{if(stopping)return;stopping=true;
      try {console.log(runTunnelDnsCommand(process.execPath,['-e',${JSON.stringify(helper)}],{lockDescriptors:j.lockDescriptors,timeoutMs:5000}));}
      finally{j.release();clearInterval(keep);}});
    console.log('READY');
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const ended = once(child, 'close'); let output = '', error = '', helperPid;
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
    if (helperPid) { try { process.kill(helperPid, 'SIGKILL'); } catch {} }
    await ended; await rm(directory, { recursive: true, force: true });
  });
  child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { error += b; });
  const waitFor = async fn => {
    const deadline = performance.now() + 6000;
    while (!(await fn())) { assert.ok(performance.now() < deadline, error || output); await delay(10); }
  };
  await waitFor(() => output.includes('READY')); process.kill(-child.pid, 'SIGINT');
  await waitFor(async () => { try { helperPid = Number(await readFile(marker, 'utf8')); return true; } catch (e) { if (e.code !== 'ENOENT') throw e; return false; } });
  assert.throws(() => openTunnelDnsJournal(join(directory, 'journal'), { coordinate: false }), /locked/);
  // This is the group delivery used by a terminal, not child.kill(SIGINT).
  process.kill(-child.pid, 'SIGINT'); await delay(30); process.kill(-child.pid, 'SIGINT');
  const [status, signal] = await ended;
  helperPid = undefined; // helper was synchronously reaped; do not signal a recycled PID
  assert.equal(status, 0, error); assert.equal(signal, null); assert.match(output, /HELPER_DONE/);
  openTunnelDnsJournal(join(directory, 'journal'), { coordinate: false }).release();
});
