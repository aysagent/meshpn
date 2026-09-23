/** Process lifecycle regressions without launching a real browser. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { readFile } from 'node:fs/promises';
import { child } from './lib/browser-lab-driver.mjs';

assert.equal(process.platform, 'linux', 'process ownership checks require Linux /proc');

async function running(pid) {
  try {
    // A zombie has stopped executing; its reaping belongs to the host's PID 1.
    const stat = await readFile(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2, stat.lastIndexOf(')') + 3) !== 'Z';
  } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

test('test process owner stops and can be stopped again', { timeout: 8000 }, async (t) => {
  const proc = child(process.execPath, ['-e', 'console.log("READY"); setInterval(() => {}, 1000);']);
  t.after(() => proc.stop());
  await proc.waitFor(/READY/); await proc.stop(); await proc.stop();
  assert.equal(await running(proc.proc.pid), false);
});

for (const pipes of ['ignore', 'inherit']) test(`owner exit kills a TERM-resistant descendant (stdio=${pipes})`, { timeout: 8000 }, async (t) => {
  const source = `
    const {spawn} = require('node:child_process');
    const p = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000); process.send("ready");'],
      {stdio: ['ignore', '${pipes}', '${pipes}', 'ipc']});
    p.once('message', () => console.log('READY ' + p.pid));
    process.on('SIGTERM', () => process.exit(0));
  `;
  const proc = child(process.execPath, ['-e', source]);
  let descendant;
  t.after(async () => {
    await proc.stop();
    if (descendant && await running(descendant)) process.kill(descendant, 'SIGKILL');
  });
  descendant = Number((await proc.waitFor(/READY (\d+)/))[1]);
  assert.equal(await running(descendant), true);
  await proc.stop();
  for (let i = 0; i < 100 && await running(descendant); i++) await delay(10);
  assert.equal(await running(descendant), false, 'surviving child process after owner close');
});
