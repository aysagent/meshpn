#!/usr/bin/env node
// Server-side collector. Copies files over the restored reverse SSH tunnel;
// stdout contains paths only, never report/log contents.
import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { command, quote } from './perf-lib.mjs';
import { macJobDir, macJobParent, macUser, sshMacArgs } from './remote-mac.mjs';
import { validateJobId } from './perf-ap-managed.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const parent = path.join(root, 'device/perf-remote-results');

export function validateCollectedState(id, state) {
  if (state?.id !== id || !['completed', 'failed', 'interrupted'].includes(state.phase))
    throw Error('Remote job has not finished or state ID mismatches');
  if (state.report && (!/^perf\/[A-Za-z0-9._-]+\/report\.md$/.test(state.report) || state.report.includes('..')))
    throw Error('Unsafe report path in remote state');
  return state;
}
async function remoteState(id, user) {
  const file = `${macJobDir(id)}/state.json`;
  const result = await command('ssh', [...sshMacArgs(user), `cat -- ${file}`], {timeout: 12000});
  if (result.code !== 0) return null;
  try { return JSON.parse(result.stdout); } catch { return null; }
}
async function waitForFinal(id, user, timeoutMs) {
  const until = Date.now() + timeoutMs;
  let terminalSince = null;
  while (Date.now() < until) {
    const state = await remoteState(id, user).catch(() => null);
    if (state && ['completed', 'failed', 'interrupted'].includes(state.phase)) {
      validateCollectedState(id, state);
      if (state.restored) return state;
      terminalSince ??= Date.now();
      // Give the crash watchdog time to finish. If restoration cannot be
      // confirmed but the tunnel is reachable, keep the diagnostic files.
      if (Date.now() - terminalSince >= 120000) return state;
    }
    await delay(5000);
  }
  throw Error(`Timed out waiting for Mac tunnel/job ${id}; job remains on Mac and can be collected later`);
}
export function copyTar(id, user, staging, {start = spawn} = {}) {
  return new Promise((resolve, reject) => {
    const remote = `tar -C ${macJobParent()} -cf - ${quote(id)}`;
    const ssh = start('ssh', [...sshMacArgs(user), remote], {stdio: ['ignore', 'pipe', 'pipe']});
    const tar = start('tar', ['-xf', '-', '-C', staging], {stdio: ['pipe', 'ignore', 'pipe']});
    let sshCode, tarCode, stderr = '', finished = false;
    const fail = error => { if (finished) return; finished = true; ssh.kill(); tar.kill(); reject(error); };
    const timer = setTimeout(() => fail(Error('Remote archive transfer exceeded 10 minutes')), 600000);
    timer.unref();
    ssh.stdout.pipe(tar.stdin);
    tar.stdin.on('error', () => {});
    ssh.stderr.on('data', b => {stderr = (stderr + b).slice(-4096);});
    tar.stderr.on('data', b => {stderr = (stderr + b).slice(-4096);});
    ssh.on('error', fail); tar.on('error', fail);
    const check = () => {
      if (sshCode === undefined || tarCode === undefined || finished) return;
      clearTimeout(timer); finished = true;
      if (sshCode === 0 && tarCode === 0) resolve();
      else reject(Error(`Remote archive failed (ssh=${sshCode}, tar=${tarCode}): ${stderr.trim()}`));
    };
    ssh.on('close', code => {sshCode = code; check();});
    tar.on('close', code => {tarCode = code; check();});
  });
}
async function fileExists(file) { try {await access(file); return true;} catch {return false;} }
async function pathsFor(id, dir) {
  const state = validateCollectedState(id, JSON.parse(await readFile(path.join(dir, 'state.json'), 'utf8')));
  const watchdog = JSON.parse(await readFile(path.join(dir, 'watchdog.json'), 'utf8').catch(() => 'null'));
  state.restored = Boolean(state.restored || watchdog?.restored);
  const report = state.report ? path.join(dir, state.report) : null;
  const result = report ? path.join(path.dirname(report), 'result.json') : null;
  if (report && (!await fileExists(report) || !await fileExists(result)))
    throw Error('Collected report/result is incomplete');
  return {state, report, result};
}
export async function collect(id, user, waitMinutes) {
  const dest = path.join(parent, id);
  await mkdir(parent, {recursive: true});
  if (!await fileExists(dest)) {
    await waitForFinal(id, user, waitMinutes * 60000);
    const staging = await mkdtemp(path.join(parent, '.incoming-'));
    try {
      await copyTar(id, user, staging);
      await pathsFor(id, path.join(staging, id));
      await rename(path.join(staging, id), dest);
    } finally { await rm(staging, {recursive: true, force: true}); }
  }
  const {state, report, result} = await pathsFor(id, dest);
  console.log(`job: ${id}`);
  const outcome = state.phase === 'completed' && state.runner_exit_code === 2 ? 'completed-with-warnings' : state.phase;
  console.log(`status: ${outcome}${state.restored ? ' (Wi-Fi restored)' : ' (Wi-Fi restore not confirmed)'}`);
  console.log(`files: ${dest}`);
  console.log(`report: ${report || 'none'}`);
  console.log(`result: ${result || 'none'}`);
  console.log(`worker log: ${path.join(dest, 'worker.log')}`);
  if (state.error) console.log('error: see state.json and worker.log');
  if (!state.restored) process.exitCode = 2;
  if (state.phase !== 'completed') process.exitCode = 1;
  else if (state.runner_exit_code === 2) process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [rawId, userArg] = process.argv.slice(2);
  try {
    const id = validateJobId(rawId || '');
    const user = macUser(userArg);
    const waitMinutes = Number(process.env.MESHPN_REMOTE_COLLECT_WAIT_MINUTES || 360);
    if (!Number.isInteger(waitMinutes) || waitMinutes < 1 || waitMinutes > 720) throw Error('Invalid MESHPN_REMOTE_COLLECT_WAIT_MINUTES');
    collect(id, user, waitMinutes).catch(error => {console.error(error.message); process.exitCode = 1;});
  } catch (error) {console.error(error.message); process.exitCode = 2;}
}
