#!/usr/bin/env node
// Linux orchestrator: start the detached Mac job, wait for the restored tunnel,
// copy the report directory locally, then print file paths only.
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { command, parseArgs, quote } from './perf-lib.mjs';
import { inMacRepo, macUser, sshMacArgs } from './remote-mac.mjs';
import { collect } from './remote-collect.mjs';
import { validateJobId } from './perf-ap-managed.mjs';

export async function main(args = process.argv.slice(2), {run = command, collectJob = collect,
  announce = message => console.error(message)} = {}) {
  if (!args.length) throw Error('Usage: npm run device:remote:ap-test -- [user@]SERVER[:port] [--ap-tcp-paced|--ap-tcp-up] [options]');
  const testArgs = [...args];
  if (!testArgs.includes('--ap-tcp-paced') && !testArgs.includes('--ap-tcp-up')) testArgs.push('--ap-tcp-paced');
  const options = parseArgs(testArgs);
  if (options.paths !== 'ap' || options.help || testArgs.includes('--out')) throw Error('AP TCP preset required; --out is managed automatically');
  const user = macUser();
  const remote = inMacRepo(['npm', 'run', '--silent', 'device:perf:ap-managed', '--', ...testArgs].map(quote).join(' '));
  const launched = await run('ssh', [...sshMacArgs(user), remote], {timeout: 120000});
  if (launched.code !== 0) throw Error(`Could not launch Mac AP job: ${launched.stderr.trim()}`);
  const id = validateJobId(launched.stdout.trim());
  announce(`Mac AP job ${id} started; waiting for report and reverse tunnel...`);
  const waitMinutes = Number(process.env.MESHPN_REMOTE_COLLECT_WAIT_MINUTES || 360);
  if (!Number.isInteger(waitMinutes) || waitMinutes < 1 || waitMinutes > 720) throw Error('Invalid MESHPN_REMOTE_COLLECT_WAIT_MINUTES');
  await collectJob(id, user, waitMinutes);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {console.error(error.message); process.exitCode = 1;});
}
