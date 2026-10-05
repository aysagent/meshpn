/** Stable configuration fingerprint; never persist/print service arguments. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const check = ok => { if (!ok) throw Error('invalid_service_configuration_snapshot'); };

// D-Bus ExecStart is a(sasbttttuii). Only the first three fields describe
// configuration; timestamps, PID and exit result MUST NOT enter the hash.
// Structured parsing also avoids treating argv text as systemctl delimiters.
export function stableExecStart(property) {
  check(property?.type === 'a(sasbttttuii)' && Array.isArray(property.data) && property.data.length > 0);
  return property.data.map(row => {
    check(Array.isArray(row) && row.length === 10 && typeof row[0] === 'string' && row[0].startsWith('/')
      && Array.isArray(row[1]) && row[1].length > 0 && row[1].every(a => typeof a === 'string')
      && typeof row[2] === 'boolean' && row.slice(3).every(n => Number.isSafeInteger(n)));
    return { path: row[0], argv: row[1], ignoreFailure: row[2] };
  });
}

export async function trialServiceFingerprint({ run, root, readFile = fs.readFileSync }) {
  const unit = 'clean-vpn.service';
  const bus = (...args) => run('busctl', ['--system', '--json=short', ...args]);
  const object = JSON.parse(await bus('call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
    'org.freedesktop.systemd1.Manager', 'GetUnit', 's', unit));
  check(object.type === 'o' && Array.isArray(object.data) && object.data.length === 1
    && /^\/org\/freedesktop\/systemd1\/unit\/[a-zA-Z0-9_]+$/.test(object.data[0]));
  const exec = stableExecStart(JSON.parse(await bus('get-property', 'org.freedesktop.systemd1',
    object.data[0], 'org.freedesktop.systemd1.Service', 'ExecStart')));
  // Also compare unit/drop-in contents on disk: path-only comparison misses
  // an edit that has not been daemon-reloaded. Neither text nor argv is logged.
  const files = await run('systemctl', ['cat', '--no-pager', unit]);
  const effective = await run('systemctl', ['show', unit,
    '--property=FragmentPath,DropInPaths,Environment,EnvironmentFiles,User,Group,WorkingDirectory']);
  const reload = await run('systemctl', ['show', unit, '--property=NeedDaemonReload', '--value']);
  if (reload !== 'no') throw Error('legacy_unit_needs_daemon_reload');
  const hash = createHash('sha256');
  for (const part of [readFile('/usr/local/bin/clean-vpn-run.sh'), readFile(path.join(root, 'scripts/clean-vpn.js')),
    files, effective, JSON.stringify(exec)]) {
    const bytes = Buffer.from(part);
    hash.update(String(bytes.length) + ':').update(bytes);
  }
  return hash.digest('hex');
}
