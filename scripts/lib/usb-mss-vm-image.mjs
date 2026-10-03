/** Copy TCPMSS test dependencies into a disposable guest, never load on host. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

export function addUsbMssVmImage(init, put) {
  const releases = [...new Set([...init.matchAll(/^insmod \/lib\/modules\/([^/]+)\//gm)].map(m => m[1]))];
  assert.equal(releases.length, 1, 'one verified guest kernel release required');
  const release = releases[0]; assert.match(release, /^[A-Za-z0-9_.-]+$/);
  assert.ok(init.includes('cd /project\n'), 'known guest init required');
  const hashes = {}, loads = new Set();
  const copy = path => {
    const data = fs.readFileSync(path);
    put(path, data); hashes[path] = createHash('sha256').update(data).digest('hex');
  };
  for (const name of ['TCPMSS', 'length']) {
    copy(`/usr/lib/x86_64-linux-gnu/xtables/libxt_${name}.so`);
    const deps = execFileSync('modprobe', ['--set-version', release, '--show-depends', `xt_${name}`], { encoding: 'utf8', timeout: 10000 });
    assert.ok(deps.includes(`/xt_${name}.ko`), 'missing guest module');
    for (const [, path] of deps.matchAll(/^insmod (\/lib\/modules\/[^\s]+\.ko)\s*$/gm)) {
      assert.ok(path.startsWith(`/lib/modules/${release}/`));
      if (!init.includes(`insmod ${path}`)) { copy(path); loads.add(`insmod ${path}`); }
    }
  }
  return { init: init.replace('cd /project\n', [...loads, 'cd /project', ''].join('\n')), hashes };
}
