// Fixture persistence helper, not a production restore/adoption operation.
import fs from 'node:fs';
import assert from 'node:assert/strict';
export function copyVmTree(source, destination) {
  fs.cpSync(source, destination, { recursive: true, verbatimSymlinks: true });
  // cpSync preserves file modes, but newly made directories follow its own
  // defaults/umask. Durable replay requires an exactly private leaf directory.
  function modes(from, to) {
    const stat = fs.lstatSync(from);
    if (!stat.isDirectory()) return;
    assert.ok(fs.lstatSync(to).isDirectory());
    for (const name of fs.readdirSync(from)) modes(from + '/' + name, to + '/' + name);
    fs.chmodSync(to, stat.mode & 0o7777);
  }
  modes(source, destination);
}
