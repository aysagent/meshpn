import assert from 'node:assert/strict';
import { readFile, readlink } from 'node:fs/promises';
import { assertBrowserNamespace } from './browser-soak.mjs';

/** Refuse all namespace fixture mutations unless mount propagation is private. */
export async function assertDnsMountNamespace() {
  assertBrowserNamespace();
  assert.ok(process.env.MESHPN_PARENT_MNTNS, 'private mount namespace provenance required');
  assert.notEqual(await readlink('/proc/self/ns/mnt'), process.env.MESHPN_PARENT_MNTNS);
  const mounts = await readFile('/proc/self/mountinfo', 'utf8');
  assert.ok(!mounts.split('\n').some((line) => /\b(?:shared|master|propagate_from):/.test(line.split(' - ')[0])),
    'all mount propagation must already be private');
}
