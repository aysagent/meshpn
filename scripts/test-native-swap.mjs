import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const script = new URL('./clean-vpn-native-swap.sh', import.meta.url);
test('native build swap exposes only explicit on/off and validates as shell', () => {
  assert.equal(spawnSync('bash', ['-n', script.pathname]).status, 0);
  const help = spawnSync('bash', [script.pathname, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0); assert.match(help.stdout, /on\|off/); assert.match(help.stdout, /never edits \/etc\/fstab/);
  for (const args of [[], ['status'], ['on', 'off']]) {
    const result = spawnSync('bash', [script.pathname, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 2); assert.match(result.stderr, /Usage:/);
  }
});

test('native build swap has a dedicated owned path and no persistent activation', () => {
  const source = readFileSync(script, 'utf8');
  assert.match(source, /cv_swap_dir=\/var\/lib\/clean-vpn-native-build-swap/);
  assert.match(source, /fallocate -l 2G/); assert.match(source, /mkswap --label clean-vpn-native-build/);
  assert.match(source, /stat -c '%u:%g:%a'/); assert.match(source, /cv_marker_value=clean-vpn-native-build-swap-v1/);
  assert.match(source, /if cv_active; then swapoff/);
  assert.doesNotMatch(source, /(?:>|tee\s+).*\/etc\/fstab/);
  assert.doesNotMatch(source, /^cv_swap_file=\/swapfile$/m);
});
