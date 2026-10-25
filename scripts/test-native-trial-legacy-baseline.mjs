import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { legacyTrialBaseline, legacyTrialPaths, validateLegacyTrialDiff } from './lib/native-trial-legacy-baseline.mjs';

test('legacy baseline permits control scripts but rejects entry/dependency/runtime changes', () => {
  const p = { type: 'module', dependencies: { ws: '1' }, scripts: { old: 'x' } };
  validateLegacyTrialDiff(['scripts/lib/native-usb-trial-peer.mjs'], p, { ...p, scripts: { new: 'y' } });
  for (const file of ['scripts/clean-vpn.js', 'scripts/lib/vpn-host-routes.mjs', 'scripts/lib/dns-tunnel-runtime.mjs',
    'native/boring_tls/helper.cc', 'package-lock.json', 'scripts/lib/unknown.mjs'])
    assert.throws(() => validateLegacyTrialDiff([file], p, p), /legacy_runtime_changed/);
  assert.throws(() => validateLegacyTrialDiff([], p, { ...p, dependencies: { ws: '2' } }), /legacy_package_runtime_changed/);
});
test('checked-in checkout retains the reviewed physical legacy runtime', () => {
  const run = args => execFileSync('git', args, { encoding: 'utf8' }).trim();
  validateLegacyTrialDiff(run(['diff', '--name-only', legacyTrialBaseline, '--', ...legacyTrialPaths]).split('\n').filter(Boolean),
    JSON.parse(run(['show', `${legacyTrialBaseline}:package.json`])), JSON.parse(fs.readFileSync('package.json')));
});
