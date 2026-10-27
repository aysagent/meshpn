// The actual legacy revision observed on both physical hosts before updating.
// Pin an immutable reviewed baseline, not the moving origin/main branch.
import assert from 'node:assert/strict';
export const legacyTrialBaseline = 'ad6746a7fb3b1c58d7d137f20689035bd4ea1f1c';
export const legacyTrialPaths = ['scripts/clean-vpn.js', 'scripts/lib', 'native/boring_tls', 'native/tun_linux', 'package-lock.json'];
const tooling = new Set(['scripts/lib/dns-vm-image.mjs', 'scripts/lib/dns-vm-protocol.mjs', 'scripts/lib/vpn-host-boot-vm.mjs',
  'scripts/lib/http2-capture-compare.mjs', 'scripts/lib/http2-prefix-observer.mjs',
  // Colocated tests are not imported by legacy runtime. Keep the exception
  // explicit rather than allowing arbitrary .test modules or changing baseline.
  'scripts/lib/native-runtime-plan.test.mjs']);
export function validateLegacyTrialDiff(paths, beforePackage, afterPackage) {
  // None of these control/lab modules is imported by the reviewed legacy entry
  // or its dependencies. Changes to that entry/dependencies still fail closed.
  assert.ok(paths.every(p => /^scripts\/lib\/native-[a-z0-9-]+\.mjs$/.test(p) || tooling.has(p)), 'legacy_runtime_changed');
  const runtime = value => { const copy = structuredClone(value); delete copy.scripts; return copy; };
  assert.deepEqual(runtime(beforePackage), runtime(afterPackage), 'legacy_package_runtime_changed');
}
