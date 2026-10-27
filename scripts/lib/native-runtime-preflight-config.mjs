import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
import { runtimePlan } from './native-runtime-plan.mjs';

// Inventory may inspect an existing host without claiming the isolated runtime
// owns its TUN, routing or DNS. The engine remains the full config validator.
export function validatePreflightConfig(config, scope = 'isolated-runtime') {
  assert.ok(['isolated-runtime', 'existing-host'].includes(scope), 'invalid_preflight_scope');
  if (scope === 'isolated-runtime') return runtimePlan(config);
  assert.equal(config?.version, 1, 'native_config_version_required');
  assert.ok(['client', 'exit'].includes(config.role), 'native_role_required');
  assert.equal(config.transport, undefined, 'boring_tls_config_required');
  assert.match(config.tun, /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/, 'invalid_tun_name');
  assert.ok(isIPv4(config.address), 'ipv4_endpoint_required');
  assert.ok(Number.isInteger(config.port) && config.port > 0 && config.port <= 65535, 'invalid_port');
  return null;
}
