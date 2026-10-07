// Files/units only, no host commands. External link owner provides addresses
// and DHCP/default with interfaces initially DOWN; this bundle gates link UP.
import assert from 'node:assert/strict';
import { nativeNetworkPlan } from './native-network-profile.mjs';
import { nativeNetworkUnit } from './native-network-unit.mjs';
import { nativeRouteServiceUnit } from './native-route-unit.mjs';
import { nativeServiceUnit } from './native-service-unit.mjs';
export const nativeSiteSources = ['clean-vpn-native-network.mjs', 'clean-vpn-native-routes.mjs',
  'lib/native-network-apply.mjs', 'lib/native-network-profile.mjs', 'lib/native-route-service.mjs',
  'lib/vpn-host-routes.mjs', 'lib/dns-tunnel-command.mjs', 'lib/vpn-uplink-watch.mjs'];
export function nativeSitePlan({ name, target, site, engine, capability }) {
  assert.match(name, /^[a-z][a-z0-9-]{0,31}$/);
  assert.deepEqual(Object.keys(site).sort(), ['link_unit', 'profile']);
  nativeNetworkPlan(site.profile); const p = site.profile;
  assert.match(site.link_unit, /^[a-z][a-z0-9-]{0,63}\.service$/);
  assert.equal(engine.role, p.role); assert.equal(engine.tun, p.tun);
  assert.equal(engine.address, p.endpoint); assert.equal(engine.port, p.port);
  if (p.role === 'client') {
    assert.equal(engine.dns, true); assert.equal(capability.dns_socket_mark, '0x43564e');
    assert.equal(engine.peer_ipv4 ?? '10.99.0.2', p.tun_address.split('/')[0]);
  }
  const guard = `native-${name}-network.service`, gate = `native-${name}-uplink.service`, route = `native-${name}-routes.service`, unit = `native-${name}.service`, targetUnit = `native-${name}.target`;
  assert.ok(![guard, gate, route, unit].includes(site.link_unit), 'site_dependency_cycle');
  const script = target + '/control/clean-vpn-native-network.mjs', config = target + '/network.json';
  const units = new Map();
  units.set(guard, nativeNetworkUnit({ script, config, linkUnit: site.link_unit }));
  units.set(gate, nativeNetworkUnit({ script, config, linkUnit: guard }).replace(' --apply ', ' --activate-links '));
  const engineUnit = nativeServiceUnit({ binary: target + '/engine', config: target + '/config.json', networkUnit: p.role === 'client' ? route : gate, guardUnit: guard });
  // Activation belongs to the target/route coordinator, not an independent
  // WantedBy=multi-user.target entry for the client.
  units.set(unit, engineUnit.replace('\n[Install]\nWantedBy=multi-user.target\n', '\n'));
  const files = new Map([['network.json', JSON.stringify(p) + '\n']]);
  if (p.role === 'client') {
    const profile = { version: 1, tun: p.tun, uplink: p.uplink, exit_ip: p.endpoint, engine_unit: unit, guard_unit: guard, route_unit: route };
    files.set('routes.json', JSON.stringify(profile) + '\n');
    units.set(route, nativeRouteServiceUnit({ config: target + '/routes.json', script: target + '/control/clean-vpn-native-routes.mjs', profile, provisionUnit: gate }));
  }
  units.set(targetUnit, `[Unit]\nDescription=clean-vpn native site\nRequires=${p.role === 'client' ? route : unit}\nAfter=${guard} ${gate}\n\n[Install]\nWantedBy=multi-user.target\n`);
  for (const [name, body] of units) if (name !== targetUnit) units.set(name, body.replace('[Unit]\n', `[Unit]\nPartOf=${targetUnit}\n`));
  return { units, files, dependencies: [site.link_unit], activation: targetUnit, engineUnit: unit };
}
