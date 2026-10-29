// Exit-only facade. All paths/service identities come from the trusted broker
// configuration; HTTP callers supply client names, never paths or unit names.
import { NativeClientManager, clientName } from '../../scripts/lib/native-client-manager.mjs';
import { nativeClientService } from '../../scripts/lib/native-client-service.mjs';
import { need } from './common.mjs';

export function publicClientList(result) {
  need(result?.version === 1 && Number.isSafeInteger(result.revision) && Array.isArray(result.clients), 'clients_result');
  return { version: 1, revision: result.revision, zone: 'mpn', clients: result.clients.map(c => {
    need(clientName(c.name) && /^10\.99\.0\.[0-9]{1,3}$/.test(c.ipv4) && typeof c.revoked === 'boolean', 'clients_result');
    return { name: c.name, hostname: c.name + '.mpn', ipv4: c.ipv4, revoked: c.revoked,
      connectionState: ['connected', 'disconnected'].includes(c.connectionState) ? c.connectionState : 'unknown' };
  }), ...(typeof result.applied === 'boolean' ? { applied: result.applied } : {}),
  ...(typeof result.requiresReload === 'boolean' ? { requiresReload: result.requiresReload } : {}) };
}

export function createClientAdministration(c, { run }) {
  const service = nativeClientService({ engine: c.engine, unit: c.vpnUnit, directory: c.clientsDirectory, run: async (...args) => (await run(...args)).out });
  const manager = new NativeClientManager({ directory: c.clientsDirectory, ...service });
  const binding = () => need(manager.load().configPath === c.vpnConfig, 'clients_exit_binding', 409);
  return {
    async list() { binding(); return publicClientList(await manager.list()); },
    async add(name) { binding(); await service.preflight(); return publicClientList(await manager.add(name)); },
    async rename(name, newName) { binding(); await service.preflight(); return publicClientList(await manager.rename(name, newName)); },
    async rotate(name) { binding(); await service.preflight(); return publicClientList(await manager.rotate(name)); },
    async revoke(name) { binding(); await service.preflight(); return publicClientList(await manager.revoke(name)); },
    async export(name) { binding(); return manager.export(name); },
  };
}
