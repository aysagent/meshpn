#!/usr/bin/env node
// Explicit native service network coordinator. Retains routes/guard on stop.
import fs from 'node:fs';
import { openHostRoutes } from './lib/vpn-host-routes.mjs';
import { runTunnelDnsCommand } from './lib/dns-tunnel-command.mjs';
import { subscribeUplinkEvents } from './lib/vpn-uplink-watch.mjs';
import { nativeRouteCoordinator, validateNativeRouteConfig } from './lib/native-route-service.mjs';
let routes, coordinator, timer, unsubscribe, stopping = false, last = '';
try {
  if (process.getuid() !== 0 || process.argv.length !== 3 || !/^--config=\/[\w./-]+$/.test(process.argv[2])) throw Error();
  const path = process.argv[2].slice(9);
  if (fs.realpathSync(path) !== path) throw Error();
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let config;
  try {
    const s = fs.fstatSync(fd);
    if (!s.isFile() || s.uid !== 0 || (s.mode & 0o077) || s.size > 4096) throw Error();
    config = validateNativeRouteConfig(JSON.parse(fs.readFileSync(fd)));
  } finally { fs.closeSync(fd); }
  // The named dependency must actually be this running service, not an unrelated
  // active unit. A manual invocation cannot claim its crash/BindsTo protection.
  if (runTunnelDnsCommand('systemctl', ['show', config.route_unit, '-p', 'MainPID', '--value'], { timeoutMs: 5000 }) !== String(process.pid)) throw Error();
  const ns = fs.readlinkSync('/proc/self/ns/net').match(/^net:\[(\d+)\]$/)?.[1]; if (!ns) throw Error();
  routes = openHostRoutes({ directory: '/run/clean-vpn-native-routes-' + ns, allowTunLinkDown: true });
  coordinator = nativeRouteCoordinator(config, routes, (file, args) =>
    runTunnelDnsCommand(file, args, { lockDescriptors: routes.lockDescriptors, timeoutMs: 15000 }));
  const tick = () => {
    if (stopping) return;
    try { const status = coordinator.tick(); const line = JSON.stringify(status);
      if (line !== last) { last = line; console.log(line); }
    } catch { finish(1); }
  };
  const finish = code => {
    if (stopping) return; stopping = true; clearInterval(timer); unsubscribe?.();
    try { coordinator?.close(); } catch { code = 1; }
    routes?.release(); process.exitCode = code;
  };
  timer = setInterval(tick, 10000);
  unsubscribe = subscribeUplinkEvents(tick, () => { clearInterval(timer); timer = setInterval(tick, 1000); tick(); });
  process.on('SIGTERM', () => finish(0)); process.on('SIGINT', () => finish(0));
  tick();
} catch {
  routes?.release(); console.error('native-routes: refused; journal and protection retained'); process.exitCode = 1;
}
