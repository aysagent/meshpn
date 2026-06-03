import { execFileSync } from 'child_process';
import { IP_CLIENT, IP_EXIT, TUN_MTU } from './constants.mjs';

function runQuiet(args) {
  return execFileSync(args[0], args.slice(1), { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function waitForInterface(ifname, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      execFileSync('ifconfig', [ifname], { stdio: ['ignore', 'ignore', 'ignore'] });
      return;
    } catch {
      const t0 = Date.now();
      while (Date.now() - t0 < 25) {
        /* spin */
      }
    }
  }
  throw new Error(`interface ${ifname} not ready for ifconfig`);
}

export function findFreeUtunName() {
  try {
    const out = runQuiet(['ifconfig', '-l']);
    const names = out.trim().split(/\s+/);
    const used = new Set();
    for (const n of names) {
      const m = /^utun(\d+)$/.exec(n);
      if (m) used.add(parseInt(m[1], 10));
    }
    let i = 0;
    while (used.has(i)) i += 1;
    return `utun${i}`;
  } catch {
    return 'utun0';
  }
}

/**
 * @param {'exit'|'client'} role
 * @param {string} ifname
 */
export function setupTunIpDarwin(role, ifname) {
  const local = role === 'exit' ? IP_EXIT : IP_CLIENT;
  const remote = role === 'exit' ? IP_CLIENT : IP_EXIT;

  waitForInterface(ifname);

  try {
    execFileSync('ifconfig', [ifname, 'down'], { stdio: 'ignore' });
  } catch {
    /* ignore */
  }

  execFileSync(
    'ifconfig',
    [ifname, local, remote, 'netmask', '255.255.255.255', 'mtu', String(TUN_MTU), 'up'],
    { stdio: 'inherit' },
  );

  try {
    execFileSync('route', ['delete', '-host', remote], { stdio: 'ignore' });
  } catch {
    /* ignore */
  }
  try {
    execFileSync('route', ['add', '-host', remote, '-interface', ifname], { stdio: 'inherit' });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (!/File exists/i.test(msg)) throw e;
  }
}

export function teardownUtunDarwin(ifname) {
  if (!ifname || !/^utun\d+$/.test(ifname)) return;
  try {
    execFileSync('ifconfig', [ifname, 'down'], { stdio: 'ignore' });
  } catch {
    /* ignore */
  }
}

export function getDefaultRouteDarwin() {
  try {
    const out = runQuiet(['route', '-n', 'get', 'default']);
    const iface = out.match(/interface:\s*(\S+)/);
    const gw = out.match(/gateway:\s*(\S+)/);
    if (iface) {
      return { gw: gw?.[1] ?? null, dev: iface[1] };
    }
  } catch {
    /* ignore */
  }
  return null;
}

export function defaultLoopbackExtDarwin() {
  return 'lo0';
}
