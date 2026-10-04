/** Isolated USB soak. Never invoked against the host or a physical device. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { startSocketObserver } from './usb-socket-observer.mjs';

function guard() {
  assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.usb-soak=1(?:\s|$)/);
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  assert.equal(process.getuid(), 0);
}
const append = (path, row) => fs.appendFileSync(path, JSON.stringify(row) + '\n');
const exitIp = '154.62.226.216', script = '/project/scripts/lib/usb-e2e-vm.mjs';

export async function startLongTcpOrigin() {
  guard(); let connection = 0;
  const server = net.createServer(socket => {
    const id = ++connection, peer = socket.remoteAddress; let data = '';
    socket.setNoDelay(); socket.on('error', () => {});
    append('/run/e2e-long-hits', { connection: id, peer });
    socket.on('data', b => {
      data += b; if (data.length > 4096) return socket.destroy();
      for (;;) {
        const n = data.indexOf('\n'); if (n < 0) break;
        const line = data.slice(0, n); data = data.slice(n + 1);
        if (!/^\d+$/.test(line)) return socket.destroy();
        socket.write(JSON.stringify({ connection: id, peer, sequence: Number(line) }) + '\n');
      }
    });
  });
  server.listen(38473, '1.0.0.1'); await once(server, 'listening');
}

export async function runLongTcpPeer() {
  guard(); let attempt = 0;
  while (!fs.existsSync('/run/e2e-monitor-stop')) {
    const current = ++attempt;
    await new Promise(resolve => {
      const socket = net.createConnection({ host: '1.0.0.1', port: 38473 });
      let receivedAt = performance.now(), data = '', sequence = 0;
      socket.setNoDelay(); socket.on('error', () => {});
      const timer = setInterval(() => {
        if (fs.existsSync('/run/e2e-monitor-stop') || performance.now() - receivedAt > 6000) return socket.destroy();
        if (!socket.connecting && !socket.destroyed) socket.write(`${++sequence}\n`);
      }, 1000);
      socket.on('data', b => {
        data += b; if (data.length > 4096) return socket.destroy();
        for (;;) {
          const n = data.indexOf('\n'); if (n < 0) break;
          const line = data.slice(0, n); data = data.slice(n + 1);
          try {
            const r = JSON.parse(line); assert.ok(Number.isInteger(r.sequence) && r.sequence > 0 && r.sequence <= sequence);
            append('/run/e2e-long-results', { ...r, attempt: current, monotonicMs: performance.now() });
            receivedAt = performance.now();
          } catch { socket.destroy(); }
        }
      });
      socket.on('close', () => { clearInterval(timer); resolve(); });
    });
    await delay(500);
  }
}

export async function runUsbSoak(c) {
  guard();
  const { check, ctl, property, sync, ip, at, link, until, ready, matrix, login, hits } = c;
  const diagnostics = /(?:^|\s)meshpn.usb-diagnostics=1(?:\s|$)/.test(fs.readFileSync('/proc/cmdline', 'utf8'));
  const event = row => c.event(diagnostics ? { ...row, observedMonotonicMs: performance.now() } : row);
  const stopObserver = diagnostics ? startSocketObserver(c.event) : async () => {};
  const started = performance.now(), unit = 'clean-vpn.service';
  const identity = async () => ({ pid: await property(unit, 'MainPID'), restarts: await property(unit, 'NRestarts'),
    networkd: await property('systemd-networkd.service', 'MainPID'),
    guard: await property('clean-vpn-killswitch.service', 'ActiveEnterTimestampMonotonic'),
    rescue: await property('clean-vpn-usb-rescue.socket', 'ActiveEnterTimestampMonotonic') });
  const initialIdentity = await identity();
  const offsets = Object.fromEntries(['http', 'raw', 'dns'].map(k => [k, hits(`/run/e2e-${k}-hits`).length]));
  const children = ['fault-monitor', 'long-tcp'].map(mode => spawn('/usr/bin/ip', ['netns', 'exec', 'peer', '/usr/bin/node', script, mode], { stdio: ['ignore', 'ignore', 'inherit'] }));
  const endings = children.map(child => once(child, 'close'));
  const resources = label => {
    const pid = initialIdentity.pid, status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const ruleText = ['iptables', 'ip6tables'].flatMap(tool => ['filter', 'nat', 'mangle', 'raw'].map(table => sync(tool, ['-w', '5', '-t', table, '-S']))).join('\n');
    const hostDir = fs.readdirSync('/run').find(n => /^clean-vpn-host-routes-\d+$/.test(n));
    assert.ok(hostDir); const journal = JSON.parse(fs.readFileSync(`/run/${hostDir}/journal.json`));
    const value = name => Number(new RegExp(`^${name}:\\s+(\\d+)`, 'm').exec(status)?.[1]);
    const row = { label, rssKiB: value('VmRSS'), threads: value('Threads'), fds: fs.readdirSync(`/proc/${pid}/fd`).length,
      rulesHash: createHash('sha256').update(ruleText).digest('hex'), ruleLines: ruleText.split('\n').length,
      ownedRoutes: journal.routes.length, journalStage: journal.stage,
      conntrackCount: Number(fs.readFileSync('/proc/sys/net/netfilter/nf_conntrack_count', 'utf8')) };
    row.nodeMemory = JSON.parse(fs.readFileSync(`/run/e2e-memory-${pid}.json`, 'utf8'));
    assert.equal(row.nodeMemory.pid, Number(pid));
    assert.ok(Number.isFinite(row.rssKiB) && row.rssKiB > 0 && Number.isFinite(row.threads));
    event({ event: 'resources', phase: 0, ...row }); return row;
  };
  const noBypass = label => {
    for (const kind of ['http', 'raw', 'dns']) {
      const records = hits(`/run/e2e-${kind}-hits`).slice(offsets[kind]);
      const unexpected = records.filter(h => h.peer !== exitIp || ['192.168.1.1', 'fd00:1::1'].includes(h.host));
      if (unexpected.length) event({ event: 'diagnostic', phase: 0, label, kind, samples: unexpected.slice(0, 8) });
      check(`${label} ${kind} receiver audit`, records.length > 0 && !unexpected.length);
    }
    check(label + ' long TCP receiver audit', hits('/run/e2e-long-hits').length > 0 && hits('/run/e2e-long-hits').every(h => h.peer === exitIp));
  };
  let baseline;
  const stable = async label => {
    const offset = hits('/run/e2e-long-results').length;
    await until(() => hits('/run/e2e-long-results').length > offset, label + ' long TCP ready');
    const first = hits('/run/e2e-long-results').at(-1), start = performance.now();
    await delay(65000);
    const rows = hits('/run/e2e-long-results').filter(r => r.attempt === first.attempt && r.monotonicMs >= first.monotonicMs);
    const last = hits('/run/e2e-long-results').at(-1);
    check(label + ' long TCP survives healthy minute', rows.length >= 50 && last.attempt === first.attempt
      && last.monotonicMs - first.monotonicMs >= 60000 && rows.every(r => r.peer === exitIp && r.connection === first.connection)
      && rows.every((r, i) => !i || r.sequence === rows[i - 1].sequence + 1));
    event({ event: 'stable', phase: 0, label, elapsedMs: performance.now() - start, connection: first.connection, samples: rows.length });
    check(label + ' process and protection identities unchanged', await identity(), initialIdentity);
    check(label + ' SSH 22', await login('22')); check(label + ' SSH 2222', await login());
    noBypass(label);
    const row = resources(label);
    baseline ??= row;
    check(label + ' no rule or journal accumulation', [row.rulesHash, row.ruleLines, row.ownedRoutes, row.journalStage],
      [baseline.rulesHash, baseline.ruleLines, baseline.ownedRoutes, 'active']);
    // Bounded growth alarm, not a mathematical proof of memory-leak freedom.
    check(label + ' bounded process resources', row.fds <= baseline.fds + 16 && row.threads <= baseline.threads + 2 && row.rssKiB <= baseline.rssKiB + 65536);
  };
  try {
    await stable('baseline');
    for (let cycle = 1; cycle <= 3; cycle++) for (const scenario of ['exit-blackhole', 'carrier-dhcp']) {
      const label = `${cycle}-${scenario}`, before = hits('/run/e2e-monitor-results').length, start = performance.now();
      event({ event: 'soak-fault', phase: 0, cycle, scenario, action: 'begin' });
      if (scenario === 'exit-blackhole') {
        for (const direction of ['-s', '-d']) at('router', 'iptables', '-I', 'FORWARD', '1', direction, exitIp, '-j', 'DROP');
      } else {
        at('router', 'ip', 'link', 'set', 'client0', 'down');
        await until(() => !link().flags.includes('LOWER_UP') && !ip('-4', 'route', 'show', 'default'), 'carrier default withdrawal');
        check(label + ' bypass withdrawn', !ip('-4', 'route', 'show', exitIp + '/32'));
        fs.writeFileSync('/run/e2e-dhcp-next', `192.168.1.${10 + cycle}`);
        await until(() => fs.existsSync('/run/e2e-dhcp-ack') && fs.readFileSync('/run/e2e-dhcp-ack', 'utf8') === `192.168.1.${10 + cycle}`, 'DHCP server changed');
      }
      await matrix(false);
      check(label + ' SSH during outage', await login('22') && await login());
      await delay(Math.max(0, 120000 - (performance.now() - start)));
      check(label + ' monitor sees outage', hits('/run/e2e-monitor-results').slice(before).some(r => !r.ok));
      noBypass(label);
      event({ event: 'soak-fault', phase: 0, cycle, scenario, action: 'restore', elapsedMs: performance.now() - start });
      if (scenario === 'exit-blackhole') {
        for (const direction of ['-s', '-d']) at('router', 'iptables', '-D', 'FORWARD', direction, exitIp, '-j', 'DROP');
      } else {
        at('router', 'ip', 'link', 'set', 'client0', 'up');
        for (const address of ['2001:db8:1::1/64', 'fd00:1::1/64']) at('router', 'ip', '-6', 'addr', 'replace', address, 'dev', 'client0', 'nodad');
        for (const subnet of ['2001:db8:7::/64', 'fd00:7::/64']) at('router', 'ip', '-6', 'route', 'replace', subnet, 'via', 'fe80::ff:fe00:102', 'dev', 'client0');
        at('router', 'ip', '-6', 'neigh', 'replace', 'fe80::ff:fe00:102', 'lladdr', '02:00:00:00:01:02', 'nud', 'permanent', 'dev', 'client0');
        const address = `192.168.1.${10 + cycle}`;
        await until(() => link().addr_info.some(a => a.local === address && a.dynamic), 'new DHCP lease');
        check(label + ' new DHCP address', link().addr_info.filter(a => a.family === 'inet').map(a => a.local), [address]);
        event({ event: 'dhcp', phase: 0, cycle, address });
      }
      const recoveryStart = performance.now(); await ready();
      check(label + ' exit bypass repaired', JSON.parse(ip('-j', '-4', 'route', 'get', exitIp))[0].dev, 'wlan0');
      event({ event: 'soak-fault', phase: 0, cycle, scenario, action: 'recovered', recoveryMs: performance.now() - recoveryStart });
      await stable(label + '-recovered');
    }
    await matrix(true); noBypass('final');
    fs.writeFileSync('/run/e2e-monitor-stop', 'yes');
    const end = await Promise.race([Promise.all(endings), delay(15000).then(() => { throw Error('soak workers stop deadline'); })]);
    check('soak workers exit cleanly', end, [[0, null], [0, null]]);
    check('soak final fresh traffic succeeds', hits('/run/e2e-monitor-results').slice(-5).every(r => r.ok));
    // No client probes during quiet windows. Do not restart the VPN or change
    // its production options. RSS need not fall when V8 frees live objects.
    const memoryPath = `/run/e2e-memory-${initialIdentity.pid}.json`;
    for (let i = 0; i < 4; i++) {
      if (i) await delay(60000);
      if (i === 3) {
        const old = JSON.parse(fs.readFileSync(memoryPath, 'utf8')).monotonicMs;
        fs.writeFileSync(`/run/e2e-memory-gc-${initialIdentity.pid}`, 'collect');
        await until(() => { const m = JSON.parse(fs.readFileSync(memoryPath, 'utf8')); return m.forcedGc && m.monotonicMs > old; }, 'lab GC sample');
      }
      event({ event: 'quiescent-memory', phase: 0, sample: i, quietSeconds: i * 60,
        nodeMemory: JSON.parse(fs.readFileSync(memoryPath, 'utf8')),
        fds: fs.readdirSync(`/proc/${initialIdentity.pid}/fd`).length });
    }
    if (diagnostics) {
      // Reclaim only already-free allocator pages, once, after the GC snapshot.
      // Never run trim in production or during the workload.
      await delay(1000);
      fs.writeFileSync(`/run/e2e-memory-trim-${initialIdentity.pid}`, 'trim');
      let trimmed;
      await until(() => {
        const m = JSON.parse(fs.readFileSync(memoryPath, 'utf8'));
        if (m.nativeMemory.trimmed < 0) return false;
        trimmed = m; return true;
      }, 'native trim diagnostic sample');
      event({ event: 'allocator-trim', phase: 0, nodeMemory: trimmed,
        fds: fs.readdirSync(`/proc/${initialIdentity.pid}/fd`).length });
      await stopObserver();
    }
    event({ event: 'soak-completed', phase: 0, cycles: 3, elapsedMs: performance.now() - started,
      monitorSamples: hits('/run/e2e-monitor-results').length, longSamples: hits('/run/e2e-long-results').length });
  } finally { await stopObserver(); for (const child of children) if (child.exitCode === null) child.kill('SIGKILL'); }
}
