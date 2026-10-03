import assert from 'node:assert/strict';

const ready = ['real TUN device', 'single SNAT rule', 'both guard families audited'];
const privateDns = (label, blocked, intercept = false) => ['192.168.1.1', 'fd00:1::1'].flatMap(server => [false, true].flatMap(tcp => [1, 28].flatMap(type => [
  `${label} private DNS ${server}/${tcp}/${type}`,
  `${label} private DNS ${intercept && !server.includes(':') ? 'tunnel source' : blocked ? 'no upstream' : 'direct source'} ${server}/${tcp}/${type}`,
])));
const rawTraffic = label => ['1.0.0.1', '192.168.1.1', '2606:4700:4700::1111', 'fd00:1::1'].flatMap(host => ['tcp', 'udp'].flatMap(protocol => [
  `${label} raw ${host}/${protocol}`, `${label} raw source-or-no-hit ${host}/${protocol}`,
]));
const baseline = label => [
  `${label} direct IPv4 positive control`, `${label} direct IPv6 positive control`,
  ...[false, true].flatMap(tcp => [1, 28].flatMap(type => [
    `${label} public DNS ${tcp ? 'TCP' : 'UDP'}/${type} positive control`,
    `${label} direct DNS source ${tcp}/${type}`,
  ])), ...privateDns(label, false), ...rawTraffic(label),
];
const matrix = active => {
  const label = active ? 'active' : 'stopped';
  return [
    `${label} forwarded HTTPS IPv4`, `${label} forwarded IPv6 blocked`, `${label} no IPv6 origin hit`,
    ...['1.1.1.1', '192.168.7.1'].flatMap(server => [false, true].flatMap(tcp => [1, 28].flatMap(type => [
      `${label} DNS ${server}/${tcp ? 'TCP' : 'UDP'}/${type}`,
      ...(active ? [`${label} DNS answer ${server}/${tcp}/${type}`, `${label} DNS only exit source ${server}/${tcp}/${type}`]
        : [`${label} DNS no upstream query ${server}/${tcp}/${type}`]),
    ]))),
    ...privateDns(label, true, active), `${label} non-DNS LAN IPv4 blocked`, `${label} non-DNS LAN IPv6 blocked`, ...rawTraffic(label), `${label} normal SSH authenticated`, `${label} rescue SSH authenticated`,
  ];
};
export const usbE2eChecks = phase => {
  assert.ok([0, 1].includes(phase));
  return ['systemd PID1', ...(phase === 0 ? [
    ...baseline('pre-install'), 'legacy actual installer preserves networkd PID',
    'legacy guard v2 active', 'legacy rescue authenticated', ...privateDns('legacy', false),
    'DNS upgrade readonly plan', 'DNS upgrade plan preserves VPN PID', 'actual installer upgrades DNS guard',
    'DNS upgrade leaves VPN stopped', 'DNS upgrade leaves guard active', 'DNS upgrade preserves networkd PID',
    'DNS upgrade retains authenticated rescue', ...privateDns('upgraded-stopped', true), ...ready,
    'DNS upgrade idempotent', 'repeated DNS upgrade preserves VPN PID', 'gateway removal leaves actual VPN running',
    'gateway removal leaves rescue authenticated', 'without SNAT peer fails with actual VPN', ...ready,
    'additive actual installer keeps VPN PID', 'additive installer keeps rescue socket',
  ] : [
    'different kernel boot ID', 'installed bytes restored from persistent disk', 'rescue login before DHCP/VPN',
    'DHCP is still absent', 'no premature SNAT', ...ready, 'SNAT enabled across boot',
    'guard precedes networkd', 'rescue login after delayed real VPN',
  ]), ...matrix(true), 'VPN really stopped', 'TUN removed', 'guard retained on VPN stop',
  ...matrix(false), ...ready, ...matrix(true), 'restart restored actual exit egress',
  ...(phase ? ['full actual uninstall succeeds', 'uninstall removes main/guard/SNAT files',
    'uninstall removes only owned SNAT', 'uninstall retains rescue files and login', ...baseline('post-uninstall'),
    ...ready, 'fresh v4 installer rescue authenticated', ...matrix(true), 'fresh v4 uninstall succeeds',
    'fresh v4 uninstall preserves rescue'] : [])];
};

export function assertUsbE2eEvidence(report) {
  assert.equal(report.nic, 'none'); assert.equal(report.hostSharedFilesystem, false);
  for (const key of ['realTls', 'realTun', 'persistentInstalledFiles']) assert.equal(report[key], true);
  assert.equal(report.boots.length, 2);
  const ids = [];
  for (const [phase, boot] of report.boots.entries()) {
    assert.equal(boot.phase, phase); assert.equal(boot.code, 0);
    assert.equal(boot.synced, true); assert.equal(boot.unmounted, true);
    assert.equal(boot.kernelRestart, phase === 0); assert.equal(boot.powerDown, phase === 1);
    assert.ok(boot.events.every(e => e.phase === phase && ['prepared', 'check', 'lifecycle-ready', 'completed'].includes(e.event)));
    assert.deepEqual(boot.events[0], { event: 'prepared', phase, restored: phase === 1, uplinkDown: true });
    assert.equal(boot.events.filter(e => e.event === 'prepared').length, 1);
    assert.equal(boot.events.filter(e => e.event === 'lifecycle-ready').length, 1);
    assert.deepEqual(boot.events.filter(e => e.event === 'check').map(e => e.name), usbE2eChecks(phase));
    const ends = boot.events.filter(e => e.event === 'completed'); assert.equal(ends.length, 1);
    assert.equal(boot.events.at(-1), ends[0]); assert.equal(ends[0].usbDnsPolicy, 'cvks4-usb-tunnel-only');
    assert.match(ends[0].bootId, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
    assert.equal(boot.bootId, ends[0].bootId); ids.push(boot.bootId);
  }
  assert.notEqual(ids[0], ids[1]);
}

const preserved = label => ['guard retained', 'guard not restarted', 'networkd not restarted', 'rescue not restarted', 'SSH 22 authenticated', 'SSH 2222 authenticated'].map(s => label + ' ' + s);
const noBypass = label => ['http', 'raw', 'dns'].map(k => `${label} ${k} no direct or LAN receiver hits`);
export const usbSoakInitialChecks = () => ['systemd PID1', ...baseline('pre-install'), ...ready,
  'fresh v4 installer rescue authenticated', ...matrix(true)];
export { matrix as usbTrafficChecks, ready as usbReadyChecks };
export const usbFaultChecks = (networkOnly = false) => ['systemd PID1', ...baseline('pre-install'), ...ready,
  'fresh v4 installer rescue authenticated', ...matrix(true), 'continuous traffic positive baseline',
  ...(networkOnly ? [] : ['SIGKILL automatically changes VPN PID', 'SIGKILL increments restart counter', ...ready,
    ...preserved('crash'), ...matrix(true), ...noBypass('crash')]),
  ...['exit-blackhole', 'carrier-loss'].flatMap(s => [
    ...(s === 'exit-blackhole' ? ['blackhole leaves uplink carrier and default route'] : ['carrier loss withdraws DHCP default', 'carrier loss withdraws exit bypass']),
    ...matrix(false), ...preserved(s), s + ' held at least 120 seconds', s + ' continuous traffic observes failure', ...noBypass(s),
    ...(s === 'carrier-loss' ? ['carrier DHCP returns automatically'] : []), ...ready,
    s + ' recovers without VPN restart', s + ' restart counter unchanged', s + ' exit route restored via wlan0',
    ...matrix(true), ...preserved(s + '-recovered'), ...noBypass(s + '-recovered'),
  ]), 'continuous monitor exits successfully', 'continuous monitor final traffic successful', ...noBypass('final')];

export function assertUsbFaultEvidence(report) {
  assert.equal(report.nic, 'none'); assert.equal(report.hostSharedFilesystem, false);
  assert.equal(report.realTls, true); assert.equal(report.realTun, true);
  assert.ok(['usb-faults', 'usb-network-faults'].includes(report.scenario)); assert.equal(report.boots.length, 1);
  const networkOnly = report.scenario === 'usb-network-faults';
  const b = report.boots[0];
  assert.equal(b.phase, 0); assert.equal(b.code, 0); assert.equal(b.synced, true); assert.equal(b.unmounted, true);
  assert.equal(b.powerDown, true); assert.equal(b.kernelRestart, false);
  assert.ok(b.events.every(e => e.phase === 0 && ['prepared', 'check', 'lifecycle-ready', 'fault', 'completed'].includes(e.event)));
  assert.deepEqual(b.events[0], { event: 'prepared', phase: 0, restored: false, uplinkDown: true });
  for (const name of ['prepared', 'lifecycle-ready', 'completed']) assert.equal(b.events.filter(e => e.event === name).length, 1);
  assert.deepEqual(b.events.filter(e => e.event === 'check').map(e => e.name), usbFaultChecks(networkOnly));
  const faults = b.events.filter(e => e.event === 'fault');
  assert.deepEqual(faults.map(e => [e.scenario, e.action]), [
    ...(networkOnly ? [] : [['sigkill', 'begin'], ['sigkill', 'recovered']]),
    ...['exit-blackhole', 'carrier-loss'].flatMap(s => ['begin', 'restore', 'recovered'].map(a => [s, a])),
  ]);
  for (const e of faults.filter(e => e.action === 'restore')) assert.ok(Number.isFinite(e.elapsedMs) && e.elapsedMs >= 120000);
  const end = b.events.at(-1); assert.equal(end.event, 'completed'); assert.equal(end.faultScenarios, true);
  assert.equal(end.usbDnsPolicy, 'cvks4-usb-tunnel-only'); assert.equal(end.bootId, b.bootId);
  assert.match(b.bootId, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
}
