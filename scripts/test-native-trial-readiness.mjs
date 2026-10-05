import test from 'node:test';
import assert from 'node:assert/strict';
import { waitLegacyReady } from './lib/native-trial-readiness.mjs';

function fixture(change = () => {}) {
  let clock = 0, attempt = 0, serviceCalls = 0;
  const calls = [];
  const io = {
    now: () => clock,
    sleep: async ms => { clock += ms; attempt++; serviceCalls = 0; },
    inspectIpv6: async ({ run }) => { await run('ipv6-audit', []); },
    async run(file, args, timeout) {
      assert.ok(timeout > 0 && timeout <= 3500); clock += 1;
      calls.push({ file, args, timeout });
      let step, value;
      if (file === 'systemctl') {
        step = ++serviceCalls === 1 ? 'service' : 'identity';
        value = 'MainPID=758\nActiveState=active\nSubState=running';
      } else if (file === 'ip' && args.includes('address')) {
        step = 'tun'; value = JSON.stringify([{ ifname: 'tun0', ifindex: 10, flags: ['UP'],
          addr_info: [{ family: 'inet', local: '10.99.0.2' }] }]);
      } else if (file === 'ip') {
        step = 'routes'; value = JSON.stringify([{ dev: args.at(-1) === '154.62.226.216' ? 'wlan0' : 'tun0' }]);
      } else if (file === 'ipv6-audit') { step = 'ipv6_policy'; value = ''; }
      else if (file === 'curl') {
        step = 'https'; value = 'fl=PRIVATE\nip=154.62.226.216\n';
        assert.equal(args[0], '-q'); assert.ok(!args.includes('-k'));
        assert.equal(args[args.indexOf('--interface') + 1], 'tun0');
        assert.equal(args[args.indexOf('--noproxy') + 1], '*');
      } else { step = 'snat_mss'; value = '{"status":"ready","mss":{"present":2}}'; }
      return change({ step, value, attempt, args }) ?? value;
    }
  };
  return { io, calls };
}
test('waits for two real probes on the same PID/TUN; returns metadata only', async () => {
  const f = fixture(), result = await waitLegacyReady(f.io);
  assert.equal(result.status, 'ready'); assert.equal(result.attempts, 2); assert.equal(result.consecutive, 2);
  assert.equal(f.calls.filter(c => c.file === 'curl').length, 2);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|154\.62|758/);
});
for (const check of ['service', 'tun', 'routes', 'snat_mss', 'ipv6_policy', 'https', 'identity']) {
  test(`retries ${check} failure; SNAT alone cannot finish readiness`, async () => {
    const f = fixture(({ step, attempt }) => { if (step === check && attempt === 0) throw Error('PRIVATE failure'); });
    const result = await waitLegacyReady(f.io);
    assert.equal(result.attempts, 3); assert.equal(result.consecutive, 2);
  });
  test(`persistent ${check} failure is bounded and sanitized`, async () => {
    const f = fixture(({ step }) => { if (step === check) throw Error('PRIVATE'); });
    await assert.rejects(waitLegacyReady({ ...f.io, timeoutMs: 800 }), { message: `old_ready_timeout_${check}` });
    assert.equal(f.io.now(), 800);
  });
}
for (const [check, replacement] of [
  ['service', 'ActiveState=active\nSubState=running\nMainPID=0'],
  ['tun', '[{"ifname":"tun0","ifindex":10,"flags":["UP"],"addr_info":[]}]'],
  ['routes', '[{"dev":"wlan0"}]'],
  ['snat_mss', '{"status":"ready","mss":{"present":1}}'],
  ['https', 'ip=192.0.2.1\n'],
  ['https', 'ip=154.62.226.216\nip=192.0.2.1\n'],
  ['identity', 'MainPID=999\nActiveState=active\nSubState=running'],
]) test(`rejects misleading ${check} success`, async () => {
  const f = fixture(({ step }) => step === check ? replacement : undefined);
  await assert.rejects(waitLegacyReady({ ...f.io, timeoutMs: 800 }), /old_ready_timeout_/);
});
test('PID change between successful attempts restarts the stability count', async () => {
  const f = fixture(({ step, value, attempt }) => ['service', 'identity'].includes(step) && attempt > 0
    ? value.replace('758', '999') : undefined);
  assert.equal((await waitLegacyReady(f.io)).attempts, 3);
});
test('an interrupted sequence needs two new successes', async () => {
  const f = fixture(({ step, attempt }) => { if (step === 'https' && attempt === 1) throw Error('failed'); });
  assert.equal((await waitLegacyReady(f.io)).attempts, 4);
});
test('each subprocess is capped by remaining total deadline', async () => {
  let clock = 0, calls = 0;
  await assert.rejects(waitLegacyReady({ now: () => clock, timeoutMs: 100,
    run: async (_f, _a, timeout) => { calls++; assert.equal(timeout, 100); clock += timeout; throw Error('timeout'); },
    sleep: async () => assert.fail('must not sleep past deadline') }), /old_ready_timeout_service/);
  assert.equal(calls, 1);
});
