import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  nativeMacLabContainerAction, nativeMacLabImageTag, nativeMacBrowserImageTag, nativeMacLabMachineInitArgs,
  parseNativeMacLabArgs,
} from './lib/native-macos-lab.mjs';

test('macOS lab parser has a read-only default and explicit VM modes', () => {
  assert.deepEqual(parseNativeMacLabArgs([], {}), {
    action: '--status', machine: 'meshpn-clean-vpn-lab', rebuildImage: false, refreshBase: false,
  });
  assert.deepEqual(parseNativeMacLabArgs(['--native-combo-boot', '--machine=lab-1', '--refresh-base'], {}), {
    action: '--native-combo-boot', machine: 'lab-1', rebuildImage: false, refreshBase: true,
  });
  assert.deepEqual(nativeMacLabContainerAction('--native-combo-boot'), ['run', '--native-combo-boot']);
  assert.equal(parseNativeMacLabArgs(['--tls-profiles'], {}).action, '--tls-profiles');
  assert.equal(parseNativeMacLabArgs(['--h2-budget'], {}).action, '--h2-budget');
  assert.deepEqual(nativeMacLabContainerAction('--h2-budget'), ['h2-budget']);
  assert.throws(()=>parseNativeMacLabArgs(['--h2-budget','--refresh-base'],{}));
  assert.equal(parseNativeMacLabArgs(['--browser-capture'], {}).action, '--browser-capture');
  assert.equal(parseNativeMacLabArgs(['--http2-capture'], {}).action, '--http2-capture');
  assert.throws(()=>parseNativeMacLabArgs(['--http2-capture','--refresh-base'],{}));
  assert.throws(() => parseNativeMacLabArgs(['--browser-capture', '--refresh-base'], {}));
  assert.deepEqual(nativeMacLabContainerAction('--tls-profiles'), ['tls-profiles']);
  assert.equal(parseNativeMacLabArgs(['--multi-clients'], {}).action, '--multi-clients');
  assert.deepEqual(nativeMacLabContainerAction('--multi-clients'), ['multi-clients']);
  assert.throws(() => parseNativeMacLabArgs(['--multi-clients', '--refresh-base'], {}));
});

test('macOS lab parser rejects ambiguous or unsafe options', () => {
  for (const args of [['--prepare', '--status'], ['--machine=bad/name'], ['--refresh-base'], ['--stop', '--rebuild-image'], ['--wat']])
    assert.throws(() => parseNativeMacLabArgs(args, {}));
});

test('image tag is content-addressed and machine resources are bounded', () => {
  assert.equal(nativeMacLabImageTag(Buffer.from('same')), nativeMacLabImageTag(Buffer.from('same')));
  assert.notEqual(nativeMacLabImageTag(Buffer.from('same')), nativeMacLabImageTag(Buffer.from('different')));
  assert.notEqual(nativeMacBrowserImageTag(Buffer.from('same')), nativeMacLabImageTag(Buffer.from('same')));
  assert.notEqual(nativeMacBrowserImageTag(Buffer.from('same')), nativeMacBrowserImageTag(Buffer.from('different')));
  assert.deepEqual(nativeMacLabMachineInitArgs('lab'), ['machine', 'init', '--provider=applehv', '--cpus=6', '--memory=6144', '--disk-size=100', '--rootful', 'lab']);
});

test('lab cache preserves build mtimes and APT evidence', () => {
  const worker = readFileSync(new URL('./clean-vpn-native-container-lab.sh', import.meta.url), 'utf8');
  const containerfile = readFileSync(new URL('./containers/clean-vpn-native-lab.Containerfile', import.meta.url), 'utf8');
  const nativeLab = readFileSync(new URL('./clean-vpn-native-lab.mjs', import.meta.url), 'utf8');
  assert.match(worker, /--preserve-modification-time/);
  assert.match(worker, /--qemu=\$NATIVE_QEMU/);
  assert.match(worker, /--qemu=\$NATIVE_QEMU" --nested-emulation/);
  assert.match(nativeLab, /nestedEmulation\?'qemu64':'max'/);
  assert.match(nativeLab, /xtables-\$\{prior\.firewallBackend\}-multi/);
  assert.match(containerfile, /FROM --platform=linux\/arm64 ubuntu:24\.04 AS native_qemu/);
  assert.match(containerfile, /apt-get install -y --no-install-recommends udev/, 'cold-boot image needs the udev daemon, not only systemd units');
  assert.match(containerfile, /test -x \/usr\/lib\/systemd\/systemd-udevd/);
  assert.match(worker, /scripts\/fixtures\/usb-dns-v2-guard\.txt/);
  assert.match(containerfile, /ld-linux-aarch64\.so\.1/);
  assert.doesNotMatch(containerfile, /rm -rf \/var\/lib\/apt\/lists/);
});
