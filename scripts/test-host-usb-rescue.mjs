import test from 'node:test';
import assert from 'node:assert/strict';
import { rescueUnits, rescueHelper, rescueFiles, validateUsbAddress, rescueProbeUnit } from './lib/host-usb-rescue.mjs';

test('systemctl inspection uses a concrete template instance without starting it', () => {
  assert.equal(rescueProbeUnit('clean-vpn-usb-rescue@.service'), 'clean-vpn-usb-rescue@inspection.service');
  assert.equal(rescueProbeUnit('clean-vpn-usb-rescue.socket'), 'clean-vpn-usb-rescue.socket');
});

const link = () => ({ ifname: 'usb0', address: '02:00:00:00:00:02', flags: ['UP'], addr_info: [{ family: 'inet', local: '192.168.7.1', prefixlen: 24 }] });
test('installer requires the live known USB IPv4 configuration', () => {
  validateUsbAddress([link()]);
  for (const change of [{ ifname: 'eth0' }, { address: '00:00:00:00:00:00' }, { flags: [] }, { addr_info: [] },
    { addr_info: [{ family: 'inet', local: '192.168.7.2', prefixlen: 24 }] }]) assert.throws(() => validateUsbAddress([{ ...link(), ...change }]));
  assert.throws(() => validateUsbAddress([]));
});
test('socket is USB-only, IPv4-only, and does not use early sockets.target ordering', () => {
  const text = rescueUnits['clean-vpn-usb-rescue.socket'];
  assert.match(text, /ListenStream=192\.168\.7\.1:2222\nBindToDevice=usb0\nFreeBind=yes\nAccept=yes/);
  assert.match(text, /DefaultDependencies=no/);
  assert.match(text, /WantedBy=multi-user.target sys-subsystem-net-devices-usb0.device/);
  assert.doesNotMatch(text, /(?:Before|WantedBy)=sockets.target/);
});
test('rescue uses existing auth, not the primary SSH service, and disables forwarding', () => {
  const text = rescueUnits['clean-vpn-usb-rescue@.service'];
  assert.match(text, /sshd -i -e -o DisableForwarding=yes -o PermitTunnel=no -o UseDNS=no/);
  assert.match(text, /StandardInput=socket/);
  assert.match(text, /RuntimeDirectoryPreserve=yes/);
  assert.doesNotMatch(text, /PasswordAuthentication|PermitRootLogin|AuthorizedKeys|HostKey| -f /i);
});
test('no unit dependency on networking, existing SSH, or VPN success', () => {
  for (const text of Object.values(rescueUnits)) {
    for (const line of text.split('\n').filter(l => /^(After|Before|Requires|Wants|BindsTo|PartOf)=/.test(l)))
      assert.doesNotMatch(line, /network(?:d|\.target|-online)|clean-vpn(?:-killswitch)?\.service|usb-gadget|(?:^| )ssh\.service/);
  }
});
test('helper is additive, fixed-interface, and never changes global networking', () => {
  assert.match(rescueHelper, /ip address add 192\.168\.7\.1\/24 dev usb0/);
  assert.doesNotMatch(rescueHelper.split('\n').filter(l => !l.startsWith('#')).join('\n'), /\b(flush|delete|replace|modprobe|iptables|sysctl|systemctl|reboot)\b/);
  assert.equal(Object.keys(rescueFiles).length, 4);
});
