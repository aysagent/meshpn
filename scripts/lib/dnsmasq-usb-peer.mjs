import assert from 'node:assert/strict';
import { readlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { child, exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';

/** Creates only a namespace-local veth and bounded test RPC worker. */
export async function startDnsmasqUsbPeer() {
  return startPeer(false);
}

export async function startDnsmasqUpstreamPeer() {
  return startPeer(true);
}

async function startPeer(upstream) {
  await assertDnsMountNamespace();
  const gatewayNetns = await readlink('/proc/self/ns/net');
  const worker = fileURLToPath(new URL('./dnsmasq-usb-peer-worker.mjs', import.meta.url));
  const peer = child('unshare', ['--net', process.execPath, worker, ...(upstream ? ['--upstream'] : [])], { stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, MESHPN_DNSMASQ_GATEWAY_NETNS: gatewayNetns } });
  peer.proc.stdin.on('error', () => {});
  let id = 0, sequence = 0;
  async function call(operation, options) {
    const request = ++id;
    const reply = peer.waitFor(new RegExp(`USB_PEER ${request} ([^\\n]+)\\n`), 12000);
    peer.proc.stdin.write(`${JSON.stringify({ id: request, operation, options })}\n`);
    const result = JSON.parse((await reply)[1]); assert.equal(result.ok, true); return result.result;
  }
  try {
    await peer.waitFor(/USB_PEER 0 /, 5000);
    assert.notEqual(await readlink(`/proc/${peer.proc.pid}/ns/net`), gatewayNetns);
    if (upstream) {
      await exec('ip', ['link', 'add', 'wanfixture', 'type', 'veth', 'peer', 'name', 'wanpeer']);
      await exec('ip', ['link', 'set', 'wanpeer', 'netns', String(peer.proc.pid)]);
      await exec('ip', ['addr', 'add', '198.18.0.1/30', 'dev', 'wanfixture']);
      await exec('ip', ['-6', 'addr', 'add', '2001:db8:8::1/64', 'dev', 'wanfixture', 'nodad']);
      await exec('ip', ['link', 'set', 'wanfixture', 'up']);
      await exec('ip', ['route', 'add', '203.0.113.53/32', 'via', '198.18.0.2']);
      await exec('ip', ['-6', 'route', 'add', '2001:db8:54::53/128', 'via', '2001:db8:8::2']);
      // Network namespace sysctls, never the host's forwarding settings.
      const forwarding = await exec('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
      assert.equal((await exec('sysctl', ['-n', 'net.ipv4.ip_forward'])).stdout.trim(), '1', JSON.stringify(forwarding));
      const forwarding6 = await exec('sysctl', ['-w', 'net.ipv6.conf.all.forwarding=1']);
      assert.equal((await exec('sysctl', ['-n', 'net.ipv6.conf.all.forwarding'])).stdout.trim(), '1', JSON.stringify(forwarding6));
    } else {
      await exec('ip', ['link', 'add', 'usb0', 'type', 'veth', 'peer', 'name', 'usbpeer']);
      await exec('ip', ['link', 'set', 'usbpeer', 'netns', String(peer.proc.pid)]);
      await exec('ip', ['addr', 'add', '192.168.7.1/24', 'dev', 'usb0']);
      await exec('ip', ['-6', 'addr', 'add', '2001:db8:7::1/64', 'dev', 'usb0', 'nodad']);
      await exec('ip', ['link', 'set', 'usb0', 'up']);
    }
    await call('configure');
    return { acquire: () => call('acquire'), hits: () => call('hits'),
      lookup: (options = {}) => call('lookup', { sequence: ++sequence, tcp: false, type: 1, ...options }),
      close: () => peer.stop() };
  } catch (error) { await peer.stop(); throw error; }
}
