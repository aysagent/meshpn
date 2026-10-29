#!/usr/bin/env node
import fs from 'node:fs';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { runtimePacketConfig } from './lib/native-runtime-plan.mjs';

// Bounded live DNS exchange, never a cached ready-file or a PID-only assertion.
export function dnsProbe(host, port, tcp, name = 'example.com') {
  assert.match(name, /^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/);
  const q = Buffer.concat([randomBytes(2), Buffer.from('01000001000000000000', 'hex'),
    ...name.split('.').map(v => Buffer.concat([Buffer.from([v.length]), Buffer.from(v)])), Buffer.from([0, 0, 1, 0, 1])]);
  return new Promise((resolve, reject) => {
    const socket = tcp ? new net.Socket() : dgram.createSocket('udp4');
    let finished = false, data = Buffer.alloc(0);
    const finish = error => {
      if (finished) return; finished = true; clearTimeout(timer);
      if (tcp) socket.destroy(); else socket.close();
      error ? reject(error) : resolve();
    };
    const answer = b => {
      if (b.length < q.length || !b.subarray(0, 2).equals(q.subarray(0, 2)) ||
          !(b[2] & 0x80) || (b[2] & 2) || (b[3] & 15) || !b.readUInt16BE(6) ||
          b.readUInt16BE(4) !== 1 || !b.subarray(12, q.length).equals(q.subarray(12))) return finish(Error('dns_health_response'));
      finish();
    };
    const timer = setTimeout(() => finish(Error('dns_health_timeout')), 4000);
    socket.on('error', finish);
    if (tcp) {
      socket.on('close', () => { if (!finished) finish(Error('dns_health_closed')); });
      socket.on('data', b => {
        data = Buffer.concat([data, b]);
        if (data.length > 65537) return finish(Error('dns_health_limit'));
        if (data.length >= 2 && data.length >= data.readUInt16BE(0) + 2) answer(data.subarray(2, 2 + data.readUInt16BE(0)));
      });
      socket.connect(port, host, () => {
        const prefix = Buffer.alloc(2); prefix.writeUInt16BE(q.length); socket.write(Buffer.concat([prefix, q]));
      });
    } else {
      socket.on('message', answer);
      socket.connect(port, host, () => socket.send(q));
    }
  });
}

async function main() {
  const directory = process.env.CVPN_STATE_DIRECTORY ?? '/run/clean-vpn';
  assert.match(directory, /^\/run\/clean-vpn(?:-[a-zA-Z0-9_-]{1,48})?$/);
  const state = JSON.parse(fs.readFileSync(directory + '/network.json', 'utf8'));
  assert.equal(state.namespace, fs.readlinkSync('/proc/self/ns/net')); assert.equal(state.phase, 'ready');
  const config = JSON.parse(fs.readFileSync(directory + '/engine.json', 'utf8')), c = runtimePacketConfig(config);
  const listening = value => {
    const port = value.toString(16).toUpperCase().padStart(4, '0');
    assert.ok(fs.readFileSync('/proc/net/tcp', 'utf8').split('\n').some(l => l.trim().split(/\s+/)[1]?.endsWith(':' + port) && l.trim().split(/\s+/)[3] === '0A'));
  };
  if (c.role === 'client') {
    await Promise.all([false, true].map(tcp => dnsProbe(c.peer_ipv4 ?? '10.99.0.2', 1053, tcp)));
    if (config.transport === 'combo-tls') listening(config.transparent.listen.port);
    console.log(config.transport === 'combo-tls' ? 'NATIVE_HEALTH=authenticated-packet-dns-and-local-relay-listener' : 'NATIVE_HEALTH=authenticated-tunnel-and-dns');
  } else {
    listening(c.port);
    console.log('NATIVE_HEALTH=exit-listening-only');
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.error('NATIVE_HEALTH=unhealthy'); process.exitCode = 1; });
}
