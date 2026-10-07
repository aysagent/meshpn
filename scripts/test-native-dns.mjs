// No host routes/firewall: an unprivileged, isolated user+network namespace.
// Node launches the C++ fixture and reads only its test result, never DNS bytes.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
test('native DNS relay: UDP/TCP, invalid upstream, bounded load and cleanup',{timeout:20000},()=>{
  const binary=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build','dns-relay-test');
  const script='set -eu; /usr/bin/ip link set lo up; /usr/bin/ip addr add 10.99.0.2/32 dev lo; /usr/bin/ip addr add 1.1.1.1/32 dev lo; /usr/bin/ip addr add 8.8.8.8/32 dev lo; exec "$1"';
  const r=spawnSync('unshare',['-Urn','sh','-c',script,'native-dns-test',binary],{encoding:'utf8',timeout:15000,maxBuffer:65536});
  assert.equal(r.status,0,`${r.error??''}\n${r.stdout}\n${r.stderr}`);assert.match(r.stdout,/FD cleanup PASS/);
});
test('native DNS follows the configured peer IPv4, including upstream source binding',{timeout:20000},()=>{
  const binary=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build','dns-relay-test');
  const script='set -eu; /usr/bin/ip link set lo up; /usr/bin/ip addr add 10.99.0.3/32 dev lo; /usr/bin/ip addr add 1.1.1.1/32 dev lo; /usr/bin/ip addr add 8.8.8.8/32 dev lo; exec "$1" 10.99.0.3';
  const r=spawnSync('unshare',['-Urn','sh','-c',script,'native-dns-peer-test',binary],{encoding:'utf8',timeout:15000,maxBuffer:65536});
  assert.equal(r.status,0,`${r.error??''}\n${r.stdout}\n${r.stderr}`);assert.match(r.stdout,/FD cleanup PASS/);
});
