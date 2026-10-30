// Explicit disposable Linux lab only; child namespace owns every address.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const enabled=process.platform==='linux'&&process.getuid()===0&&process.env.CVPN_DNS_TCP_LATENCY_TEST==='1';
test('real TCP DNS frames avoid prefix stalls and preserve partial IO/cancellation',{skip:!enabled,timeout:20000},t=>{
 assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab','utf8').trim(),'isolated-admin-lab-v1');
 const run=(c,a)=>execFileSync(c,a,{encoding:'utf8',timeout:15000,stdio:['pipe','pipe','pipe']});
 assert.deepEqual(JSON.parse(run('ip',['-j','link'])).map(x=>x.ifname),['lo']);
 const snapshot=()=>['link','addr','route','rule'].map(x=>run('ip',['-j',x]));const before=snapshot();
 const mode=process.env.CVPN_DNS_TCP_BASELINE==='1'?'--baseline':'--expect-coalesced';
 const binary=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build','dns-tcp-latency-test');
 const output=run('unshare',['--net','--mount','--propagation','private','sh','-c','set -eu; ip link set lo up; ip addr add 10.99.0.1/32 dev lo; ip addr add 10.99.0.2/32 dev lo; exec "$1" "$2"','fixture',binary,mode]);
 assert.match(output,/DNS_TCP_FRAMING_PASS/);assert.equal(output.split('\n').filter(x=>x.startsWith('DNS_TCP_SAMPLE ')).length,5);
 assert.deepEqual(snapshot(),before);t.diagnostic(output.trim());
});
