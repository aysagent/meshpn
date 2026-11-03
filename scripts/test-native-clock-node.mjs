import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {validateResponse,hostPin,sshArgs,claimAttempt,strictFlatJson} from './clean-vpn-native-clock.mjs';
const nonce='a'.repeat(64),now=1793664000;
const data=o=>JSON.stringify({version:1,nonce,unix_seconds:now,synchronized:true,...o});
test('clock JSON rejects duplicate/escaped duplicate keys and nested payloads',()=>{
 for(const text of ['{"version":1,"version":2}','{"version":1,"ver\\u0073ion":2}','{"version":{}}','[]'])assert.throws(()=>strictFlatJson(text));
 assert.deepEqual(strictFlatJson('{"value":"a\\\"b: c","version":1}'),{value:'a"b: c',version:1});
});
test('clock validates nonce, bounded RTT, remote sync, floor and stable local clock',()=>{
 assert.equal(validateResponse(data(),nonce,.2,now-100,now-99.8).needsCorrection,true);
 assert.equal(validateResponse(data(),nonce,.2,now,now+.2).needsCorrection,false);
 for(const fn of [()=>validateResponse(data({nonce:'b'.repeat(64)}),nonce,.2,now,now+.2),()=>validateResponse(data(),nonce,5.01,now,now+5.01),()=>validateResponse(data(),nonce,.1,now,now+10),()=>validateResponse(data({synchronized:false}),nonce,.2,now,now+.2),()=>validateResponse(data(),nonce,.2,now,now+.2,now+6),()=>validateResponse(data({unix_seconds:0}),nonce,.2,now,now+.2),()=>validateResponse(data({extra:true}),nonce,.2,now,now+.2)])assert.throws(fn);
});
test('SSH enforces raw pinned host key and excludes agent, proxies and multiplex',()=>{
 const raw=Buffer.concat([Buffer.from('0000000b7373682d6564323535313900000020','hex'),Buffer.alloc(32,1)]);
 assert.match(hostPin(Buffer.from('clean-vpn-clock ssh-ed25519 '+raw.toString('base64'))),/^[a-f0-9]{64}$/);
 assert.throws(()=>hostPin(Buffer.from('other ssh-ed25519 '+raw.toString('base64'))));
 const a=sshArgs({host:'192.0.2.1',port:22,user:'cvpn-clock',identity:'/key',known_hosts:'/pin'});
 for(const s of ['StrictHostKeyChecking=yes','IdentityAgent=none','ControlPath=none','ProxyCommand=none','GlobalKnownHostsFile=/dev/null','PasswordAuthentication=no','ClearAllForwardings=yes'])assert.ok(a.includes(s));
});
test('failed probe cannot reset the once-per-boot budget; fresh boot can retry',t=>{
 const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'clock-node-')));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const c={state_dir:dir},boot='12345678-1234-1234-1234-123456789012';
 claimAttempt(c,'auth_clock_skew',boot);assert.throws(()=>claimAttempt(c,'tls_verify_expired',boot),/clock_attempt_already_consumed/);
 claimAttempt(c,'auth_clock_skew','22345678-1234-1234-1234-123456789012');assert.throws(()=>claimAttempt(c,'timeout',boot),/clock_failure_required/);
 assert.equal(fs.statSync(dir+'/attempt.json').mode&0o777,0o600);
});
