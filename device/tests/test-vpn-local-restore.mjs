import assert from 'node:assert/strict';
import {restoreVPN} from '../scripts/vpn-local-restore.mjs';
import {blockedNetworkError, monitorTransfer} from '../scripts/vpn-local-lab.mjs';
import {setTimeout as delay} from 'node:timers/promises';
for (const code of [7,28]) assert(blockedNetworkError({code}));
for (const code of ['ENOENT','ERR_ASSERTION',6,22,45,60]) assert(!blockedNetworkError({code}));
assert(!blockedNetworkError({code:28,killed:true}));
assert(!blockedNetworkError({code:28,signal:'SIGTERM'}));
// Transfer rejects while an API request is pending. With delayed attachment of
// the catch handler Node would terminate before settings restoration.
await assert.rejects(monitorTransfer(async () => { throw Error('transfer failed'); },
  async () => { await delay(20); return 1; }), /transfer failed/);
let transferFinished = false;
await assert.rejects(monitorTransfer(async () => { await delay(20); transferFinished = true; },
  async () => { throw Error('API failed'); }), /API failed/);
assert(transferFinished, 'Do not restore settings while the request is still running');
assert.deepEqual(await monitorTransfer(async () => {}, async () => 3), [3]);
const original={enabled:false,transport:'wireguard',server:'192.0.2.1:51820',kill_switch:true,tls_server_name:'exit.example',saved_servers:{tcp:'',udp:'',tls:'',wireguard:'192.0.2.1:51820'},allow_plaintext:true};
const journal={board:'m5_stamp_p4_c6',gateway:'192.168.12.1',original,ca_pem:'public CA'};
let calls=[],vpn={...original,enabled:true,transport:'tls'},ca='test CA',wrong=false,fail=false;
async function api(path,body){
 calls.push({path,body});
 if(path==='/api/status')return {board:wrong?'other':journal.board,net:{usb_ip:journal.gateway},vpn};
 if(path==='/api/vpn/config'){vpn={...vpn,...body};return {};}
 if(path==='/api/vpn/tls-ca'){if(body){if(fail)throw Error('NVS failure');ca=body.ca_pem;return {};}return {ca_pem:ca};}
 throw Error('Unexpected API');
}
await restoreVPN(journal,api);
const mutations=calls.filter(c=>c.body);
assert.equal(mutations.length,3);assert.equal(mutations[0].body.enabled,false);
assert.equal(mutations[1].path,'/api/vpn/tls-ca');assert.deepEqual(mutations[2].body,original);
assert(!JSON.stringify(calls).includes('private_key'));
calls=[];wrong=true;await assert.rejects(()=>restoreVPN(journal,api),/Wrong board/);
assert(!calls.some(c=>c.body));wrong=false;fail=true;calls=[];
await assert.rejects(()=>restoreVPN(journal,api),/NVS failure/);
assert.equal(calls.filter(c=>c.body).length,2);assert.equal(vpn.enabled,false);
console.log('VPN lab restoration: identity, disable/CA/config order, verification and failure preservation passed');
