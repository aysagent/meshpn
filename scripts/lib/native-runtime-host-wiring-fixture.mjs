// Disposable VM adapter for the public configurable gateway controller.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { gatewayMain } from '../clean-vpn-native-gateway.mjs';
assert.ok(fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.runtime-host-wiring=1'),'disposable_vm_only');
const apply=process.argv[2]==='apply';
await gatewayMain([process.argv[2], ...(apply?['--config=/config/gateway.json','--seconds=300']:[])], {
  ready:()=>console.log('HOST_WIRING_READY'),
  checkpoint:(phase,next)=>{
    const key={'before-rename':'CVPN_WIRING_KILL_BEFORE_RENAME','before-mutation':'CVPN_WIRING_KILL_AT','after-mutation':'CVPN_WIRING_KILL_AFTER_MUTATION'}[phase];
    const selected=apply?key:phase==='before-rename'?'CVPN_WIRING_RECOVER_KILL_BEFORE_RENAME':null;
    if(selected&&Number(process.env[selected])===next&&next>0)process.kill(process.pid,'SIGKILL');
  },
});
if(!apply)console.log('HOST_WIRING_RESTORED');
