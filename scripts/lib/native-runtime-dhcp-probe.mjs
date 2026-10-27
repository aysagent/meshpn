// Fixture only: DORA exchange without applying a lease to the interface.
import dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import fs from 'node:fs';
assert.ok(fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.runtime-host-wiring=1'),'disposable_vm_only');
const xid=randomBytes(4),mac=Buffer.from('021122334455','hex'),gateway=Buffer.from([192,168,7,1]);
const header=Buffer.alloc(240);header[0]=1;header[1]=1;header[2]=6;xid.copy(header,4);header.writeUInt16BE(0x8000,10);mac.copy(header,28);header.writeUInt32BE(0x63825363,236);
const packet=options=>Buffer.concat([header,Buffer.from(options),Buffer.from([55,2,3,6,255])]);
const socket=dgram.createSocket('udp4');let offered=false;
const timer=setTimeout(()=>{socket.close();console.error('DHCP_FIXTURE_TIMEOUT');process.exitCode=1;},4000);
socket.on('error',e=>{clearTimeout(timer);socket.close();throw e;});
socket.on('message',b=>{
  try{
    if(b.length<240||!b.subarray(4,8).equals(xid))return;
    assert.equal(b[0],2);assert.equal(b.readUInt32BE(236),0x63825363);
    const options=new Map();
    for(let p=240;p<b.length;){const type=b[p++];if(type===255)break;if(type===0)continue;const n=b[p++];assert.ok(p+n<=b.length);assert.ok(!options.has(type),'duplicate_dhcp_option');options.set(type,b.subarray(p,p+n));p+=n;}
    assert.deepEqual(options.get(3),gateway);assert.deepEqual(options.get(6),gateway);assert.deepEqual(options.get(54),gateway);
    const address=b.subarray(16,20);assert.deepEqual(address.subarray(0,3),gateway.subarray(0,3));assert.ok(address[3]>=10&&address[3]<=50);
    if(!offered){assert.deepEqual(options.get(53),Buffer.from([2]));offered=true;
      socket.send(packet([53,1,3,50,4,...address,54,4,...gateway]),67,'255.255.255.255');
    }else{assert.deepEqual(options.get(53),Buffer.from([5]));clearTimeout(timer);socket.close();console.log('DHCP_ROUTER_AND_SINGLE_DNS_OPTION_OK');}
  }catch(e){clearTimeout(timer);socket.close();throw e;}
});
socket.bind(68,'0.0.0.0',()=>{socket.setBroadcast(true);socket.send(packet([53,1,1]),67,'255.255.255.255');});
