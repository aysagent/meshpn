// Disposable veth phone fixture: DORA without changing interface addresses.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import dgram from 'node:dgram';
import {randomBytes} from 'node:crypto';
import {makeDhcpLabRequest,parseDhcpLabReply} from './lib/dhcp-lab-wire.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_SETUP,'1');
assert.equal(fs.readFileSync('/run/systemd/container','utf8').trim(),'podman');
assert.notEqual(fs.readlinkSync('/proc/self/ns/net'),fs.readlinkSync('/proc/1/ns/net'));
assert.ok(fs.existsSync('/sys/class/net/phone0'));
const xid=randomBytes(4).readUInt32BE(),socket=dgram.createSocket('udp4');
let offer;
await new Promise((resolve,reject)=>{
 const finish=error=>{clearTimeout(timer);socket.close();error?reject(error):resolve();};
 const timer=setTimeout(()=>finish(Error('DHCP timeout')),5000);
 socket.once('error',finish);
 socket.on('message',packet=>{
  if(packet.length<8||packet.readUInt32BE(4)!==xid)return;
  try{
   const reply=parseDhcpLabReply(packet,xid);assert.deepEqual(reply.dns,['192.168.7.1']);
   if(!offer){assert.equal(reply.type,2);offer=reply;socket.send(makeDhcpLabRequest({xid,requested:reply.address,server:reply.server}),67,'255.255.255.255');}
   else{assert.equal(reply.type,5);assert.equal(reply.address,offer.address);finish();}
  }catch(e){finish(e);}
 });
 socket.bind(68,'0.0.0.0',()=>{socket.setBroadcast(true);socket.send(makeDhcpLabRequest({xid}),67,'255.255.255.255');});
});
console.log('DHCP_OFFER_ACK_ROUTER_AND_SINGLE_DNS_OK');
