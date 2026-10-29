import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import {packet, startPeer, testAddress} from '../scripts/vpn-local-peer.mjs';

// A synthetic exit must not make a broken transport checksum look healthy.
const peer = await startPeer({type:'udp'});
const socket = dgram.createSocket('udp4');
const replies = [];
socket.on('message', b => replies.push(b));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function send(p) {
  await new Promise((resolve,reject) => socket.send(p,peer.port,'127.0.0.1',e=>e?reject(e):resolve()));
}
async function wait(check) {
  const end=Date.now()+2000;
  while (!check() && Date.now()<end) await delay(5);
  assert(check(), 'peer did not process packet');
}
function echo(protocol) {
  const body=Buffer.alloc(protocol===6?20:12);
  if(protocol===1)body[0]=8;
  else {
    body.writeUInt16BE(40000,0);body.writeUInt16BE(protocol===6?80:7,2);
    if(protocol===6){body[12]=0x50;body[13]=2;}
    else body.writeUInt16BE(body.length,4);
  }
  return packet('10.99.0.2',testAddress,protocol,body);
}
try {
  for(const protocol of [1,6,17]) {
    const good=echo(protocol), bad=Buffer.from(good);bad[bad.length-1]^=1;
    const before=peer.stats.invalid, count=replies.length;
    await send(bad);await wait(()=>peer.stats.invalid===before+1);
    assert.equal(replies.length,count);
    await send(good);await wait(()=>replies.length===count+1);
  }
  const zero=echo(17);zero.writeUInt16BE(0,26);
  const count=replies.length;await send(zero);await wait(()=>replies.length===count+1);
  // IPv4 permits zero UDP checksum, but the UDP length must still match.
  const badLength=Buffer.from(zero);badLength.writeUInt16BE(9,24);
  const before=peer.stats.invalid;await send(badLength);await wait(()=>peer.stats.invalid===before+1);
  assert.equal(replies.length,count+1);
  console.log('Synthetic VPN peer rejects corrupt ICMP/TCP/UDP and invalid UDP length; IPv4 zero UDP checksum accepted');
} finally {socket.close();await peer.close();}

// A reconnect may reuse its inner tuple; old synthetic TCP state must not leak.
const tcpPeer=await startPeer({type:'tcp'});
async function synAck(sequence) {
  const s=net.connect(tcpPeer.port,'127.0.0.1');
  try {
    await new Promise((resolve,reject)=>{s.once('connect',resolve);s.once('error',reject);});
    const p=echo(6), body=Buffer.from(p.subarray(20));body.writeUInt32BE(sequence,4);
    const syn=packet('10.99.0.2',testAddress,6,body), length=Buffer.alloc(4);length.writeUInt32BE(syn.length);
    const response=new Promise((resolve,reject)=>{let received=Buffer.alloc(0);
      s.setTimeout(2000,()=>reject(Error('missing SYN ACK')));
      s.on('data',b=>{received=Buffer.concat([received,b]);if(received.length>=48)resolve(received);});
      s.once('error',reject);
    });
    s.write(Buffer.concat([length,syn]));
    return (await response).readUInt32BE(4+28);
  } finally {s.destroy();}
}
try {
  assert.equal(await synAck(100),101);
  assert.equal(await synAck(200),201);
  console.log('Synthetic VPN peer isolates inner TCP state across outer reconnects');
} finally {await tcpPeer.close();}
