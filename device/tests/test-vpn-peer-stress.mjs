// Real local sockets/TLS. Tests the lab peer, not ESP32 RF/NAPT or the full firmware.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import {execFileSync} from 'node:child_process';
import {packet,startPeer,testAddress} from '../scripts/vpn-local-peer.mjs';
const rounds=Number(process.env.VPN_PEER_STRESS_ROUNDS??3);
assert(Number.isInteger(rounds)&&rounds>=1&&rounds<=1000);
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-peer-stress-'));
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=loopback-test',
  '-keyout',path.join(dir,'key.pem'),'-out',path.join(dir,'cert.pem')],{stdio:'ignore'});
const key=fs.readFileSync(path.join(dir,'key.pem')),cert=fs.readFileSync(path.join(dir,'cert.pem'));
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function until(check){const end=Date.now()+3000;while(!check()&&Date.now()<end)await delay(5);assert(check(),'resource/packet deadline');}
function echo(i){const body=Buffer.alloc(80,i&255);body[0]=8;body[1]=0;return packet('10.99.0.2',testAddress,1,body);}
function framed(p){const n=Buffer.alloc(4);n.writeUInt32BE(p.length);return Buffer.concat([n,p]);}
async function open(peer,type){
 const socket=type==='tls'?tls.connect({host:'127.0.0.1',port:peer.port,servername:'loopback-test',ca:cert,
   minVersion:'TLSv1.2',maxVersion:'TLSv1.2'}):net.connect(peer.port,'127.0.0.1');
 socket.on('error',()=>{});
 await new Promise((resolve,reject)=>{socket.once(type==='tls'?'secureConnect':'connect',resolve);socket.once('error',reject);});
 return socket;
}
const result={scope:'loopback lab-peer lifecycle; not ESP32 throughput/stability',rounds,transports:[],memory:[]};
for(const type of ['tcp','udp','tls']){
 const peer=await startPeer({type,key,cert,fragmentFrames:type!=='udp',maxPendingBytes:8192});
 try{
  for(let r=0;r<rounds;r++){
   if(type==='udp'){
    const s=dgram.createSocket('udp4');let received=0;
    s.on('message',p=>{assert.equal(p[20],0);received++;});
    try{for(let i=0;i<8;i++)await new Promise((ok,bad)=>s.send(echo(i),peer.port,'127.0.0.1',e=>e?bad(e):ok()));
     await until(()=>received===8);
    }finally{s.close();}
    peer.drop();
   }else{
    let s=await open(peer,type), input=Buffer.alloc(0), received=0;
    try{
     s.on('data',b=>{input=Buffer.concat([input,b]);while(input.length>=4){const n=input.readUInt32BE(0);assert(n>=20&&n<=1400);
      if(input.length<n+4)break;assert.equal(input[24],0);received++;input=input.subarray(n+4);}});
     for(let i=0;i<8;i++){const p=framed(echo(i));s.write(p.subarray(0,2));s.write(p.subarray(2));}
     await until(()=>received===8);
    }finally{s.destroy();}
    await until(()=>peer.resources().sockets===0&&peer.resources().writers===0);
    // Interrupted header must disappear with the connection, not poison reconnect.
    s=await open(peer,type);s.write(Buffer.from([0,0]));peer.drop();s.destroy();
    await until(()=>peer.resources().sockets===0&&peer.resources().queued_bytes===0);
   }
   if(r%10===0)result.memory.push({type,round:r,...process.memoryUsage(),resources:peer.resources()});
  }
  assert.equal(peer.stats.packets_in,rounds*8);assert.equal(peer.stats.packets_out,rounds*8);
  assert.equal(peer.stats.invalid,0);assert.equal(peer.stats.output_overflow,0);
 }finally{await peer.close();}
 await until(()=>Object.values(peer.resources()).every(n=>n===0));
 result.transports.push({type,stats:peer.stats,resources:peer.resources()});
}
// A non-reading client cannot accumulate an unbounded promise/output queue.
for(const type of ['tcp','tls']){
 const peer=await startPeer({type,key,cert,fragmentFrames:true,writeDelayMs:10,maxPendingBytes:1404});
 let s;
 try{s=await open(peer,type);s.pause();s.write(Buffer.concat(Array.from({length:100},(_,i)=>framed(echo(i)))));
  await until(()=>peer.stats.output_overflow===1);s.destroy();
  await until(()=>peer.resources().queued_bytes===0&&peer.resources().sockets===0);
  assert(peer.stats.output_high_water<=1404);
 }finally{s?.destroy();await peer.close();}
}
result.finished=new Date().toISOString();
const output=process.env.VPN_PEER_STRESS_OUT||path.join(dir,'result.json');
fs.writeFileSync(output,JSON.stringify(result,null,2),{mode:0o600});
console.log(`Peer stress: ${rounds} cycles per TCP/UDP/TLS, partial headers, reconnect and bounded slow-reader output passed; ${output}`);
