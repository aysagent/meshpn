// Lab-only program executed inside the managed client namespace, never host DNS.
export const managedDnsProbe = String.raw`
import dgram from 'node:dgram';import net from 'node:net';
import {parseDns} from '/opt/clean-vpn/scripts/lib/lab-dns-wire.mjs';
const [name,transport,typeText='1',host='10.99.0.2',portText='1053']=process.argv.slice(1),port=Number(portText),type=Number(typeText),h=Buffer.alloc(12);h.writeUInt16BE(4321);h.writeUInt16BE(0x100,2);h.writeUInt16BE(1,4);const tail=Buffer.alloc(5);tail.writeUInt16BE(type,1);tail.writeUInt16BE(1,3);const q=Buffer.concat([h,...name.split('.').map(l=>Buffer.concat([Buffer.from([l.length]),Buffer.from(l)])),tail]);
const output=b=>{const p=parseDns(b);if(p.id!==4321)throw Error('id');console.log(JSON.stringify({rcode:p.rcode,answers:p.records.filter(r=>r.section===0).map(r=>({type:r.type,ipv4:r.type===1?[...b.subarray(r.offset,r.offset+4)].join('.'):null}))}));};
const deadline=setTimeout(()=>process.exit(2),6000);
if(transport==='tcp'){let b=Buffer.alloc(0);const s=net.connect(port,host,()=>{const len=Buffer.alloc(2);len.writeUInt16BE(q.length);s.write(Buffer.concat([len,q]));});s.on('error',()=>process.exit(3));s.on('data',d=>{b=Buffer.concat([b,d]);if(b.length>8192)process.exit(4);if(b.length>=2&&b.length===b.readUInt16BE(0)+2){output(b.subarray(2));clearTimeout(deadline);s.destroy();}});}
else{const s=dgram.createSocket('udp4');s.on('error',()=>process.exit(3));s.on('message',b=>{output(b);clearTimeout(deadline);s.close();});s.send(q,port,host);}
`;
