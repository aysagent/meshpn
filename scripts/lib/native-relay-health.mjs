// Opt-in active probe. Target selection is explicit; no OS DNS or redirects.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import {isIPv4} from 'node:net';
import {createHash} from 'node:crypto';
import {transparentSpecialIPv4} from './native-transparent-network.mjs';

const numeric=ip=>ip.split('.').reduce((a,b)=>a*256+Number(b),0);
export function validateRelayHealth(c,relay){
  assert.deepEqual(Object.keys(c).sort(),['ca','ipv4','path','server_name','sha256','version']);
  assert.equal(c.version,1);assert.ok(isIPv4(c.ipv4));
  for(const range of [...transparentSpecialIPv4,...relay.destination_policy.deny_ipv4,relay.exit.ipv4+'/32']){
    const [ip,bits]=range.split('/');assert.notEqual(Math.floor(numeric(c.ipv4)/2**(32-Number(bits))),Math.floor(numeric(ip)/2**(32-Number(bits))),'health_destination_denied');
  }
  assert.match(c.server_name,/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/);
  assert.ok(c.server_name.split('.').every(l=>l.length<=63));
  assert.ok(typeof c.path==='string'&&c.path.length<=512&&/^\/[a-zA-Z0-9/_?=.&%~-]*$/.test(c.path));
  assert.match(c.sha256,/^[a-f0-9]{64}$/);
  assert.ok(c.ca===null||typeof c.ca==='string'&&/^\/config\/[a-zA-Z0-9_-]+\.pem$/.test(c.ca),'health_ca_path');
  return c;
}
export function readRelayHealth(file,relay){
  const s=fs.lstatSync(file);assert.ok(s.isFile()&&s.uid===0&&!(s.mode&0o022)&&s.size<=4096,'unsafe_health_file');
  const c=validateRelayHealth(JSON.parse(fs.readFileSync(file)),relay);
  if(c.ca){const s=fs.lstatSync(c.ca);assert.ok(s.isFile()&&s.uid===0&&!(s.mode&0o022)&&s.size<=65536,'unsafe_health_CA');}
  return c;
}
export function relayHttpsProbe(c,source){
  assert.ok(isIPv4(source)&&/^10\.99\.0\./.test(source),'health_source_required');
  return new Promise((resolve,reject)=>{
    let finished=false,bytes=0;const hash=createHash('sha256');
    const done=error=>{if(finished)return;finished=true;clearTimeout(timer);error?reject(error):resolve();};
    const req=https.get({host:c.ipv4,port:443,path:c.path,localAddress:source,
      servername:c.server_name,headers:{host:c.server_name},ca:c.ca?fs.readFileSync(c.ca):undefined,
      agent:false,rejectUnauthorized:true},res=>{
      if(res.statusCode!==200){req.destroy();return done(Error('relay_health_status'));}
      res.on('data',b=>{bytes+=b.length;if(bytes>16384){req.destroy();done(Error('relay_health_size'));}else hash.update(b);});
      res.on('aborted',()=>done(Error('relay_health_aborted')));res.on('error',done);
      res.on('end',()=>done(hash.digest('hex')===c.sha256?null:Error('relay_health_body')));
    });
    const timer=setTimeout(()=>{req.destroy();done(Error('relay_health_deadline'));},4000);
    req.on('error',done);
  });
}
