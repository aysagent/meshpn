import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
const [server,client,run]=process.argv.slice(2);
if(!server||!client||!run)throw Error('Usage: test-compression.mjs SERVER CLIENT EXISTING_RUN');
const pki=path.join(run,'pki');let output='',errors='',resolveReady;
const ready=new Promise(r=>resolveReady=r);
const child=spawn(server,[path.join(pki,'valid.pem'),path.join(pki,'server.key')]);
child.stdout.on('data',b=>{output+=b;const m=output.match(/PORT (\d+)/);if(m)resolveReady(m[1]);});child.stderr.on('data',b=>errors+=b);
let timer=setTimeout(()=>{child.kill('SIGKILL');resolveReady(null);},20000);
const closed=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',code=>{clearTimeout(timer);resolveReady(null);resolve(code);});});
const exporters=[],gates=[];
try{
 const port=await ready;assert(port,'server did not listen: '+errors);
 for(let i=0;i<3;i++){
  const r=await new Promise((resolve,reject)=>{
   const c=spawn(client,['connect',port,path.join(pki,'ca.pem')]);let out='',err='';const timeout=setTimeout(()=>c.kill('SIGKILL'),10000);
   c.stdout.on('data',b=>out+=b);c.stderr.on('data',b=>err+=b);c.on('error',reject);c.on('close',code=>{clearTimeout(timeout);resolve({code,out,err});});
  });
  assert.equal(r.code,0,r.err);assert.match(r.err,/PROFILE_GATE hellos=1 match=1 /);
  exporters.push(r.out.trim().split(' ')[1]);gates.push(r.err.match(/PROFILE_GATE[^\n]*/)[0]);
 }
 assert.equal(await closed,0,errors);
 const replies=[...output.matchAll(/EXPORTER ([a-f0-9]{64}) compressed=(\d+) alps=1/g)];assert.equal(replies.length,3);
 replies.forEach((m,i)=>{assert.equal(m[1],exporters[i]);assert.equal(Number(m[2]),i+1);});
 assert.equal(new Set(exporters).size,3);
 const result={connections:3,certificate_compression:'brotli negotiated and decoded',alps:true,exporter_equal:true,gates};
 fs.writeFileSync(path.join(run,'compression-result.json'),JSON.stringify(result,null,2)+'\n');console.log(result);
}finally{child.kill();clearTimeout(timer);}
