import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {once} from 'node:events';
import {brokerStartupSettings} from '../lib/broker-startup.mjs';
import {brokerRequest} from '../server.mjs';

test('startup waits for an actual delayed broker socket',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mpn-start-')),socket=dir+'/b.sock';
 const server=http.createServer((req,res)=>{assert.equal(req.url,'/settings');res.end('{"hostname":"mpn"}');});
 t.after(async()=>{if(server.listening)await new Promise(r=>server.close(r));fs.rmSync(dir,{recursive:true,force:true});});
 let attempts=0;
 const pending=brokerStartupSettings(()=>{attempts++;return brokerRequest(socket,'/settings');},{timeoutMs:1000,intervalMs:10});
 await new Promise(r=>setTimeout(r,50));server.listen(socket);await once(server,'listening');
 assert.deepEqual(await pending,{hostname:'mpn'});assert(attempts>1);
});
test('connection refusal retries, persistent absence has a finite deadline',async()=>{
 let count=0;
 assert.deepEqual(await brokerStartupSettings(async()=>{if(++count<3)throw Object.assign(Error('refused'),{code:'ECONNREFUSED'});return {hostname:'ok'};},{intervalMs:1}),{hostname:'ok'});
 const start=performance.now();
 await assert.rejects(brokerStartupSettings(async()=>{throw Object.assign(Error('missing'),{code:'ENOENT'});},{timeoutMs:30,intervalMs:5}),/broker_startup_unavailable/);
 assert(performance.now()-start<1000);
});
test('invalid responses, permission errors and broker timeouts fail without retry',async()=>{
 for(const error of [Error('broker_timeout'),Error('invalid_config'),new SyntaxError('bad JSON'),Object.assign(Error('denied'),{code:'EACCES'})]){
  let count=0;await assert.rejects(brokerStartupSettings(async()=>{count++;throw error;}),e=>e===error);assert.equal(count,1);
 }
});
