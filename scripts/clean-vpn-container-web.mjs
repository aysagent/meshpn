#!/usr/bin/env node
// Frontend startup ordering only; the web process never controls containers.
import fs from 'node:fs';
import http from 'node:http';
import {setTimeout as delay} from 'node:timers/promises';
import {createAdmin} from '../admin/server.mjs';
const c=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
if(c.container!==true||c.address!=='127.0.0.1'||c.loopbackProxy!==true)throw Error('container_loopback_web_required');
async function available(){return await new Promise(resolve=>{const q=http.request({socketPath:c.brokerSocket,method:'POST',path:'/settings',headers:{'content-type':'application/json'}},r=>{r.resume();r.on('end',()=>resolve(r.statusCode===200));});q.setTimeout(1000,()=>q.destroy());q.on('error',()=>resolve(false));q.end('{}');});}
let ready=false;for(let i=0;i<120;i++){if(await available()){ready=true;break;}await delay(500);}
if(!ready)throw Error('container_broker_start_timeout');
const app=await createAdmin(c);app.server.listen(c.port,c.address);app.captureFront.listen(c.capturePort,c.address);
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>void app.close());
