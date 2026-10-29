#!/usr/bin/env node
// Explicit offline preparation, never deployment or automatic CA rotation.
import {parseArgs} from 'node:util';
import {prepareCertificateRenewal} from './lib/native-certificate-renewal.mjs';
try{
 const {values:v}=parseArgs({options:Object.fromEntries(['config','ca-cert','ca-key','trust','server-name','output','engine','days'].map(k=>[k,{type:'string'}]))});
 const result=prepareCertificateRenewal({config:v.config,caCert:v['ca-cert'],caKey:v['ca-key'],trust:v.trust,serverName:v['server-name'],output:v.output,engine:v.engine,days:v.days});console.log(JSON.stringify(result,null,2));
}catch(e){const message=/^[A-Za-z0-9_ -]{1,100}$/.test(e?.message??'')?e.message:'certificate_preparation_failed';console.error(JSON.stringify({kind:'native-certificate-renewal',status:'failed',error:message}));process.exitCode=1;}
