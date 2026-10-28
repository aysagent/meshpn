// Diagnostic for disposable container fixture; never prints settings/auth data.
import fs from 'node:fs';
import {brokerRequest} from '../server.mjs';
try {
  const config=JSON.parse(fs.readFileSync('/shared/web.json','utf8'));
  for(const file of ['/shared',config.state,'/shared/socket',config.brokerSocket]) {
    const s=fs.statSync(file);console.log(JSON.stringify({file,mode:(s.mode&0o777).toString(8),uid:s.uid,gid:s.gid,processUid:process.getuid(),processGid:process.getgid()}));
  }
  fs.accessSync(config.state,fs.constants.R_OK|fs.constants.W_OK);
  try{console.log('Frontend process label: '+fs.readFileSync('/proc/self/attr/current','utf8').replaceAll('\0',''));}catch{}
  console.log('UID mapping: '+fs.readFileSync('/proc/self/uid_map','utf8'));
  await brokerRequest(config.brokerSocket,'/settings',{});
  console.log('FRONTEND_BROKER_PREFLIGHT_OK');
} catch(e) {console.error(e.stack);process.exitCode=1;}
