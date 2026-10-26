#!/usr/bin/env node
// Offline comparison of captured TLS record bytes, independently of the engine.
import fs from 'node:fs';
import { observeTlsProfile, compileTlsProfileCandidate } from './lib/native-tls-profile-observer.mjs';
try {
  const args=process.argv.slice(2);
  function read(file,limit) {
    const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    try {const st=fs.fstatSync(fd);if(!st.isFile()||st.size>limit)throw Error('file_limit');
      const bytes=Buffer.alloc(limit+1);let used=0,n;
      while((n=fs.readSync(fd,bytes,used,bytes.length-used,null))>0){used+=n;if(used>limit)throw Error('file_limit');}
      return bytes.subarray(0,used);
    } finally {fs.closeSync(fd);}
  }
  let report;
  if(args[0]==='--candidate'&&args.length===6) {
    const [,id,extensionOrder,padding,echMode,recordsPath]=args;
    report=compileTlsProfileCandidate(read(recordsPath,65536),{id,extensionOrder,padding,echMode});
  } else {
    if(args.length!==2)throw Error('usage');
    const profile=JSON.parse(read(args[0],16384));
    report=observeTlsProfile(read(args[1],65536),profile);
  }
  console.log(JSON.stringify(report,null,2));process.exitCode=['matched','candidate'].includes(report.status)?0:2;
} catch {
  console.error('Expected: node scripts/clean-vpn-native-profile-observe.mjs PROFILE.json TLS_RECORDS.bin (bounded regular files; not pcap)');
  console.error('Or: --candidate ID fixed|permuted exact|optional disabled|grease TLS_RECORDS.bin');
  process.exitCode=1;
}
