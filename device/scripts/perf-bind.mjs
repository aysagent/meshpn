import path from 'node:path';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { checked } from './perf-lib.mjs';

export async function macosBuildContext(signal,{run=checked,checkAccess=access}={}) {
  // Do not let an inherited iOS/stale SDKROOT select the host helper's SDK.
  // Keep DEVELOPER_DIR: the user's active Xcode/CLT selection remains authoritative.
  const env={...process.env};delete env.SDKROOT;
  let compiler;
  try {compiler=(await run('/usr/bin/xcrun',['--sdk','macosx','--find','clang'],{signal,env})).trim();}
  catch(e) {
    if(signal?.aborted)throw e;
    throw Error(`macOS interface binding needs Apple Command Line Tools. Install once: xcode-select --install. ${e.message}`);
  }
  if(!path.isAbsolute(compiler))throw Error('xcrun did not return an absolute clang path. Check xcode-select --install');
  let sdk;
  try {
    sdk=(await run('/usr/bin/xcrun',['--sdk','macosx','--show-sdk-path'],{signal,env})).trim();
    if(!path.isAbsolute(sdk))throw Error('xcrun did not return an absolute macOS SDK path');
    await checkAccess(path.join(sdk,'usr/include/sys/socket.h'),constants.R_OK);
  }catch(e) {
    if(signal?.aborted)throw e;
    throw Error(`macOS SDK unavailable/incomplete${sdk?` (${sdk})`:''}: ${e.message}. `+
      'Check xcode-select -p and xcrun --sdk macosx --show-sdk-path; install/update Apple Command Line Tools or select a complete Xcode installation. No system settings were changed.');
  }
  return {compiler,sdk,env:{...env,SDKROOT:sdk}};
}

export async function prepareIperfBinding(output,signal,deps={}) {
  const library=path.join(output,'iperf-bind.dylib');
  if(library.includes(':'))throw Error('Performance output path cannot contain a colon (DYLD library path separator).');
  const {compiler,sdk,env}=await macosBuildContext(signal,deps);
  await (deps.run||checked)(compiler,['-isysroot',sdk,'-dynamiclib','-O2','-Wall','-Wextra','-Werror','-arch','arm64','-arch','x86_64',
    fileURLToPath(new URL('./perf-bind-darwin.c',import.meta.url)),'-o',library],{signal,env,timeout:60000});
  return library;
}
export function iperfEnvironment(library,iface) {
  if(!library||!/^en\d+$/.test(iface))throw Error('Missing binding helper or unexpected macOS Ethernet interface');
  return {...process.env,DYLD_INSERT_LIBRARIES:library,MESHPN_IPERF_IFACE:iface};
}
export function verifyIperfBinding(stderr,iface) {
  if(!stderr.split(/\r?\n/).includes(`MESHPN_BOUND_IF=${iface}`))
    throw Error('macOS IP_BOUND_IF helper did not run; refusing an unverified data path. Use a native Homebrew iperf3 executable (not a wrapper or hardened binary).');
}
export function iperfError(raw) {
  let message;
  try {message=JSON.parse(raw.stdout).error;} catch {}
  return message||raw.stderr.split(/\r?\n/).filter(s=>!s.startsWith('MESHPN_BOUND_IF=')).join('\n').trim()||'see raw JSON';
}
