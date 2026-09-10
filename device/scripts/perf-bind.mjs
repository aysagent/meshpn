import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checked } from './perf-lib.mjs';

export async function prepareIperfBinding(output,signal,{run=checked}={}) {
  const library=path.join(output,'iperf-bind.dylib');
  if(library.includes(':'))throw Error('Performance output path cannot contain a colon (DYLD library path separator).');
  let compiler;
  try {compiler=(await run('/usr/bin/xcrun',['--find','clang'],{signal})).trim();}
  catch {throw Error('macOS interface binding needs Apple Command Line Tools. Install once: xcode-select --install');}
  if(!compiler)throw Error('xcrun did not return a clang path. Check xcode-select --install');
  await run(compiler,['-dynamiclib','-O2','-Wall','-Wextra','-Werror','-arch','arm64','-arch','x86_64',
    fileURLToPath(new URL('./perf-bind-darwin.c',import.meta.url)),'-o',library],{signal,timeout:60000});
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
