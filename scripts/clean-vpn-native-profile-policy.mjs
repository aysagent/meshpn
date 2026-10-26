#!/usr/bin/env node
import {pathToFileURL} from 'node:url';
import {readCaptureFile} from './clean-vpn-native-browser-capture.mjs';
import {assessNativeProfilePolicy} from './lib/native-profile-policy.mjs';
export function main(args) {
  if(args.length!==3)throw Error('usage');
  const [browser,capabilities,native]=args.map((file,i)=>JSON.parse(readCaptureFile(file,i===1?65536:2097152)));
  const report=assessNativeProfilePolicy(browser,capabilities,native);console.log(JSON.stringify(report,null,2));return report;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {main(process.argv.slice(2));}catch {console.error('Usage: node scripts/clean-vpn-native-profile-policy.mjs BROWSER.json ENGINE_CAPABILITIES.json NATIVE.json (verified capture bundles; read-only)');process.exitCode=1;}
}
