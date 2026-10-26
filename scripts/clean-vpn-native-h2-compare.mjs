#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { readCaptureFile } from './clean-vpn-native-browser-capture.mjs';
import { compareHttp2Captures } from './lib/http2-capture-compare.mjs';
export function main(args) {
  if(args.length!==2)throw Error('usage');
  const [browser,native]=args.map(file=>JSON.parse(readCaptureFile(file,2097152)));
  const result=compareHttp2Captures(browser,native);console.log(JSON.stringify(result,null,2));return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {main(process.argv.slice(2));}catch {console.error('Usage: node scripts/clean-vpn-native-h2-compare.mjs BROWSER.json NATIVE.json (bounded capture bundles; no profile activation)');process.exitCode=1;}
}
