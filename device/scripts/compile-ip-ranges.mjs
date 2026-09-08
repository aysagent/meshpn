#!/usr/bin/env node
// Compile one IPv4 CIDR/IP per line into a compact, sorted membership set.
// Disk header: "MPNIPV4\0", uint32 LE version=1, uint32 LE count;
// then count pairs of uint32 LE inclusive start/end. No routing action implied.
import fs from 'node:fs';
import readline from 'node:readline';
import {pathToFileURL} from 'node:url';

export function parseCIDR(text) {
  const parts = text.split('/');
  if (parts.length > 2 || !/^\d+\.\d+\.\d+\.\d+$/.test(parts[0])) throw Error('Invalid IPv4: '+text);
  const octets = parts[0].split('.').map(Number);
  if (octets.some(x=>x>255)) throw Error('Invalid octet: '+text);
  const prefix = parts.length === 1 ? 32 : /^\d+$/.test(parts[1]) ? Number(parts[1]) : -1;
  if (prefix < 0 || prefix > 32) throw Error('Invalid prefix: '+text);
  const ip = octets.reduce((a,b)=>a*256+b,0), size = 2 ** (32-prefix);
  const first = Math.floor(ip/size)*size;
  return [first,first+size-1];
}
export function mergeRanges(ranges) {
  const sorted=ranges.slice().sort((a,b)=>a[0]-b[0]||a[1]-b[1]), out=[];
  for (const [first,last] of sorted) {
    const prev=out.at(-1);
    if (prev && first<=prev[1]+1) prev[1]=Math.max(prev[1],last);
    else out.push([first,last]);
  }
  return out;
}
export function encodeRanges(ranges) {
  const out=Buffer.alloc(16+ranges.length*8);
  out.write('MPNIPV4\0',0,'ascii');out.writeUInt32LE(1,8);out.writeUInt32LE(ranges.length,12);
  ranges.forEach(([first,last],i)=>{out.writeUInt32LE(first,16+i*8);out.writeUInt32LE(last,20+i*8);});
  return out;
}
async function main() {
  const [input,output]=process.argv.slice(2);
  if (!input||!output) throw Error('Usage: node compile-ip-ranges.mjs input.cidrs output.bin (new file)');
  const ranges=[];let lineNo=0;
  for await(const raw of readline.createInterface({input:fs.createReadStream(input),crlfDelay:Infinity})) {
    lineNo++;const line=raw.replace(/#.*/,'').trim();if(!line)continue;
    try {ranges.push(parseCIDR(line));}catch(e){throw Error('Line '+lineNo+': '+e.message);}
  }
  const merged=mergeRanges(ranges), encoded=encodeRanges(merged);
  fs.writeFileSync(output,encoded,{flag:'wx'});
  console.log(JSON.stringify({source_cidrs:ranges.length,ranges:merged.length,bytes:encoded.length,
    mib:encoded.length/1048576,format:'MPNIPV4 v1; membership set, no policy priority'},null,2));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  main().catch(e=>{console.error(e.message);process.exitCode=1;});
}
