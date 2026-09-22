// Compare the firmware codec with production clean-vpn functions, not a
// reimplementation of them. This is wire compatibility, NOT a TUN/LAN test.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
const source = fs.readFileSync(new URL('../../scripts/clean-vpn.js', import.meta.url), 'utf8');
const argsStart = source.indexOf('function parseArgs(argv) {');
const argsEnd = source.indexOf('function parseHostPort(', argsStart);
assert(argsStart > 0 && argsEnd > argsStart);
const argsContext = vm.createContext({});
vm.runInContext(source.slice(argsStart, argsEnd) + ';globalThis.parseArgs=parseArgs;', argsContext);
assert.equal(argsContext.parseArgs(['--type=tcp']).type, 'tcp');
assert.equal(argsContext.parseArgs(['--type=socket']).type, 'tcp');
assert.equal(argsContext.parseArgs(['--type=tls', '--tls-raw']).tlsRaw, true);
assert.throws(() => argsContext.parseArgs(['--type=tls', '--tls-ra']), /Неизвестный параметр/);
const start = source.indexOf('const STREAM_FRAMER_CHUNK_MERGE_AFTER =');
const end = source.indexOf('/**\n * TCP-транспорт с опциональным батчем', start);
assert(start > 0 && end > start);
const context = vm.createContext({Buffer, MAX_PKT:65535});
vm.runInContext(source.slice(start,end)+';globalThis.codec={StreamFramer,encodeCleanVpnFramedPkt};', context);
const packet = Buffer.from('4500001c00010000400100000a6300020a6300010800000000010001','hex');
const input = Buffer.concat(Array.from({length:100},()=>context.codec.encodeCleanVpnFramedPkt(packet)));
const result = spawnSync(process.argv[2],['pipe'],{input});
assert.equal(result.status,0,String(result.stderr)); assert.deepEqual(result.stdout,input);
const framer = new context.codec.StreamFramer(); let seen=0;
for(let i=0;i<result.stdout.length;i+=3) framer.push(result.stdout.subarray(i,i+3),p=>{assert.deepEqual(p,packet);seen++;});
assert.equal(seen,100);
for(const bad of [Buffer.from([0,0,0,0]),Buffer.from([0,0,6,0]),input.subarray(0,31)])
  assert.notEqual(spawnSync(process.argv[2],['pipe'],{input:bad}).status,0);
console.log('Production clean-vpn JS ↔ firmware C framing compatibility passed');
