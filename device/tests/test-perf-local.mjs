import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp,readdir,readFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { downloadBoard,localDownloadBytes,discoverBoard,checkLocalRoute } from '../scripts/perf-network.mjs';
import { parseLocalArgs,main } from '../scripts/perf-local.mjs';

const usb={kind:'usb',iface:'en7',address:'192.168.7.2',gateway:'192.168.7.1',protocol:'http:'};
const interfaces=()=>({en7:[{family:'IPv4',address:usb.address,netmask:'255.255.255.0'}]});
const status=()=>({build:'test',uptime_sec:100,wifi:{connected:false},net:{usb_ip:usb.gateway,usb_napt:false},
  usb:{host_ready:true,tx_ok:0,ncm:{ntb_completed:0},tx_queue:{full:0}},secret:'must-not-save'});

test('local options cannot accidentally select WAN/AP or unbounded repetitions',()=>{
  assert.equal(parseLocalArgs([]).startDelay,60);
  for(const args of [['server'],['--paths','ap'],['--runs','0'],['--runs','21'],['--start-delay','601'],['--out']])
    assert.throws(()=>parseLocalArgs(args));
});
test('local discovery allows no uplink/NAT, WAN discovery still rejects it',async()=>{
  const deps={networkInterfaces:interfaces,run:async()=>({code:0,stdout:usb.gateway}),
    request:async(c,url)=>url==='/login'?{code:200,text:'<title>MeshPN</title>'}:
      {code:200,text:JSON.stringify(url==='/api/login'?{token:'private'}:status())}};
  const board=await discoverBoard(parseLocalArgs([]),undefined,()=>{},deps);
  assert.equal(board.paths[0].kind,'usb');assert.equal(typeof board.download,'function');
  await assert.rejects(discoverBoard({paths:'usb'},undefined,()=>{},deps),/no uplink/);
});
test('local route accepts direct link gateway, refuses wrong interface/source',async()=>{
  const deps={run:async()=> 'gateway: link#20\ninterface: en7\n',networkInterfaces:interfaces};
  await checkLocalRoute(usb,undefined,deps);
  await assert.rejects(checkLocalRoute(usb,undefined,{...deps,networkInterfaces:()=>({})}),/changed/);
  await assert.rejects(checkLocalRoute(usb,undefined,{...deps,run:async()=> 'interface: en0\n'}),/changed/);
});

async function withServer(fn,check) {
  const server=http.createServer(fn);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {await check({address:'127.0.0.1',gateway:'127.0.0.1',protocol:'http:',port:server.address().port});}
  finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}
function headers(res) {res.writeHead(200,{'Content-Type':'application/octet-stream','X-MeshPN-Download-Bytes':String(localDownloadBytes)});}
test('streaming receiver counts exactly 8MiB, sends authenticated empty POST',async()=>{
  await withServer((req,res)=>{
    assert.equal(req.method,'POST');assert.equal(req.url,'/api/diag/usb-download');
    assert.equal(req.headers.authorization,'Bearer private');assert.equal(req.headers['content-length'],'0');
    headers(res);res.end(Buffer.alloc(localDownloadBytes));
  },async endpoint=>{
    const r=await downloadBoard(endpoint,{token:'private'});
    assert.equal(r.bytes,localDownloadBytes);assert.ok(r.seconds>0&&r.receiver_mbps>0);
    assert.ok(!JSON.stringify(r).includes('private'));
  });
});
test('reject short, oversize, redirects, deadline and aborted streams',async()=>{
  for(const [handler,pattern] of [
    [(_,res)=>{headers(res);res.end('short');},/Incomplete/],
    [(_,res)=>{headers(res);res.end(Buffer.alloc(localDownloadBytes+1));},/Oversized/],
    [(_,res)=>{res.writeHead(302,{Location:'http://example.invalid/'});res.end();},/unexpected response/],
    [(_,res)=>{headers(res);res.write('x');},/deadline/],
    [(_,res)=>{headers(res);res.write('x');setTimeout(()=>res.destroy(),10);},/aborted|reset|hang up/]
  ]) await withServer(handler,endpoint=>assert.rejects(downloadBoard(endpoint,{timeout:150}),pattern));
  await withServer((_,res)=>{headers(res);res.write('x');},async endpoint=>{
    const controller=new AbortController();const pending=downloadBoard(endpoint,{signal:controller.signal});
    controller.abort();await assert.rejects(pending,/abort/i);
  });
});
test('runner excludes warmup, samples sequentially, persists safe results, stops on failure',async()=>{
  const parent=await mkdtemp(path.join(tmpdir(),'meshpn-local-test-'));
  try {
    let downloading=false,samples=0,downloads=0;
    const deps={log:()=>{},wait:async()=>{},command:async()=>({code:0,stdout:''}),checkLocalRoute:async()=>{},
      discoverBoard:async()=>({paths:[usb],initial:status(),status:async()=>{assert.equal(downloading,false);samples++;return status();},
        download:async()=>{downloading=true;downloads++;await Promise.resolve();downloading=false;
          return {bytes:localDownloadBytes,seconds:1,receiver_mbps:downloads===1?100:8};}})};
    assert.equal(await main(['--out',parent,'--start-delay','0'],deps),0);
    assert.equal(downloads,4);assert.equal(samples,8);
    const dir=(await readdir(parent))[0],raw=await readFile(path.join(parent,dir,'result.json'),'utf8'),r=JSON.parse(raw);
    assert.equal(r.receiver_mbps.median,8);assert.equal(r.receiver_mbps.count,3);assert.ok(!raw.includes('must-not-save'));
    const original=deps.discoverBoard;
    deps.discoverBoard=async()=>({...await original(),download:async()=>{throw Error('test failure');}});
    assert.equal(await main(['--out',parent,'--start-delay','0'],deps),1);
    assert.equal((await readdir(parent)).length,2);
  } finally {await rm(parent,{recursive:true,force:true});}
});
