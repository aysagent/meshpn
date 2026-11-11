// Run ONLY inside a disposable privileged Linux container with --network none.
// Takes the CIDRs emitted by android/test-fixtures/RoutePlan.java, not a copy
// of the production algorithm. All routes live in two temporary namespaces.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {execFileSync,spawn} from 'node:child_process';
import {once} from 'node:events';

assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
assert.equal(process.env.CVPN_ISOLATED_LAB,'1','disposable isolated container required');
const routes=fs.readFileSync(process.argv[2],'utf8').trim().split('\n');
assert.equal(routes.length,32);
for(const route of routes)assert.match(route,/^\d+\.\d+\.\d+\.\d+\/(?:[1-9]|[12]\d|3[0-2])$/);
const client=`cvpn-ac-${process.pid}`,exit=`cvpn-ae-${process.pid}`;
const endpoint='84.201.14.124',port=24443;
const run=(...args)=>execFileSync('ip',args,{encoding:'utf8',timeout:5000,stdio:['ignore','pipe','pipe']});
const ip=(ns,...args)=>run('-n',ns,...args);
const routeTo=address=>JSON.parse(ip(client,'-j','route','get',address))[0];
const created=[];let server;
const probe=source=>JSON.parse(execFileSync('ip',['netns','exec',client,process.execPath,'-e',`
 const net=require('node:net');let finished=false;
 const s=net.createConnection({host:'${endpoint}',port:${port},${source?"localAddress:'192.0.2.2',":''}});
 const timer=setTimeout(()=>finish('timeout'),700);
 function finish(status){if(finished)return;finished=true;clearTimeout(timer);console.log(JSON.stringify({status,source:s.localAddress??null}));s.destroy();}
 s.on('connect',()=>finish('connected'));s.on('error',()=>finish('error'));
`],{encoding:'utf8',timeout:3000}));
try{
    for(const ns of [client,exit]){run('netns','add',ns);created.push(ns);ip(ns,'link','set','lo','up');}
    run('link','add','ac0','type','veth','peer','name','ae0');
    run('link','set','ac0','netns',client);run('link','set','ae0','netns',exit);
    ip(client,'addr','add','192.0.2.2/24','dev','ac0');ip(client,'link','set','ac0','up');
    ip(exit,'addr','add','192.0.2.1/24','dev','ae0');ip(exit,'link','set','ae0','up');
    ip(exit,'addr','add',`${endpoint}/32`,'dev','lo');
    ip(client,'route','add','default','via','192.0.2.1','dev','ac0');
    ip(client,'link','add','tun0','type','dummy');ip(client,'addr','add','10.99.0.5/32','dev','tun0');ip(client,'link','set','tun0','up');
    ip(client,'rule','add','priority','100','lookup','200');
    ip(client,'route','add','table','200','default','dev','tun0');
    server=spawn('ip',['netns','exec',exit,process.execPath,'-e',`
        require('node:net').createServer(s=>s.end('ok')).listen(${port},'${endpoint}',()=>console.log('ready'));
    `],{stdio:['ignore','pipe','pipe']});
    let startupTimer;
    try{
        await Promise.race([once(server.stdout,'data'),once(server,'exit').then(()=>{throw Error('server exited');}),
            new Promise((_,reject)=>{startupTimer=setTimeout(()=>reject(Error('server startup timeout')),3000);})]);
    }finally{clearTimeout(startupTimer);}
    const beforeRoute=routeTo(endpoint),before=probe(false);
    assert.equal(beforeRoute.dev,'tun0');assert.equal(beforeRoute.prefsrc,'10.99.0.5');
    assert.equal(before.status,'timeout');assert.equal(before.source,'10.99.0.5');
    ip(client,'route','del','table','200','default','dev','tun0');
    for(const route of routes)ip(client,'route','add','table','200',route,'dev','tun0');
    const afterRoute=routeTo(endpoint),after=probe(false),bound=probe(true);
    assert.equal(afterRoute.dev,'ac0');assert.equal(afterRoute.prefsrc,'192.0.2.2');
    assert.deepEqual(after,{status:'connected',source:'192.0.2.2'});assert.deepEqual(bound,after);
    for(const address of ['1.1.1.1','8.8.8.8','84.201.14.123','84.201.14.125'])assert.equal(routeTo(address).dev,'tun0');
    console.log(JSON.stringify({test:'android-exit-route-kernel',before,after,bound,dnsAndExitNeighboursRemainInTun:true,externalNetwork:false}));
}finally{
    if(server&&server.exitCode===null){const done=once(server,'exit');server.kill('SIGKILL');await done;}
    for(const ns of created.reverse())try{run('netns','del',ns);}catch{}
}
