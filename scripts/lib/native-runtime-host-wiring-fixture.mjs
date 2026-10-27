// Reference host-side wiring, ONLY in the disposable NIC-less QEMU fixture.
// Not a live-host installer. All operations are reconstructed from this code;
// the recovery journal contains a cursor/scope, never executable commands.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
const table = '19998', priority = '10998', chain = 'CVPN_HW', tag = 'cvpn-host-wiring-fixture';
const run = (bin,args) => execFileSync(bin,args,{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']}).trim();
const json = args => JSON.parse(run('ip',args));
const sameTable = r => String(r.table) === table;
const routeRows = () => json(['-j','-4','route','show','table','all']).filter(sameTable);
const route = (words, matches) => ({add:['ip',['-4','route','add',...words,'table',table]],
  del:['ip',['-4','route','del',...words,'table',table]],present:()=>routeRows().some(matches)});
const filter = (bin, hook, spec, first=false, nat=false) => {
  const base=['-w','5',...(nat?['-t','nat']:[])];
  return {add:[bin,[...base,first?'-I':'-A',hook,...(first?['1']:[]),...spec]],
    del:[bin,[...base,'-D',hook,...spec]],present:()=>{
      // A rule referring to our not-yet-created chain returns exit 2, not
      // "rule absent" (1). Inspect the chain inventory first; never turn
      // arbitrary iptables errors into successful absence checks.
      const inventory=run(bin,[...base,'-S']);
      if((hook===chain||spec.at(-1)===chain)&&!inventory.split('\n').includes('-N '+chain))return false;
      return exists(bin,[...base,'-C',hook,...spec]);
    }};
};
function exists(bin,args) {try {run(bin,args);return true;}catch(e){if(e.status===1)return false;throw e;}}
export function hostWiringOperations() {
  const comment=['-m','comment','--comment',tag], bypass=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'];
  return [
    {add:['iptables-nft',['-N',chain]],del:['iptables-nft',['-X',chain]],present:()=>exists('iptables-nft',['-S',chain])},
    filter('iptables-nft',chain,[...comment,'-j','DROP']),
    filter('iptables-nft','FORWARD',['-i','usb0',...comment,'-j',chain],true),
    filter('ip6tables-nft','FORWARD',['-i','usb0',...comment,'-j','DROP'],true),
    route(['unreachable','default','metric','32767'],r=>r.dst==='default'&&r.type==='unreachable'&&r.metric===32767),
    ...bypass.map(dst=>route(['throw',dst],r=>r.dst===dst&&r.type==='throw')),
    route(['default','via','192.168.88.2','dev','cvlbr0','metric','10'],r=>r.dst==='default'&&r.gateway==='192.168.88.2'&&r.dev==='cvlbr0'&&r.metric===10),
    {add:['ip',['-4','rule','add','priority',priority,'iif','usb0','lookup',table]],
      del:['ip',['-4','rule','del','priority',priority,'iif','usb0','lookup',table]],
      present:()=>json(['-j','-4','rule','show']).some(r=>Number(r.priority)===Number(priority)&&sameTable(r)&&(r.iif??r.iifname)==='usb0')},
    filter('iptables-nft','POSTROUTING',['-s','192.168.7.0/24','-o','cvlbr0',...comment,'-j','SNAT','--to-source','192.168.88.1'],true,true),
    ...bypass.map(dst=>filter('iptables-nft',chain,['-d',dst,...comment,'-j','RETURN'],true)),
    filter('iptables-nft','FORWARD',['-i','cvlbr0','-o','usb0','-m','conntrack','--ctstate','ESTABLISHED,RELATED',...comment,'-j','ACCEPT'],true),
    filter('iptables-nft',chain,['-o','cvlbr0',...comment,'-j','ACCEPT'],true),
    // Explicit ingress DNS, including queries addressed to the host's LAN IP.
    // Host OUTPUT/resolv.conf and non-selected interfaces remain untouched.
    ...['udp','tcp'].map(proto=>filter('iptables-nft','PREROUTING',['-i','usb0','-s','192.168.7.0/24','-p',proto,'--dport','53',...comment,'-j','DNAT','--to-destination','192.168.88.2:53'],true,true)),
  ];
}

function main() {
  assert.ok(fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.runtime-host-wiring=1'),'disposable_vm_only');
  assert.equal(process.getuid(),0);assert.ok(['apply','recover'].includes(process.argv[2]));
  const file='/run/cvpn-host-wiring.json',ops=hostWiringOperations();
  const scope={boot:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim(),net:fs.readlinkSync('/proc/self/ns/net')};
  const startTick=pid=>fs.readFileSync('/proc/'+pid+'/stat','utf8').split(') ').at(-1).split(' ')[19];
  const save=s=>{
    // A killed writer may leave its temporary file. A unique name keeps that
    // harmless orphan from preventing the next independent recovery write.
    const temporary=file+'.tmp-'+randomBytes(8).toString('hex');
    const fd=fs.openSync(temporary,'wx',0o600);
    try {
      fs.writeFileSync(fd,JSON.stringify(s));fs.fsyncSync(fd);
      if(process.argv[2]==='apply'&&Number(process.env.CVPN_WIRING_KILL_BEFORE_RENAME)===s.next)process.kill(process.pid,'SIGKILL');
      fs.renameSync(temporary,file);
      const directory=fs.openSync('/run','r');try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
    } finally {fs.closeSync(fd);fs.rmSync(temporary,{force:true});}
  };
  if(process.argv[2]==='apply') {
    assert.equal(fs.existsSync(file),false,'recover_previous_run_first');
    assert.equal(run('sysctl',['-n','net.ipv4.ip_forward']),'1','already_configured_gateway_required');
    for(const name of ['usb0','cvlbr0'])assert.ok(json(['-j','link','show','dev',name])[0].flags.includes('UP'));
    for(const name of ['usb0','cvlbr0'])assert.equal(run('sysctl',['-n',`net.ipv4.conf.${name}.rp_filter`]),'2','loose_reverse_path_precondition');
    assert.equal(routeRows().length,0,'reserved_table_busy');
    assert.ok(json(['-j','-4','rule','show']).every(r=>r.priority===0||r.priority>Number(priority)),'earlier_custom_policy_refused');
    assert.ok(ops.every(op=>!op.present()),'foreign_wiring_refused');
    const state={schema:1,scope,next:0,pid:process.pid,startTick:startTick(process.pid)};save(state);
    for(const [i,op]of ops.entries()) {
      state.next=i+1;save(state); // intent before mutation
      if(Number(process.env.CVPN_WIRING_KILL_AT)===i+1)process.kill(process.pid,'SIGKILL');
      run(...op.add);
      if(Number(process.env.CVPN_WIRING_KILL_AFTER_MUTATION)===i+1)process.kill(process.pid,'SIGKILL');
      assert.ok(op.present());
    }
    console.log('HOST_WIRING_READY');setInterval(()=>{},1000);
  } else {
    const st=fs.lstatSync(file);assert.ok(st.isFile()&&st.uid===0&&!(st.mode&0o077)&&st.size<4096);
    const state=JSON.parse(fs.readFileSync(file));assert.equal(state.schema,1);assert.deepEqual(state.scope,scope);
    assert.ok(Number.isInteger(state.next)&&state.next>=0&&state.next<=ops.length);
    let alive=false;try{alive=startTick(state.pid)===state.startTick;}catch(e){if(e.code!=='ENOENT')throw e;}
    assert.equal(alive,false,'live_owner_refused');
    while(state.next){const op=ops[state.next-1];if(op.present())run(...op.del);assert.equal(op.present(),false);state.next--;save(state);}
    fs.unlinkSync(file);console.log('HOST_WIRING_RESTORED');
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main();
