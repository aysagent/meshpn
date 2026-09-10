import os from 'node:os';
import http from 'node:http';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { spawn } from 'node:child_process';
import { command, checked, quote, remoteServer, macRoute, sameSubnet } from './perf-lib.mjs';

export function requestBoard(endpoint, resource, {token,password,signal,ca,insecure=false}={}) {
  return new Promise((resolve,reject)=>{
    const body=password===undefined?null:JSON.stringify({password});
    const secure=endpoint.protocol==='https:';
    const req=(secure?https:http).request({hostname:endpoint.gateway,port:endpoint.port||(secure?443:80),
      path:resource,method:body?'POST':'GET',localAddress:endpoint.address,agent:false,
      servername:'meshpn.local',rejectUnauthorized:!insecure,ca,signal,
      headers:{Host:'meshpn.local',...(token?{Authorization:`Bearer ${token}`} : {}),
        ...(body?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}:{})}},res=>{
      let text='';res.setEncoding('utf8');
      res.on('data',b=>{text+=b;if(text.length>512*1024)req.destroy(Error('Oversized board response'));});
      res.on('end',()=>resolve({code:res.statusCode,text,location:res.headers.location}));
      res.on('error',reject);
    });
    // Total deadline, not just socket inactivity (CPU/network overload must not stall the run).
    const timer=setTimeout(()=>req.destroy(Error('Board API timeout')),3500);
    req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(body);
  });
}

export async function discoverBoard(o, signal, log, {networkInterfaces=os.networkInterfaces,run=command,request=requestBoard}={}) {
  const ca=o.adminCA?await readFile(o.adminCA):undefined;
  const auth={ca,insecure:o.adminInsecure,signal};
  let explicit;
  if(o.adminURL) {
    explicit=new URL(o.adminURL);
    if(!['http:','https:'].includes(explicit.protocol)||isIP(explicit.hostname)!==4||explicit.username||explicit.password||explicit.pathname!=='/'||explicit.search||explicit.hash)
      throw Error('--admin-url must be http(s)://BOARD-IPv4[:port]/ (no credentials)');
  }
  const candidates=[];
  for(const [iface,addresses] of Object.entries(networkInterfaces())) {
    for(const a of addresses||[]) {
      if(a.internal||!(a.family==='IPv4'||a.family===4))continue;
      const dhcp=await run('/usr/sbin/ipconfig',['getoption',iface,'router'],{signal});
      let gateway=dhcp.stdout.trim().split(/\s+/)[0];
      // Explicit URL also supports static addressing; DHCP remains the source for other interfaces.
      if(explicit&&sameSubnet(a.address,explicit.hostname,a.netmask))gateway=explicit.hostname;
      if(!sameSubnet(a.address,gateway,a.netmask)||gateway===a.address)continue;
      if(candidates.some(c=>c.iface===iface&&c.gateway===gateway))continue;
      const c={iface,address:a.address,gateway,protocol:explicit?.hostname===gateway?explicit.protocol:'http:',
        port:explicit?.hostname===gateway?(explicit.port||undefined):undefined};
      candidates.push(c);
    }
  }
  const found=[],errors=[];
  for(const c of candidates) {
    try {
      let r=await request(c,'/login',auth);
      if([301,302,307,308].includes(r.code)&&r.location?.startsWith('https://')) {
        // Never follow a redirect to an arbitrary host with credentials.
        const redirect=new URL(r.location);
        if(!['meshpn.local',c.gateway].includes(redirect.hostname))throw Error('Unexpected HTTPS redirect');
        c.protocol='https:';c.port=redirect.port||443;
        r=await request(c,'/login',auth);
      }
      if(r.code===200&&/<title>MeshPN(?:[^<]*)<\/title>/i.test(r.text))found.push(c);
      else errors.push(`${c.iface}/${c.gateway}: HTTP ${r.code}, not a MeshPN login page`);
    } catch(e) {errors.push(`${c.iface}/${c.gateway}: ${e.message}`);}
  }
  if(!found.length)throw Error(`MeshPN admin not found on DHCP gateways. Check USB/AP and macOS Local Network permission. For static IP use --admin-url http://BOARD-IP/. For HTTPS use --admin-ca cert.pem (or explicitly --admin-insecure). ${errors.join('; ')}`);
  const password=process.env.MESHPN_ADMIN_PASSWORD??'admin';
  let endpoint=found[0],token;
  async function login() {
    const r=await request(endpoint,'/api/login',{...auth,password});
    if(r.code!==200)throw Error(`Admin login HTTP ${r.code}; set MESHPN_ADMIN_PASSWORD. Close the admin browser tab.`);
    const data=JSON.parse(r.text);
    if(!data.token)throw Error('Admin did not return a session token');
    if(data.must_change_password)throw Error('Firmware requires admin password change; change it or disable that configuration for testing.');
    token=data.token;
  }
  await login();
  async function status(c=endpoint, reauth=true) {
    let r=await request(c,'/api/status',{...auth,token});
    if(r.code===401&&reauth){await login();r=await request(c,'/api/status',{...auth,token});}
    if(r.code!==200)throw Error(`Admin status HTTP ${r.code} via ${c.iface}`);
    const s=JSON.parse(r.text);
    if(!s.net||!s.wifi||!Number.isFinite(s.uptime_sec))throw Error('Unexpected status schema');
    return s;
  }
  const initial=await status(),paths=[];
  for(const c of found) {
    const kind=c.gateway===initial.net.usb_ip?'usb':c.gateway===initial.net.ap_ip?'ap':null;
    if(!kind)continue;
    // A shared session proves both endpoints belong to the same board; no second login.
    await status(c,false);
    if(paths.some(p=>p.kind===kind))throw Error(`Ambiguous ${kind} interfaces; disconnect the extra adapter.`);
    paths.push({...c,kind});
  }
  paths.sort((a,b)=>a.kind==='usb'?-1:b.kind==='usb'?1:0);
  if(!initial.wifi.connected)throw Error('MeshPN STA has no uplink; connect it to the router first.');
  const selected=o.paths==='auto'||o.paths==='both'?paths:paths.filter(p=>p.kind===o.paths);
  if(!selected.length||(o.paths==='both'&&selected.length!==2)) {
    const diagnostics={candidates,errors,detectedPaths:paths};
    const e=Error(`Requested paths=${o.paths}, found: ${paths.map(p=>p.kind).join(', ')||'none'}. `+
      `Connect USB and connect Mac Wi-Fi to the board AP ${JSON.stringify(initial.net.ap_ssid||'MeshPN_*')} `+
      `(gateway ${initial.net.ap_ip||'unknown'}, active=${Boolean(initial.net.ap_active)}), not to the home router. `+
      `The board's STA uplink is not a Mac AP connection. For USB-only tests use --paths usb. `+
      `Probed gateways: ${candidates.map(c=>`${c.iface}: ${c.address} → ${c.gateway}`).join('; ')||'none'}. `+
      (errors.length?`Probe failures: ${errors.join('; ')}. Check routes/VPN and macOS Local Network permission if already connected to the board AP.`:''));
    e.boardInitial=initial;e.discovery=diagnostics;
    throw e;
  }
  for(const p of selected) {
    if(!initial.net[`${p.kind}_napt`]||(p.kind==='usb'&&!initial.usb?.host_ready)||(p.kind==='ap'&&!initial.net.ap_active))
      throw Error(`${p.kind}: interface/NAT not ready`);
  }
  endpoint=paths.find(p=>p.kind==='usb')||selected[0];
  if(endpoint.protocol==='http:')log('Admin uses HTTP (firmware setting); credentials cross the local link unencrypted.');
  // Serialize API readers, including reauthentication after a reboot.
  let pending=Promise.resolve();
  const serializedStatus=()=>{const next=pending.then(()=>status());pending=next.catch(()=>{});return next;};
  return {paths:selected,status:serializedStatus,initial,endpoint};
}

export async function checkRoute(path, server, signal, {run=checked,networkInterfaces=os.networkInterfaces}={}) {
  const raw=await run('/sbin/route',['-n','get','-ifscope',path.iface,server],{signal});
  const r=macRoute(raw);
  if(r.iface!==path.iface||r.gateway!==path.gateway)
    throw Error(`${path.kind}: route to ${server} is ${r.iface}/${r.gateway}, expected ${path.iface}/${path.gateway}. Refusing a possible bypass measurement; disable other VPNs and check DHCP/routes.`);
  const current=networkInterfaces()[path.iface]||[];
  if(!current.some(a=>a.address===path.address))throw Error(`${path.kind}: local IP changed or interface disconnected`);
  return raw;
}

export function sshArgs(o) {
  return ['-T','-p',String(o.sshPort),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
    '-o','ConnectTimeout=10','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3',
    '-o','ControlMaster=no','-o','ControlPath=none',o.sshTarget];
}

export async function startServers(o, count, signal) {
  const ports=Array.from({length:count},(_,i)=>o.iperfPort+i);
  const p=spawn('ssh',[...sshArgs(o),`python3 -u -c ${quote(remoteServer)} ${ports.join(' ')}`],{stdio:['pipe','pipe','pipe']});
  let output='',stderr='',closed=false,code,spawnError;
  const finished=new Promise(resolve=>{
    p.on('error',e=>{spawnError=e;});
    p.on('close',c=>{closed=true;code=c;resolve();});
  });
  p.stdout.on('data',b=>{output=(output+b).slice(-8192);});
  p.stderr.on('data',b=>{stderr=(stderr+b).slice(-16384);});
  p.stdin.on('error',()=>{});
  const heartbeat=setInterval(()=>{if(!closed&&!p.stdin.destroyed)p.stdin.write('heartbeat\n');},5000);
  const stop=()=>{clearInterval(heartbeat);p.stdin.end();};
  signal.addEventListener('abort',stop,{once:true});
  const close=async()=>{
    stop();
    let timer;
    await Promise.race([finished,new Promise(resolve=>{timer=setTimeout(resolve,6000);})]);clearTimeout(timer);
    if(!closed){p.kill('SIGTERM');await new Promise(resolve=>{timer=setTimeout(resolve,1000);});clearTimeout(timer);}
    if(!closed)p.kill('SIGKILL');
    await finished;signal.removeEventListener('abort',stop);
  };
  try {
    const deadline=Date.now()+20000;
    while(!output.includes('MESHPN_READY')) {
      if(signal.aborted)throw Error('Interrupted');
      if(closed)throw Error(`SSH iperf3 server failed (${code}): ${spawnError?.message||stderr}`);
      if(Date.now()>deadline)throw Error('SSH iperf3 server readiness timeout');
      await new Promise(resolve=>setTimeout(resolve,50));
    }
  } catch(e){await close();throw e;}
  return {ports,close,assertAlive:()=>{if(closed)throw Error(`SSH server session lost (${code}): ${stderr}`);}};
}
