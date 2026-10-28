// Disposable Linux fixture only; called after the container identity checks.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
export function checkUsbProxy() {
  assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab','utf8'),'isolated-admin-lab-v1\n');
  const run=(file,args)=>execFileSync(file,args,{encoding:'utf8',timeout:10000}).trim();
  const ip=(...args)=>args[0]==='netns'&&args[1]==='exec' ?
    run('/usr/bin/nsenter',['--net=/run/netns/'+args[2],'--',...args.slice(3)]) : args[0]==='-n' ?
    run('/usr/bin/nsenter',['--net=/run/netns/'+args[1],'--','/usr/bin/ip',...args.slice(2)]) : run('/usr/bin/ip',args);
  for(const [ns,dev,subnet] of [['adminusb','usb0','192.168.7'],['adminwan','wan0','192.0.8']]) {
    ip('netns','add',ns); ip('link','add',dev,'type','veth','peer','name',dev+'peer');
    ip('link','set',dev+'peer','netns',ns); ip('addr','add',subnet+'.1/24','dev',dev); ip('link','set',dev,'up');
    ip('-n',ns,'link','set','lo','up'); ip('-n',ns,'addr','add',subnet+'.2/24','dev',dev+'peer');
    ip('-n',ns,'link','set',dev+'peer','up'); ip('-n',ns,'route','add','default','via',subnet+'.1');
  }
  fs.writeFileSync('/etc/systemd/system/admin-lab-proxy.socket',`[Unit]
DefaultDependencies=no
[Socket]
ListenStream=192.168.7.1:80
ListenStream=192.168.7.1:8443
BindToDevice=usb0
FreeBind=yes
Service=admin-lab-proxy.service
`);
  fs.writeFileSync('/etc/systemd/system/admin-lab-proxy.service',`[Unit]
DefaultDependencies=no
[Service]
User=65534
Group=65534
NoNewPrivileges=yes
CapabilityBoundingSet=
ExecStart=/usr/bin/node /project/admin/socket-proxy.mjs
`);
  run('/usr/bin/systemctl',['daemon-reload']); run('/usr/bin/systemctl',['start','admin-lab-proxy.socket']);
  const request=(namespace,host,port=80)=>ip('netns','exec',namespace,'/usr/bin/node','--input-type=module','-e',
    `import{fixtureFetch}from'/project/admin/test/http-fixture.mjs';try {const r=await fixtureFetch('http://192.168.7.1:${port}/',{headers:{host:${JSON.stringify(host)}},timeoutMs:2000});console.log(r.status);}catch{console.log('blocked');}`);
  assert.equal(request('adminusb','mpn.local'),'200');
  assert.equal(request('adminusb','evil.example'),'403');
  assert.equal(request('adminwan','mpn.local'),'blocked');
  assert.equal(request('adminusb','mpn.local',8080),'blocked');
  run('/usr/bin/systemctl',['stop','admin-lab-proxy.socket','admin-lab-proxy.service']);
  for(const ns of ['adminusb','adminwan'])ip('netns','del',ns);
  console.log('NATIVE_ADMIN_USB_PROXY_PASS');
}
