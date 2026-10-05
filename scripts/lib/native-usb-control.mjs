/** Native M1 control-plane owner. Never opens a packet or DNS socket. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { openHostRoutes } from './vpn-host-routes.mjs';
import { openTunnelDnsJournal } from './dns-tunnel-journal.mjs';
import { watchVpnUplink } from './vpn-uplink-watch.mjs';
const run=(file,args)=>execFileSync(file,args,{encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
export function prepareNativeUsb(config){
  assert.equal(process.getuid(),0);assert.equal(config.role,'client');assert.equal(config.tun,'tun0');
  assert.equal(config.address,'154.62.226.216');assert.equal(config.dns,true);
  const guard=run('/usr/local/bin/clean-vpn-killswitch.sh',['status']);
  for(const family of [4,6])assert.ok(guard.includes(`IPv${family}: cvks4:both:block:tun0:154.62.226.216:22`));
  const links=JSON.parse(run('ip',['-j','address','show']));
  const usb=links.find(l=>l.ifname==='usb0'),tun=links.find(l=>l.ifname==='tun0');
  assert.ok(usb?.flags.includes('UP')&&usb.address==='02:00:00:00:00:02'&&usb.addr_info.some(a=>a.local==='192.168.7.1'&&a.prefixlen===24));
  assert.ok(tun?.flags.includes('UP')&&tun.mtu===1400&&tun.addr_info.some(a=>a.local==='10.99.0.2'));
  const defaults=JSON.parse(run('ip',['-j','-4','route','show','default']));
  assert.equal(defaults.length,1);const {dev,gateway}=defaults[0];assert.equal(dev,'wlan0');assert.ok(gateway);
  const host=openHostRoutes();let dns,watch,active=false,prepared=false,closed=false,faulted=false;
  try{
    host.assertAvailable();dns=openTunnelDnsJournal();
    dns.prepareRestart({lanSubnet:'192.168.7.0/24',lanInterface:'usb0'});
    host.begin('tun0');host.relaxRpFilter();
  }catch(e){dns?.release();host.release();throw e;}
  return {
    attach(engine){
      engine.on('status',status=>{
        if(closed||faulted)return;
        try{
          // The first event is emitted after native TUN/listeners are attached.
          // Before that, persistent TUN routes carry linkdown and cannot pass
          // the existing strict ownership audit. No audit is weakened here.
          if(!prepared){
            host.add(config.address+'/32',dev,gateway);
            for(const destination of ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'])host.add(destination,dev,gateway);
            for(const destination of ['0.0.0.0/1','128.0.0.0/1'])host.add(destination,'tun0');
            console.error('native-control: owned routes ready');
            dns.begin({tun:'tun0',lanSubnet:'192.168.7.0/24',lanInterface:'usb0'});dns.applyStage('guard');dns.applyStage('route');
            console.error('native-control: DNS guard/routes ready');
            prepared=true;
            watch=watchVpnUplink({repair:()=>host.repairUplink(dev,gateway,config.address),
              disconnect:()=>engine.uplink(false),reconnect:()=>engine.uplink(true),log:()=>{}});
          }
          if(status.state==='ready'&&!active){dns.applyStage('activate');dns.activate();active=true;console.error('native-control: DNS active');}
        }
        catch{faulted=true;engine.emit('fault',{reason:'native_dns_activation_failed'});engine.stop();}
      });
    },
    close({restore=false}={}){
      if(closed)return;closed=true;watch?.stop();
      // Only explicit graceful shutdown restores OWNED routes/DNS, while the
      // independent cvks4 guard and USB admin interface stay in place.
      try{if(restore){dns.restore();host.restore();}}finally{dns.release();host.release();}
    }
  };
}
