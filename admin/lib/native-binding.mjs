// Read an explicitly selected standalone host installation. Never infer a VPN
// from process argv, an old service, or files belonging to another instance.
import fs from 'node:fs';
import {readOwned,binaryDigest} from '../../scripts/lib/native-binary-update.mjs';
import {need} from './common.mjs';
export function nativeAdminBinding(name,{root=''}={}){
 need(typeof name==='string'&&/^[a-z][a-z0-9-]{0,31}$/.test(name),'native_install_name');
 const bundle='/opt/clean-vpn-native/'+name,at=p=>root+p;
 const manifest=JSON.parse(readOwned(at(bundle+'/installed.json')));
 need(manifest.schema===1&&manifest.name===name&&manifest.role==='client'&&['boring-tls','combo-tls'].includes(manifest.transport)&&
  manifest.unit===`native-${name}.service`&&manifest.networkUnit===`native-${name}-network.service`&&
  manifest.activation===manifest.networkUnit&&manifest.guardUnit==='clean-vpn-killswitch.service','native_host_install_required');
 const network=JSON.parse(readOwned(at(bundle+'/network.json'))),config=JSON.parse(readOwned(at(bundle+'/config.json')));
 const packet=config.transport==='combo-tls'?config.boring:config;
 need((config.transport??'boring-tls')===manifest.transport,'native_transport_binding');
 if(config.transport==='combo-tls')need(network.combo_redirect&&config.transparent?.role==='client'&&
  network.combo_redirect.endpoint===packet.address&&network.combo_redirect.listen_port===config.transparent.listen?.port&&
  config.transparent.exit?.ipv4===packet.address&&config.transparent.exit?.port===packet.port,'native_combo_binding');
 need(network.engine_unit===manifest.unit&&network.network_unit===manifest.networkUnit&&network.guard_unit===manifest.guardUnit&&
  network.guard_script==='/usr/local/bin/clean-vpn-killswitch.sh'&&network.exit_ip===packet.address,'native_host_binding');
 need(config.role==='client'&&packet.role==='client'&&packet.dns===true&&packet.tun==='tun0'&&(!packet.transport||packet.transport==='boring-tls'),'native_client_required');
 for(const [unit,file] of [[manifest.unit,'service.unit'],[manifest.networkUnit,'units/'+manifest.networkUnit]]){
  need(binaryDigest(readOwned(at('/etc/systemd/system/'+unit)))===manifest.files.find(f=>f.name===file)?.sha256,'native_unit_changed');
 }
 need(fs.statSync(at(bundle+'/engine')).isFile(),'native_engine_missing');
 return{bundle,vpnUnit:manifest.unit,networkUnit:manifest.networkUnit,guardUnit:manifest.guardUnit,
  guardScript:network.guard_script,engine:bundle+'/engine',vpnConfig:bundle+'/config.json',nativeManaged:true,config};
}
