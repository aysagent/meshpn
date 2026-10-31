// Select the real engine schema and matching network overlay. Preserve the
// inactive combo branch privately; public settings never return this document.
import {need} from './common.mjs';
import {validateNativeHostConfig} from '../../scripts/lib/native-host-network.mjs';
export function clientTransportPlan(raw, network, settings, transport, packet) {
 need(['boring-tls','combo-tls'].includes(transport),'client_transport');
 need(raw.role==='client'&&packet.role==='client','client_transport_role');
 const combo=raw.transport==='combo-tls'?raw:settings.inactiveCombo;
 need(combo?.transport==='combo-tls'&&combo.role==='client'&&combo.transparent?.role==='client','combo_configuration_unavailable',409);
 need(packet.address===combo.boring.address&&packet.port===combo.boring.port&&packet.secret_path===combo.boring.secret_path,'transport_identity_changed',409);
 const redirect=network.combo_redirect??settings.inactiveComboRedirect;
 need(redirect&&redirect.endpoint===packet.address&&redirect.listen_port===combo.transparent.listen.port,'transport_network_binding',409);
 need(network.exit_ip===packet.address,'transport_network_binding',409);
 const nextSettings={...settings,inactiveCombo:{...combo,boring:packet},inactiveComboRedirect:redirect};
 const nextNetwork={...network};
 let config;
 if(transport==='combo-tls'){
  need(packet.sni.toLowerCase()===combo.transparent.public_name.toLowerCase(),'combo_name_requires_exit_migration',409);
  config={...combo,boring:packet};nextNetwork.combo_redirect=redirect;
 }else{config={...packet};delete config.transport;delete nextNetwork.combo_redirect;}
 validateNativeHostConfig(nextNetwork);
 return {config,network:nextNetwork,settings:nextSettings};
}
