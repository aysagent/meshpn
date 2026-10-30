// Keep ProtectSystem=strict: only the selected, verified native bundle is writable.
import {need} from './common.mjs';
export function brokerWritablePaths(c) {
 need(c.state==='/var/lib/meshpn-admin-broker'&&/^\/opt\/clean-vpn-native\/[a-z][a-z0-9-]{0,31}$/.test(c.bundle),'admin_native_write_binding');
 return `${c.state} ${c.bundle} /run/meshpn-admin -/run/clean-vpn-killswitch -/run/xtables.lock`;
}
export function upgradeBrokerUnit(text,c) {
 need(text.startsWith('# meshpn-admin-owned-v1\n'),'unit_changed');
 const lines=text.split('\n'),indices=lines.flatMap((l,i)=>l.startsWith('ReadWritePaths=')?[i]:[]);
 need(indices.length===1,'admin_broker_write_paths_changed');
 const before=lines[indices[0]].slice('ReadWritePaths='.length);
 const baseline='/var/lib/meshpn-admin-broker /run/meshpn-admin -/run/clean-vpn-killswitch -/run/xtables.lock';
 need(before===baseline||/^\/var\/lib\/meshpn-admin-broker \/opt\/clean-vpn-native\/[a-z][a-z0-9-]{0,31} \/run\/meshpn-admin -\/run\/clean-vpn-killswitch -\/run\/xtables.lock$/.test(before),'admin_broker_write_paths_changed');
 lines[indices[0]]='ReadWritePaths='+brokerWritablePaths(c);
 return lines.join('\n').replace('After=network.target avahi-daemon.service\n','After=network.target avahi-daemon.service clean-vpn-killswitch.service\n');
}
export function verifyLegacyBrokerBinding(text) {
 need(/^# clean-vpn-daily-native-binding\n\[Service\]\nReadWritePaths=\/opt\/clean-vpn-native\/[a-z][a-z0-9-]{0,31}\n$/.test(text),'admin_broker_binding_dropin_changed');
}
