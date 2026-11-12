import test from 'node:test';
import assert from 'node:assert/strict';
import {vpnStatusText,operationText,relayStatusText} from '../public/vpn-status.js';
test('running or activating service with a timeout never claims a connected tunnel',()=>{
 for(const ActiveState of ['active','activating']){
  assert.match(vpnStatusText({ActiveState,StatusText:'connect_deadline'}),/Таймаут/);
  assert.doesNotMatch(vpnStatusText({ActiveState,StatusText:'connect_deadline'}),/подключён/);
  assert.equal(vpnStatusText({ActiveState,StatusText:'handshake'}),'TLS-подключение');
 }
 assert.equal(vpnStatusText({ActiveState:'active',StatusText:'ready'}),'Туннель подключён');
 assert.equal(vpnStatusText({ActiveState:'active',StatusText:'idle_wait'}),'Включён, ожидает трафик');
 assert.match(vpnStatusText({ActiveState:'active',StatusText:'h2_ping_timeout'}),/Связь потеряна/);
 assert.equal(vpnStatusText({ActiveState:'active'}),'Соединение не подтверждено');
});
test('combo packet readiness and HTTPS relay counters are separate facts',()=>{
 assert.equal(vpnStatusText({ActiveState:'active',StatusText:'ready'},null,'combo-tls'),'Основной туннель подключён');
 assert.equal(relayStatusText('boring-tls',{}),'');
 assert.match(relayStatusText('combo-tls',{status:'stale',relay:{failed:12}}),/свежих данных/);
 assert.match(relayStatusText('combo-tls',{status:'sampled',relay:{broken:true}}),/ошибка обработчика/);
 const text=relayStatusText('combo-tls',{status:'sampled',relay:{active:0,completed:0,failed:180}});
 assert.match(text,/ошибок с запуска 180/);assert.doesNotMatch(text,/работает|доступен|успешн/);
});
test('operation status reports actual network recovery and failed result',()=>{
 assert.match(operationText({kind:'vpn-settings',status:'running',phase:'waiting-tunnel'}),/Ожидание подключения/);
 assert.match(operationText({kind:'vpn-stop',status:'running'},{SubState:'stop-post'}),/Восстановление маршрутов/);
 assert.match(operationText({kind:'vpn-start',status:'failed',error:'native_not_ready'}),/ошибка.*native_not_ready/);
 assert.match(operationText({kind:'vpn-settings',status:'failed',error:'endpoint_change_requires_owner_migration'}),/Смена exit требует переноса ключей/);
});
