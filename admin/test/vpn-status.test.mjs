import test from 'node:test';
import assert from 'node:assert/strict';
import {vpnStatusText,operationText} from '../public/vpn-status.js';
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
test('operation status reports actual network recovery and failed result',()=>{
 assert.match(operationText({kind:'vpn-settings',status:'running',phase:'waiting-tunnel'}),/Ожидание подключения/);
 assert.match(operationText({kind:'vpn-stop',status:'running'},{SubState:'stop-post'}),/Восстановление маршрутов/);
 assert.match(operationText({kind:'vpn-start',status:'failed',error:'native_not_ready'}),/ошибка.*native_not_ready/);
});
