export const operationNames={'vpn-start':'Включение VPN','vpn-stop':'Выключение VPN','vpn-restart':'Перезапуск VPN','vpn-settings':'Сохранение параметров VPN',guard:'Изменение защиты: очистка маршрутов и DNS','device-reboot':'Перезагрузка платы','device-poweroff':'Выключение платы'};
const phases={sending:'Отправка команды',queued:'Команда принята',validating:'Проверка настроек','checking-guard':'Проверка защиты','starting-network':'Подготовка маршрутов и DNS','stopping-network':'Восстановление маршрутов и DNS','starting-engine':'Запуск движка','restarting-engine':'Перезапуск движка','waiting-tunnel':'Ожидание подключения туннеля','enabling-guard':'Включение защиты','disabling-guard':'Разрешение прямого выхода','restoring-usb-access':'Восстановление USB-доступа','applying-settings':'Проверка и применение настроек'};
export function operationText(job,network={}){
 const name=operationNames[job?.kind]??job?.kind??'Операция';
 if(job?.status==='failed')return name+': ошибка · '+(job.error==='endpoint_change_requires_owner_migration'?'Смена exit требует переноса ключей, сертификата, маршрутов и kill switch; эта форма не переносит подключение на другой сервер':job.error??'operation_failed');
 if(job?.status==='passed'){
  if(job.kind==='guard')return job.result?.active===false?'Прямой выход разрешён; VPN выключен':job.result?.unchanged?'Защита уже находится в выбранном состоянии':'Защита включена';
  return name+': завершено';
 }
 const phase=network?.SubState==='stop-post'?'Восстановление маршрутов и DNS':phases[job?.phase]??'Выполняется';
 return name+' — '+phase;
}
export function vpnStatusText(v={},job,transport){
 if(job?.status==='running'&&['vpn-start','vpn-restart','vpn-stop','guard','vpn-settings'].includes(job.kind))return job.kind==='vpn-stop'?'Останавливается':job.kind==='vpn-restart'?'Перезапускается':'Переключение…';
 if(v.ActiveState==='deactivating')return 'Останавливается';
 const connection={ready:'Туннель подключён',idle_wait:'Включён, ожидает трафик',connecting:'Подключается',handshake:'TLS-подключение',waiting_uplink:'Ожидание Wi-Fi',connect_deadline:'Таймаут подключения; повторная попытка',h2_ping_timeout:'Связь потеряна; переподключение',h1_ping_timeout:'Связь потеряна; переподключение',tls_read:'Связь прервана; переподключение',auth_rejected:'Отказ авторизации',auth_clock_skew:'Не совпадает время клиента и exit'};
 if(v.ActiveState==='activating')return connection[v.StatusText]??'Запускается';
 if(v.ActiveState==='inactive')return 'Выключен';
 if(v.ActiveState==='failed')return 'Ошибка службы';
 if(v.ActiveState==='active')return v.StatusText==='ready'&&transport==='combo-tls'?'Основной туннель подключён':connection[v.StatusText]??('Соединение не подтверждено'+(v.StatusText?' · '+v.StatusText:''));
 return 'Статус недоступен';
}
export function relayStatusText(transport,diagnostics={}){
 if(!['combo-tls','transparent-tls'].includes(transport))return '';
 if(diagnostics.status!=='sampled'||!diagnostics.relay)return 'HTTPS-ветка: свежих данных пока нет';
 const r=diagnostics.relay;
 if(r.broken===true)return 'HTTPS-ветка: ошибка обработчика';
 const count=k=>Number.isSafeInteger(r[k])&&r[k]>=0?r[k]:'—';
 return `HTTPS-ветка: активных ${count('active')}; закрыто ${count('completed')}; ошибок с запуска ${count('failed')}`;
}
