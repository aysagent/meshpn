# Прямой physical trial native combo

Статус 2026-10-11: локальная реализация и fault-тесты закончены; следующий шаг —
первый ограниченный физический прогон Radxa ↔ VPS. Это transient trial, не
production-установка.

## Почему без namespace

На Radxa уже проверен transient lifecycle `old → native boring → old`:
`clean-vpn-native-trial.mjs` запускается отдельным systemd unit, переживает
потерю SSH, останавливает только `clean-vpn.service`, владеет временным `tun0`,
маршрутами и DNS-журналом и перед возвратом legacy проверяет cleanup. USB rescue
на `192.168.7.1:2222` и отдельный cvks4 kill switch продолжают работать.

Для тестового клиента этот путь проще, чем второй network namespace, veth,
дополнительный адресный план и исключение в существующем kill switch.

## Целевой цикл

1. Проверить работающий legacy TLS, USB rescue, cvks4, baseline DNS/HTTPS и
   точный binary/config для native client и exit.
2. До остановки сервисов проверить две разные 32-байтные PSK: packet PSK для
   boring branch и отдельную relay PSK для transparent branch. Сверить пару
   client/exit одноразовым proof, не печатая ключи.
3. На exit заранее запустить независимый rollback watchdog. Затем временно
   остановить только его clean-vpn service, поднять native combo на том же
   согласованном порту/TUN и проверить listener/readiness. SSH не трогать.
4. На Radxa временно остановить только `clean-vpn.service`. Kill switch, USB
   rescue, dnsmasq USB gadget и SNAT/MSS service оставить активными.
5. Создать тестовый `tun0`, запустить native combo и применить обычные owned
   packet routes/DNS из существующего trial.
6. Добавить отдельный journalled NAT PREROUTING chain только для
   `usb0`, `192.168.7.0/24`, public TCP/443 → локальный combo listener. Частные,
   local/control и IP exit не перехватывать. При смерти engine правило остаётся,
   поэтому HTTPS получает отказ, а не незаметный direct/TUN downgrade.
7. Проверить с USB peer одновременно: HTTPS через transparent (без роста packet
   TUN counters), TCP/UDP/DNS через boring, отсутствие прямого fallback,
   штатный stop и аварийный SIGKILL.
8. Удалить только правило/chain с совпавшими identity и read-back, восстановить
   routes/DNS/TUN, запустить legacy на exit и client и повторить baseline.

## Что уже подготовлено

- существующий Radxa old/native/old lifecycle и его crash rollback;
- native combo engine, единый exit listener, real-TUN VM и load/benchmark;
- pure composition client combo config из существующей packet-конфигурации;
- USB control выбирает `config.boring` у `combo-tls`, поэтому route/DNS owner
  остаётся общим для boring и combo и не зависит от TLS relay;
- отдельный relay secret обязателен; совпадение путей отклоняется в pure plan,
  совпадение реальных bytes должно проверяться runtime до остановки legacy.

## Что закончено до первого запуска

- `native-combo-redirect-journal.mjs`: write-ahead journal client REDIRECT,
  активация PREROUTING последней, exact read-back/cleanup, отказ при foreign
  drift или подмене `usb0`;
- `clean-vpn-native-combo-redirect-recover.mjs`: read-only по умолчанию,
  `--apply` только для точного same-boot journal;
- combo-профиль встроен в прежний Radxa old/native/old runner и Mac USB
  coordinator; relay PSK сравнивается с packet PSK по байтам до остановки
  legacy;
- crash recovery сохраняет HTTPS overlay fail-closed до удаления packet
  routes/DNS и удаляет его последним;
- exit использует случайный `cvne<id>` TUN и только три собственных правила:
  два `FORWARD` и один `MASQUERADE`. Исходный `ip_forward` восстанавливается;
  Docker/x-ui rules не flush/reload/replace;
- `clean-vpn-native-exit-trial.mjs` даёт read-only network preflight,
  bounded transient unit, `RuntimeMaxSec` и независимый `ExecStopPost` recovery,
  который возвращает `clean-vpn.service` после смерти wrapper;
- модельные cut-point тесты и реальные user/netns+iptables тесты проходят.

## Подготовка пары (следующий физический шаг)

Сначала обновить ветку и собрать актуальный engine на обеих архитектурах. Затем
на exit, пока legacy работает, создать **новый** приватный trial-каталог:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-native-direct-config.mjs \
  --create-exit \
  --directory=/root/native-combo-trial \
  --endpoint=154.62.226.216 \
  --uplink=eth0 \
  --client-relay-path=/root/native-combo-trial/relay.psk
```

Команда не трогает сеть и службы. Она создаёт отдельную случайную relay PSK,
`exit.json`, явным вызовом engine инициализирует durable replay и создаёт
`client-profile.json`. Packet PSK/cert/key берутся из фактического argv
работающего legacy exit и не копируются.

`relay.psk` и `client-profile.json` надо безопасно скопировать на Radxa ровно в
`/root/native-combo-trial/`, затем выполнить там `chmod 600` для обоих файлов и
`chmod 700` для каталога. Relay PSK не печатать и не передавать в argv.

На exit выполнить только preflight:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-native-exit-trial.mjs \
  --preflight \
  --config=/root/native-combo-trial/exit.json \
  --endpoint=154.62.226.216 \
  --uplink=eth0
```

Первый безопасный порядок физического smoke:

1. Запустить exit на 15 минут той же командой с `--apply` вместо `--preflight`.
   Команда вернётся после появления native listener; unit продолжит работать.
2. С Mac через USB запустить coordinator с дополнительным
   `--combo-profile=/root/native-combo-trial/client-profile.json`.
3. После отчёта Radxa выполнить на exit `node
   scripts/clean-vpn-native-exit-trial.mjs --stop`; проверить `--status`.
4. Только после успешного ordinary smoke повторять `--crash`, затем bounded
   benchmark. Первый запуск не совмещать с fault injection.

Ручной same-boot recovery нужен только если transient unit уже inactive/failed:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-native-exit-trial.mjs --recover
sudo env "PATH=$PATH" node scripts/clean-vpn-native-combo-redirect-recover.mjs
# и только после успешного dry-run при незавершённом journal:
sudo env "PATH=$PATH" node scripts/clean-vpn-native-combo-redirect-recover.mjs --apply
```

Нельзя flush-ить iptables, удалять неизвестный TUN или journal вручную: при
foreign drift recovery специально останавливается для разбора.

Kill switch на Radxa можно остановить технически, но в выбранном плане этого не
делаем: остановка VPN-сервиса безопасно оставляет guard fail-closed, а остановка
guard создаёт ненужное окно прямого IPv4/IPv6 выхода. Если обнаружится конкретный
несовместимый rule, сначала меняется и тестируется точный overlay-контракт.
