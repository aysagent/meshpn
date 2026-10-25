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
2. С Mac через USB запустить coordinator с **`--smoke`** и дополнительным
   `--combo-profile=/root/native-combo-trial/client-profile.json`. Без `--smoke`
   исторический default проверяет настоящий down/up wlan0; это не первый smoke.
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

## Если на exit нет запущенного legacy (2026-10-26)

Это отдельный opt-in режим, не автоматический fallback. В подготовке вместо
чтения работающего legacy указать все четыре параметра существующего PKI:
`--standalone-cert=PATH --standalone-key=PATH --standalone-packet-secret=PATH
--standalone-public-name=NAME`. PSK/certificate должны соответствовать клиенту;
секреты не печатаются. Fresh private directory/replay создаются как выше.

К exit `--preflight` и `--apply` добавить `--standalone`. Он требует отсутствия
активного clean-vpn service, listener 443, tun0 и маршрутов 10.99.0.*. Запуск
создаёт только journalled transient TUN/NAT/FORWARD. Независимый ExecStopPost
восстанавливает сетевые изменения, **не запускает несуществующий legacy**.
Ручное восстановление в этом режиме: `--recover --standalone`, после остановки
unit. По deadline exit выключается; это не постоянное исправление отсутствующего
сервера. Клиентский baseline должен реально заработать до переключения клиента.

Preflight принимает kernel `type=local dev=lo` для собственного адреса exit;
принадлежность адреса выбранному uplink проверяется отдельно. Маршрут к собственному
адресу через lo нормален и не должен ошибочно блокировать trial.

Legacy runtime сравнивается с фиксированным `ad6746a7fb3b1c58d7d137f20689035bd4ea1f1c`,
фактически наблюдавшимся на обеих машинах до обновления, а не с движущимся
`origin/main`. Проверяются legacy entry, библиотеки, native helper/addon sources,
lockfile и поля package.json кроме npm-команд. Разрешены только отдельные native
control/lab-модули, не входящие в legacy runtime; изменение production-зависимости
блокирует trial. Unit/argv fingerprint дополнительно проверяется до stop/restore.

### Cold-start при неработающем исходном legacy

Если legacy клиент активен, но не проходит исходный host smoke, обычный `--smoke`
не запускает native. Явный `--cold-smoke` у USB coordinator предназначен именно
для этого случая: работающий baseline он отвергает. Проверки native host и USB
(DNS UDP/TCP, HTTPS с IP exit, загрузка 1 MiB) сохраняются полностью. Fault injection
не выполняется. После удаления собственных journal/TUN восстанавливается прежний
legacy service; два последовательных наблюдения подтверждают стабильный PID/TUN,
маршруты, SNAT/MSS и IPv6 guard. Интернет legacy не считается восстановленным.

Успех имеет отдельное имя `native-smoke-passed-legacy-unavailable` и
`rollback=configuration-verified`, а не обычные `passed/verified`. Это не приёмка
миграции с исправного legacy, не постоянная установка и не разрешение оставить
работающие тестовые процессы без deadline.

USB trace использует `https://one.one.one.one/cdn-cgi/trace` с закреплённым
`--resolve one.one.one.one:443:1.1.1.1`, привязкой к USB и обычной проверкой
сертификата. Так запрос не зависит от DNS Mac и содержит SNI. IP-literal HTTPS
без SNI не поддерживается текущим transparent codec и закрывается; этот smoke
не является заявлением поддержки таких приложений. Прямой fallback не включается.

### Отпечатки из внешнего захвата

`clean-vpn-pcap-fingerprints.mjs` читает classic pcap от tcpdump вне процесса engine:

```bash
node scripts/clean-vpn-pcap-fingerprints.mjs \
  --pcap=/private/path/exit.pcap --destination=154.62.226.216
```

Захват на Ethernet uplink должен начинаться **до** соединения, включать SYN и
полные пакеты (`tcpdump -s 0`). Ограничить время/размер отдельным timeout и хранить
pcap в приватном каталоге. Observer не меняет сеть, не читает engine diagnostics
и не выводит raw ClientHello, tickets или relay token. Он собирает первый
ClientHello IPv4/TCP: учитывает перестановку сегментов, retransmission и wrap
sequence number; неоднозначный overlap не получает отпечаток. Лимиты: 64 MiB
pcap, 128 соединений, первые 64 KiB потока. IPv6, IP fragmentation, pcapng,
HRR и прочие link types не поддержаны; пропуски/ограничения указаны в отчёте.

Вычисления JA3/JA4 используют существующие библиотеки отдельного project-sniffer:
источник байтов независим от engine, алгоритм не является второй независимой
реализацией. Для такой сверки остаётся tshark. Успешный разбор не доказывает
отсутствие потерь захвата, соответствие браузеру или отсутствие утечек.

### Следующие сборки на Radxa

Физически проверены 4 доступных CPU и около 1,6 GiB доступной RAM на Radxa 2 GiB.
Для следующей сборки можно явно выбрать `bash scripts/build-clean-vpn-native.sh
--jobs=2`; по умолчанию остаётся один compiler job для малопамятного VPS.
`--low-memory` независим от `--jobs`: он убирает debug info, сохраняя `-O2`.
Смена этого флага перекомпилирует зависимости, поэтому ради incremental build
можно сохранить текущий профиль: `bash scripts/build-clean-vpn-native.sh
--low-memory --jobs=2`. Четыре одновременных тяжёлых C++ файла пока не проверялись.
Текущий запущенный build менять или прерывать для этого не нужно.

### Ранний отказ запуска combo

Физический прогон выявил несовместимость stdio-controller с прежним требованием
combo `--service`. Client теперь поддерживает тот же control/status stdin/stdout,
что и packet transport; exit остаётся service-only. Preflight проверяет явную
capability `client_stdio_control`, поэтому старый binary отвергается **до** stop.
Изолированный Linux-тест открывает настоящий TUN и проверяет queued stdin stop
производственного combo client, а не только `--check-config`.

Если wrapper завершился до первого status, допустим узкий recovery: host journal
должен принадлежать созданному TUN и не содержать маршрутов, DNS/REDIRECT должны
быть released. Восстанавливается journalled rp_filter, удаляется только проверенный
TUN, затем повторяются обычные audits. Active DNS, чужой ifindex или маршруты
не принимаются за этот случай. Guard не снимается.
