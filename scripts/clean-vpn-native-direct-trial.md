# Прямой physical trial native combo

Статус 2026-10-11: выбран вместо параллельного namespace sandbox для тестовой
Radxa. Это будущий ограниченный trial, не готовая команда `--apply` и не
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

## Ещё требуется до первого запуска

- durable owner для временного PREROUTING chain: write-ahead journal, exact
  read-back, повторяемый cleanup и отказ при foreign drift;
- model/namespace fault matrix этого overlay, включая SIGKILL на каждом шаге;
- прямой exit lifecycle/rollback поверх его фактической конфигурации и Docker
  firewall без flush или присвоения чужих rules;
- компактный read-only preflight именно direct trial для exit;
- только затем пользовательский bounded запуск сначала без fault injection,
  потом crash и короткая нагрузка.

Kill switch на Radxa можно остановить технически, но в выбранном плане этого не
делаем: остановка VPN-сервиса безопасно оставляет guard fail-closed, а остановка
guard создаёт ненужное окно прямого IPv4/IPv6 выхода. Если обнаружится конкретный
несовместимый rule, сначала меняется и тестируется точный overlay-контракт.
