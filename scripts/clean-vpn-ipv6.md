# IPv6 внутри TLS over IPv4

Первый opt-in режим: `--ipv6=auto` на **client и exit**, только обычный
`--type=tls`, только трафик самого client с `--split-default`.
Без флага поведение остальных транспортов не меняется. `boring-tls`,
`combo-tls`, `transparent-tls`, LAN/USB и `--from-tun` пока не поддержаны.

Внешнее соединение остаётся `--server=154.62.226.216:443`: внутри одного
аутентифицированного TLS-потока передаются IPv4 и IPv6. Второй `--server`
или публичный IPv6 адрес в команде client не нужны. HTTP/2 и HTTP/1.1
передают возможность IPv6 в ответе exit после проверки Bearer.

## Запуск

Обновить репозиторий на обеих сторонах. Client/exit запускать вручную;
на client нужен резервный доступ по **IPv4**: внешние SSHv6-соединения
при включении защиты могут оборваться.

Exit:

```bash
sudo env -u CLEAN_VPN_TLS_LOG_BEARER "PATH=$PATH" node scripts/clean-vpn.js \
  --role=exit --server=0.0.0.0:443 --type=tls --keep-alive=5 \
  --tls-probe-target=www.trustpilot.com:443 \
  --tls-public-name=www.trustpilot.com --ext=eth0 --ipv6=auto
```

Client:

```bash
sudo env -u CLEAN_VPN_TLS_LOG_BEARER "PATH=$PATH" node scripts/clean-vpn.js \
  --role=client --server=154.62.226.216:443 --type=tls --split-default \
  --tls-client-sni=www.trustpilot.com --tls-public-name=www.trustpilot.com \
  --ipv6=auto
```

Exit выбирает `tunnel`, только если на `--ext` есть глобальный IPv6,
маршрут к контрольному IPv6 через тот же интерфейс и **уже включены**
`net.ipv6.conf.all.forwarding=1` и forwarding внешнего интерфейса.
Это проверка конфигурации, не гарантия доступности интернета.
Глобальный forwarding/RA автоматически не меняются: это могло бы
нарушить адресацию провайдера, Docker и другие интерфейсы.

Если хотя бы одного условия нет, exit сообщает `blocked`, client блокирует
внешний IPv6, IPv4 продолжает работать. Отсутствующий или неизвестный заголовок
старого exit также означает `blocked`. Для IPv6-only сайта требуется настоящий
IPv6-выход; перевозка пакетов до exit по IPv4 не заменяет его.
Наличие AAAA в DNS-ответе не означает, что exit умеет выпускать IPv6.

### Что происходит с приложениями без IPv6 на exit

В режиме `blocked` внешний IPv6 получает явный отказ маршрутизации/`REJECT`,
а не намеренный молчаливый `DROP`. IPv4 остаётся доступен через VPN.
Если у сервиса есть IPv4-адрес и приложение умеет перебирать адреса
(например, Happy Eyeballs), оно может установить новое соединение по IPv4.
Сам VPN не переводит произвольный IPv6-адрес в IPv4 и не повторяет запрос
за приложение. Поэтому совместимость с любым приложением не гарантируется:
IPv6-only сервис, принудительный IPv6 и клиент без fallback останутся недоступны.
Уже открытые прямые внешние IPv6-соединения при включении защиты могут оборваться;
переподключение зависит от приложения. Это политика трафика самого host-client,
не подключённых к Radxa устройств USB/LAN.

Если получился `blocked`, на exit сначала собрать **без изменений системы**:

```bash
ip -6 addr show dev eth0
ip -6 route get 2606:4700:4700::1111
sysctl net.ipv6.conf.all.forwarding net.ipv6.conf.eth0.forwarding net.ipv6.conf.eth0.accept_ra
```

Не включать forwarding вслепую: для провайдера с RA может потребоваться
отдельная настройка `accept_ra`. Публичный IPv6 нужно получить у провайдера,
а не выбирать произвольно.
Обеим сторонам также нужны включённый IPv6 в ядре/TUN, `ip6tables` и `flock`.
Неподдерживаемый kernel/firewall или конфликт собственных адресов/таблиц —
ошибка запуска, а не обещание рабочего режима `blocked`.

## Одна команда проверки на client

При работающих client/exit:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-client-leak-check.mjs --probe --exit-ip=154.62.226.216
```

Прислать весь блок отчёта и строки `IPv6 exit:` / `IPv6 client:` из логов запуска.
Для рабочего IPv6 ожидаются `ipv6.status=tunnel-https-observed` и
`status=dns-and-ipv6-seen-on-TUN-not-on-uplink`. Это ограниченное наблюдение:
HTTPS с проверкой сертификата + маршрут/источник TUN + положительный захват
на TUN, без соответствующих открытых пакетов на uplink; не всеобщая гарантия
отсутствия утечек. При `blocked` HTTPS по IPv6 не устанавливается,
общий результат проверки может быть `inconclusive`, а не PASS.

## Политика и восстановление

- Внутренние адреса TUN фиксированы: `fd42:6376:706e::2` client,
  `fd42:6376:706e::1` exit, `/126`. Exit делает узкий NAT66/MASQUERADE
  для адреса client через `--ext`.
- Через туннель идёт глобальный unicast `2000::/3`. Client не использует
  uplink как запасной IPv6-выход. Остальные внешние IPv6 назначения
  блокируются; loopback, link-local и link-local multicast оставлены для
  локальной работы. Это не поддержка произвольных частных IPv6 сетей.
- IPv6 DNS по порту 53 остаётся под существующей DNS-политикой: запросы к
  IPv4 resolver внутри VPN могут возвращать AAAA. DoH/DoT отдельно не перехватываются.
- Служебные пакеты NDP/MLD не запускают lazy TLS reconnect. Пропускаются
  только валидные IPv6 кадры с ожидаемым адресом client.
- Штатный Ctrl+C восстанавливает свои правила и адреса, затем закрывает TUN.
  При аварии защита остаётся до явного восстановления в той же загрузке.
  Это **не** reboot kill-switch и не полный IPv4 kill-switch.

После аварии, когда VPN-процесс уже остановлен, сначала проверить DNS
recovery, если он был включён, затем IPv6 и host IPv4:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-dns-recover.mjs
sudo env "PATH=$PATH" node scripts/clean-vpn-ipv6-recover.mjs
sudo env "PATH=$PATH" node scripts/clean-vpn-host-recover.mjs
```

После проверки, если нужно **вернуть прямую сеть**, применить соответствующие
recovery-команды с `--apply` (DNS → IPv6 → host IPv4). Если используется отдельный
kill-switch, recovery не снимает его: в лаборатории он остаётся включённым до
завершения всех проверок. IPv6 recovery берёт отдельную
блокировку, проверяет boot/namespace, идентичность интерфейсов, backend,
зарезервированные таблицу `19997` и правило `10995`, удаляет только свои
точные операции с read-back. Чужие конфликты не «исправляются» flush-командами.
Незавершённый IPv6-журнал запрещает повторный запуск `--ipv6=auto` до recovery.
Незавершённый host IPv4-журнал также запрещает новый host client; он восстанавливает
только собственные маршруты и `rp_filter`, не LAN forwarding/firewall.

## Локальные тесты

`node --test scripts/test-vpn-ipv6.mjs scripts/test-client-leak-check.mjs`
проверяет валидатор, CLI, журнал и честность диагностических статусов.
`scripts/test-vpn-ipv6-real.mjs` — отдельная namespace-сеть с реальным TUN,
TLS/H1/H2, NAT66, UDP, большой TLS-передачей, отсутствующим IPv6 forwarding,
старым exit без capability, штатной остановкой и SIGKILL/recovery.
В среде без TUN используется NIC-less VM runner `ingress-vm-lab.mjs --ipv6`
с локальными проверенными инструментами; никаких подключений к production.

Проверено 2026-09-29 перед публикацией:

- 95 выбранных Node-тестов DNS/bridge/IPv6/диагностики — PASS, без skips.
- NIC-less VM, Linux 5.4, ip6tables-legacy: 29 проверок TLS IPv6 — PASS,
  включая write-ahead cuts до/после установки guard и перед завершением start.
  Локальный отчёт: `/var/tmp/meshpn-ingress-vm-ZzKutA/report.json`.
- Отдельная регрессия прежнего TLS host DNS: 23 проверки — PASS,
  `/var/tmp/meshpn-ingress-vm-IkDlMQ/report.json`. Она не подтверждает совместный
  live dual-stack/DNS на Radxa; в той версии IPv4 маршруты host не журналировались
  (`nonDnsNetworkRestored=false`). Текущая работа над журналом и совместной
  crash-матрицей описана в `clean-vpn-host-acceptance.md`; исторический отчёт
  сам по себе не подтверждает восстановление IPv4.

Проверка на Radxa/exit, nft backend, провайдерский IPv6/PMTU и совместный
dual-stack/DNS пока требуют живого отчёта; локальные результаты не заменяют его.

Дополнительная проверка 2026-09-30: 29 Node-тестов — PASS; NIC-less VM —
35 проверок PASS (`/var/tmp/meshpn-ingress-vm-BB0naC/report.json`).
На exit удалён публичный IPv6 при включённом forwarding: IPv6 блокируется,
а Node-клиент с `autoSelectFamily` и контролируемым lookup (IPv6 первым,
IPv4 вторым) действительно пробует оба адреса и получает HTTPS-ответ через
IPv4 exit с проверкой TLS-сертификата. Проверено для TLS/H1 и TLS/H2.
Это не тест публичного DNS, всех приложений или провайдерского IPv6;
проверка настоящего IPv6-выхода отложена до появления IPv6 на сервере.
