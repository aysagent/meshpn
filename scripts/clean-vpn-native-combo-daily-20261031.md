# Native combo: повседневная пара Radxa ↔ VPS

31 октября пара **переключена на native C++ `combo-tls`**, включена в автозагрузку
и проверена после обычного reboot Radxa. USB-админка использует новую установку.
[Машиночитаемая приёмка](../fixtures/clean-vpn-native-combo-daily-20261031.json).
Это личный pilot конкретной пары, не универсальная приёмка всех Linux/нагрузок.

## Управление

| Узел | Network owner — запускать/останавливать его | Engine |
| --- | --- | --- |
| Radxa | `native-combo-daily-network.service` | `native-combo-daily.service` |
| VPS | `native-combo-daily-exit-network.service` | `native-combo-daily-exit.service` |

```sh
# На Radxa: состояние, restart/stop/start всего VPN lifecycle.
systemctl status native-combo-daily-network.service native-combo-daily.service
systemctl restart native-combo-daily-network.service
journalctl -u native-combo-daily.service -u native-combo-daily-network.service -n 100 --no-pager

# На VPS.
systemctl status native-combo-daily-exit-network.service native-combo-daily-exit.service
```

Админка: `http://mpn.local/`, резервный адрес `http://192.168.7.1/`, только USB.
Аккаунт, Wi-Fi-профили и hostname сохранены. Доступны start/stop, профиль
boring-ветки, импорт/захват профиля, probes, диагностика и независимый observer.
Общий packet SNI и endpoint требуют согласованной миграции, поэтому произвольная
смена этих полей на одном клиенте запрещена. Новая установка:
`/opt/clean-vpn-native/combo-daily`; на exit — `combo-daily-exit`.

HTTPS **TCP/443 от USB-клиентов** направляется в transparent relay с
`public-https` policy. Остальной IPv4-трафик идёт через boring packet-ветку.
Собственный HTTPS Radxa тоже использует packet-ветку. QUIC/UDP не является
transparent TLS и идёт через packet-ветку. IPv6 не туннелируется; guard блокирует
его прямой выход. Для private/исключённых HTTPS destinations нет тихого downgrade.

Сертификат: **CN/SAN `personal-cert.internal`**, issuer `Personal Certificate
Authority`, срок до **2027-10-30 20:30:46 UTC**. Client проверяет эту SAN/CA;
packet SNI для классификации соединения на exit остаётся `www.trustpilot.com`.
CA private key остался на VPS. DNS/маршрутные настройки Mac не менялись;
тестовые HTTPS-соединения явно привязывались к уже существующему USB route `en9`.
Основной маршрут Mac сохранился через Wi-Fi `en0`, gateway `192.168.1.1`.

## Клиенты и обновление

Адреса **10.99.0.2/.3/.4 и packet-ключи сохранены**. Для relay созданы три
отдельных ключа/ID, собственные durable replay journals. Лимиты 128 всего,
64 на identity. На VPS подготовлены portable bundles с новой CA, profile,
packet/relay ключами:

```text
/var/lib/clean-vpn-combo-upgrade-20261031/exports/10.99.0.3.bundle.json
/var/lib/clean-vpn-combo-upgrade-20261031/exports/10.99.0.4.bundle.json
```

Они содержат credentials; импорт через `clean-vpn-native-clients.mjs import`
проверен без запуска дополнительных клиентов. Прежнему клиентскому config
нужны новая CA/server_name и корректный combo SNI. `export-snapshot` рядом —
только offline snapshot для этих экспортов; он **не управляет работающим exit**.
Private `.mpn` resolver/discovery не включались в daily; host-IP пока фиксирован.

Новые bundles подключены к [транзакционному binary updater](clean-vpn-native-update.md).
На реальных узлах updater заменил выключенные binaries с сохранением config,
ключей, replay/clock state и stopped state. Прежние **native boring-tls** bundles
`daily`/`daily-exit` сохранены выключенными; старый Node VPN не запускался.
Временные независимые rollback timers были вооружены на обоих узлах, переживали
reboot, затем отключены и удалены только после приёмки новой пары.

## Проверки

- Финальные CTest: **14/14 на каждом узле**. Native regression private DNS
  прошла на x64 VPS, ARM64 Radxa и native ARM64 lab. Mac/admin/pcap — 63/63,
  выбранные admin-тесты на Radxa — 47/47; installers — 23/23, updater — 18/18.
- [Clock VM](../fixtures/clean-vpn-native-combo-clock-20261031.json): три boot,
  четыре проверенных SSH time requests, неверные ключ/имя/CA/SSH pin, expired
  certificate, attempt budget, guard и cleanup. Reference exit в этой fixture —
  boring; combo exit/relay проверены отдельными физическими испытаниями.
- На 3443 в отдельных namespace: **60/60 составных steady checks**, последние
  747.508 с от начала steady; проверенный TLS, HTTP 200 и непустые ответы настоящего HTTPS origin, private DNS UDP/TCP,
  TCP echo, canary discovery/rotation/revoke и pending transaction. Host snapshots
  до/после этого прогона совпали, временный порт освобождён. Первый public probe
  плюс steady дают 61 успешный реальный HTTPS запрос.
- Независимый WAN tcpdump: **6/6 packet profiles**, **61/61 original↔wire relay
  pairs** совпали по проверяемым JA3/JA4; capture kernel drops = 0. Для рабочей
  пары на 443 дополнительно сопоставлены **3/3 настоящих TLS-запроса Mac** на
  `usb0`/`wlan0`; packet profile после reconnect тоже matched. Это отдельные
  captures, но реализация JA3/JA4 parser общая с инструментами проекта.
- Реальный SIGKILL client engine: systemd сменил PID, network owner PID сохранился,
  clock state не изменился; USB DNS/HTTPS восстановились. После reboot Radxa
  owner/engine, guard/rescue/admin поднялись **без ручного старта**, SSH clock
  helper не запускался. NSS по свежему имени, USB DNS UDP/TCP, HTTPS с IP VPS,
  админка проверены после загрузки. Ошибок EXT4 в новой загрузке нет.
- Сборки выполнялись отдельно от установленных рабочих binaries. На VPS после
  давления на RAM первый compiler был остановлен; повторная сборка использовала
  собственный временный swap и RAM cap 384 MiB. Swap удалён. У x-ui в том интервале
  журнал зафиксировал panic/nil-pointer и systemd restart; kernel OOM не найден.
  Команды остановки/перезапуска x-ui не выполнялись, его конфигурация не менялась; при самом переключении x-ui/Docker сохранили PID.

JA4 packet-ветки:

```text
t13d0915h2_f91f431d341e_54d72502093d
```

Это bounded Chromium-derived cold profile. User-Agent, HTTP headers/priority и
весь сетевой профиль браузера этим совпадением не подтверждаются.

## DNS и границы результата

Исправлен [private DNS deadline](clean-vpn-native-dns-private-budget-20261031.md):
корректный TCP ответ с учётом connect занял 1451 мс при старом лимите 1200 мс.
Новый бюджет private hop — 3000 мс; loopback/public budgets не менялись,
public fallback для `.mpn` запрещён.

Полный фоновой журнал финального soak содержит **439 passed / 442 probes**:
sequence 32 — намеренный pending transaction, 442 — уже после `Stopping`.
Sequence **291** отдельно вернул SERVFAIL: запрос прибыл на exit через
**4238.148 мс**, resolver ответил за **1.459 мс**, корректный ответ достиг клиента
через **4262.115 мс**. Это превышение ограниченного private WAN budget; поздний
ответ не выдаётся как своевременный. Следующий запрос прошёл без reconnect.
60 отдельно зафиксированных steady checks все прошли. Поэтому формулировка
«весь фоновой трафик без единого отказа» к этому прогону неприменима.

В прежних попытках отдельно наблюдались h2_ping_timeout с самостоятельным
переподключением и один upstream TLS disconnect. Причина последнего не доказана;
в финальных 61 public HTTPS запросах он не повторился. Старые captures/отказы
не удалены из приватных артефактов. Изменение DNS budget не объявляется их общим исправлением.

Проверен **software reboot**, не физическое снятие питания. Плохой RTC и смена
boot budget проверены в VM; фактическое unplug/replug требует физического действия.
VPS включён в автозагрузку, но его reboot не выполнялся. Источник прежнего EXT4
повреждения Radxa не установлен; новая загрузка/записи не дали новых ошибок.
Результат не является полным DNS/IPv6 leak-аудитом или длительным capacity benchmark.
Следующий этап — пользование парой с наблюдением за задержками/обрывами; при
необходимости отдельный длительный soak и развитие `.mpn`/OpenWrt вне daily.
