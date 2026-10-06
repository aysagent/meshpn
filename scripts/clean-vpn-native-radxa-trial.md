# Native M1: короткий прогон на Radxa с установленным systemd

Экспериментальный **native client → существующий exit**. Не установка native
вместо рабочего клиента. Проверено в лаборатории на x86_64; на физической
Radxa/ARM64 2026-10-05 прошёл old/native/old host smoke с проверенным возвратом
(коммит `0325b9c`). Это ещё не USB/leak/crash/длительная приёмка native.
Ветка должна быть опубликована перед командами ниже.

## Автоматический Mac/USB + настоящий обрыв uplink

Следующий этап после принятого host hold на `252f649` (2026-10-06):
один запуск с Mac проверяет old/native/old **с USB-клиента**, а между native
проверками действительно опускает и поднимает `wlan0` на Radxa командой
`networkctl down/up`. Это не `engine.uplink`-имитация и не перезагрузка роутера.
Сеть Mac, USB/rescue и конфигурация exit не перенастраиваются. Fault-этап не
меняет firewall; обычные owned DNS/route setup и cleanup самого trial сохранены.
Потеря интернет-доступа через Radxa на время переключений/обрыва ожидаема.

После публикации изменений на Radxa через rescue SSH:

```bash
cd /root/dev/meshpn && git pull --ff-only
```

После исправления multicast на клиенте требуется **пересборка C++**:
`bash scripts/build-clean-vpn-native.sh`. Правки macOS `/tmp` и ожидания
`idle_wait` сами по себе не требовали пересборки, но multicast меняет engine.
Не запускать отдельный `--apply`:
его вызовет координатор с Mac. На Mac нужен Node.js 18+ и штатные ssh/curl/dig.

На Mac (здесь USB — `en9`):

```bash
scp -P 2222 root@192.168.7.1:/root/dev/meshpn/scripts/clean-vpn-native-usb-check.mjs /tmp/clean-vpn-native-usb-check.mjs &&
node /tmp/clean-vpn-native-usb-check.mjs --interface=en9
```

Скопировать итоговый блок `CLEAN-VPN USB CHECK BEGIN … END`. Обычно несколько
минут; не делать checkout/build/restart во время теста. Координатор открывает
собственное SSH multiplex-соединение, сохраняет проверку host key и берёт путь
к Node из работающего legacy-сервиса — NVM не нужно загружать в удалённом shell.

Фазы в `usb.phases`:

| Фаза | Проверка с Mac |
| --- | --- |
| baseline | Старый VPN: DNS A/AAAA UDP/TCP, 3 HTTPS с exit IP, загрузка 1 MiB |
| native | Те же проверки через native |
| blocked | `wlan0` административно down, IPv4 default отсутствует; два отказа TCP/таймаута HTTPS |
| recovered | После включения wlan0: ожидание HTTPS до ~60 с, затем полный набор проверок |
| restored | Полный набор после проверенного возврата legacy |

DNS запрашивается явно у `192.168.7.1` с USB-адреса Mac. HTTPS привязан к `en9`;
IP для загрузки получается тем же DNS и передаётся curl через `--resolve`.
Системный DNS/Wi-Fi Mac не используется для этих проверок. Всего до семи загрузок
по 1 MiB вместе с host smoke; upload, Speedtest и непрерывный поток не проверяются.

За восстановление wlan0 отвечает **отдельный** transient unit
`clean-vpn-native-usb-uplink-run-….service`: helper ждёт 20 с после down,
затем выполняет up; systemd ограничивает работу `RuntimeMaxSec=30` и дополнительно
запускает `ExecStopPost=/usr/bin/networkctl up wlan0`, в том числе при гибели helper.
Команды имеют собственные таймауты; `TimeoutStopSec=15` ограничивает остановку unit.
Основной trial останавливает fault-unit сразу после blocked-проверки. Это команда
включения интерфейса, а не гарантия доступности точки доступа/DHCP; их ошибки
попадут в отчёт, роутер здесь не диагностируется. Нельзя гарантировать восстановление
при отказе systemd/ядра/питания. USB rescue остаётся независимым.

Каждая фаза связана с конкретным run ID, IP SSH-клиента и одноразовым nonce.
Ожидание Mac ограничено 120 с (blocked — 15 с). При закрытии Mac/SSH trial
продолжает работу в systemd, завершает ожидание и выполняет штатный audited rollback.
Обычная отмена не отменяет cleanup; SIGKILL самого trial не считается проверенным
crash-recovery legacy. Независимый fault-unit всё равно обязан выполнить up.
Позже через rescue можно получить сохранённый отчёт:

```bash
cd /root/dev/meshpn && node scripts/clean-vpn-native-trial.mjs --report
```

Успех: `status=passed`, `usb.status=passed`, все пять фаз passed,
`rollback=verified`, `guard=verified`. `rollback=verified` относится к host
восстановлению: если Mac исчез на последней фазе, USB-результат и общий статус
будут failed, даже при работающем legacy. `recoveryMs` — ожидание первого успешного
HTTPS **с начала recovered-фазы на Mac**, не точная задержка от DHCP; отдельно
записано время команды восстановления. `blocked` — проверка недоступности выбранного
HTTPS endpoint, не доказательство отсутствия всех IPv4/IPv6/DNS-утечек.

Локальная проверка нового сценария: unit/negative-тесты протокола, координатора,
команд fault-helper и lifecycle/rollback. Реальный запуск networkctl/systemd на
Radxa и macOS coordinator ещё требуют этого физического прогона; лабораторные
mock-проверки не подменяют его.

Физический прогон `684d2e6`, `run-IV703a` (2026-10-06): все пять USB-фаз
и три host smoke прошли, реальный down подтверждён, guard/rollback verified.
От начала recovered-фазы Mac до первого успешного HTTPS — 2279 мс;
команда восстановления заняла 215 мс. Общий результат корректно failed:
`native_peer_address_rejected`, до остановки шесть раз приходили пакеты
`10.99.0.1 → 224.0.0.22`, IP protocol 2, приводившие к перезапуску сессии.
Их адрес/протокол соответствуют IGMPv3 multicast reports; содержимое пакетов
не сохранялось. Полной приёмкой этот прогон не считается.

Правка C++: после проверки framing/IPv4-header/checksum клиент отбрасывает
входящий multicast `224.0.0.0/4`, увеличивая `dropped_packets`, без записи в TUN
и без завершения TLS/H2. Multicast-forwarding не добавлен. Unicast destination
isolation и exit source isolation остаются строгими; критерий отсутствия
`peer_address` в trial не ослаблен. Нужен повторный физический USB-прогон
с пересобранным engine. Счётчик dropped может содержать корректно отброшенный
multicast и сам по себе не означает потерю пользовательского unicast.

## Запуск

С Mac зайти именно через уже настроенный и проверенный USB rescue:

```bash
ssh -o ControlPath=none -p 2222 root@192.168.7.1
```

На Radxa, от root, без отдельного worktree:

```bash
cd /root/dev/meshpn &&
git fetch origin &&
git switch feat/clean-vpn-native-data-plane &&
git pull --ff-only &&
bash scripts/build-clean-vpn-native.sh &&
node scripts/clean-vpn-native-trial.mjs --apply
```

Никаких ручных `systemctl stop`, поиска ключа или создания `tun0`.
Если нет инструментов сборки, скрипт остановится **до изменения сервисов** и
подскажет установку: `apt-get install build-essential cmake git patch pkg-config perl python3`.
Node берётся из текущего окружения (на нашей Radxa уже установлен через NVM).

Скопировать блок `CLEAN-VPN NATIVE TRIAL BEGIN … END`.
При ошибке сборки — последние строки `NATIVE_BUILD=failed`; сервис ещё работает.
Полный build log: `native/clean_vpn/build/radxa-build.log`.

После закрытия SSH можно переподключиться и получить результат:

```bash
cd /root/dev/meshpn && node scripts/clean-vpn-native-trial.mjs --report
```

`--report` показывает выполняющуюся фазу либо итог последнего запущенного теста,
а не выдаёт старый успешный отчёт за результат незавершённого нового прогона.
Отчёты сохраняются в приватном `/var/lib/clean-vpn-native-trial/`.

## Что делает тест

1. Проверяет работающий штатный клиент, cvks4, rescue, существующие SNAT/MSS,
   автозагрузку и совместимость конфигурации. Считывает реальный argv из `/proc`,
   не исполняет shell-wrapper и не печатает аргументы/ключи.
2. Проверяет DNS/HTTPS/1 MiB через старый клиент. Если baseline не прошёл,
   сервис вообще не останавливается.
3. Останавливает **только** `clean-vpn.service`, проверяет освобождение журналов
   маршрутов/DNS/IPv6 и исчезновение старого TUN. IPv6 audit выполняется до
   создания нового TUN и после его удаления: журнал помнит старый ifindex.
4. Создаёт свой временный `tun0`, запускает native, ждёт authenticated ready и
   активацию DNS, повторяет проверки.
5. Останавливает native управляющей JSON-командой, проверяет освобождение
   журналов, удаляет только свой TUN с прежним ifindex, запускает старый сервис
   и ждёт фактической готовности (до 60 секунд): стабильный PID/TUN, маршруты,
   SNAT/MSS, исходная blocked IPv6-политика для `auto` и два последовательных
   HTTPS-запроса через TUN с ожидаемым exit IP. Затем отдельно повторяет полный
   smoke. `restorationReadiness` содержит число попыток и время ожидания.

Итог успеха: `status: passed`, `rollback: verified`, `guard: verified`.
`nativeDiagnostics.beforeStop` сохраняет последние 48 состояний движка, счётчики
пакетов и этапы control-plane на момент окончания теста/ошибки. `afterStop`
добавляет состояние после возврата. `stateCounts` считает все переходы, даже
вытесненные из последних 48 событий. `rejectedAddresses` содержит максимум
16 записей за запуск: роль, IPv4 source/destination и номер IP-протокола
отклонённого пакета. Это сетевые метаданные, не содержимое: без портов, DNS-имён,
произвольного stderr, ключей и аргументов запуска.
Таймаут готовности сам по себе не доказывает ошибку TLS или авторизации;
смотрим эту историю, а не угадываем по одному `native_ready_timeout`.
Startup gate допускает `idle_wait`, если уже наблюдался authenticated `ready`
и активирован DNS: следующие активные smoke-запросы будят lazy transport и
проверяют фактический выход. Иначе переход `ready → END_STREAM → idle_wait`
между двумя опросами мог приводить к ложному `native_ready_timeout` без трафика.
Один лишь исторический `ready` не допускает текущие ошибки, `waiting_uplink`
или `stopped`. Эта правка runner не требует пересборки C++.
Ошибки проверки сертификата различаются: `tls_verify_name`,
`tls_verify_expired`, `tls_verify_not_yet_valid`, `tls_verify_untrusted`,
`tls_verify_failed`. Прочий отказ TLS остаётся `tls_handshake`.
Поддержан старый сертификат с CN=`clean-vpn` без DNS SAN, выпущенный прежним
установщиком. DNS SAN имеет приоритет над CN; другие имена требуют DNS SAN.
Проверки доверенного CA, имени и срока действия остаются включёнными.
Этот C++ fix требует повторного запуска сборки перед trial.

Новая диагностика сессий различает `h2_peer_end_stream`, `h2_goaway_no_error`,
`h2_goaway_error`, `h2_reset_no_error`, `h2_reset_error`, `tls_peer_closed`.
Закрытие без error code не доказывает, что оно ожидаемо для VPN: важны частота,
нагрузка и настройки idle на exit. Ошибки callback больше не скрываются за
общим `http2_receive`: видны `invalid_frame_length`, `invalid_ipv4`,
`peer_address`, ошибки заголовков/очередей и другие фиксированные коды.
`h2_invalid_frame` — отклонённый HTTP/2-кадр; `h2_local_goaway_error` /
`h2_local_reset_error` — завершение, инициированное локальной HTTP/2-библиотекой.
Неизвестные причины не печатают peer-текст или содержимое пакета.

После штатного END_STREAM/GOAWAY без ошибки на уже аутентифицированной сессии
client переходит в `idle_wait`, а не открывает новую сессию без трафика.
Первый IPv4-пакет сохраняется в C++ до готовности новой сессии. DNS stub умеет
разбудить движок внутренним сигналом и ограниченно подождать готовности;
пакеты/DNS не передаются через Node. Первоначальное подключение остаётся
активным для проверки готовности, ошибки транспорта по-прежнему дают retry.

`--hold-seconds=120` теперь делает HTTPS-проверки через `tun0` с паузой 10 секунд
после ответа (проверяется и пробуждение после наблюдавшегося 5-секундного idle).
В `hold` сохраняются результаты, время каждого запроса и полные счётчики
состояний за native-запуск. Ошибка запроса завершает hold с возвратом legacy.
`peer_address` в течение native-запуска также не позволяет считать hold успешным,
даже если все HTTPS прошли. При `hold-seconds=0` остаётся только обычный smoke.
Предыдущий `passed` для 120-секундного окна проверял только живой процесс,
а не такую непрерывную работоспособность. Эти изменения требуют пересборки.

Старый отчёт с общими кодами не позволяет задним числом определить причину.
`atMs` — время получения события runner, **не timestamp движка**: синхронная
настройка/очистка может задержать чтение pipe и собрать несколько событий рядом.
Не измерять по таким группам длительность TLS или частоту попыток.
Стандартный прогон обычно занимает несколько минут после сборки; при сбоях
может быть дольше из-за ограниченных таймаутов безопасной очистки.

Сборка однопоточная и использует отдельный **каталог зависимостей**, но не
отдельный checkout: `native/clean_vpn/build-deps-helper`. Она не пересобирает и
не патчит `native/boring_tls/build`, используемый старым helper. Build и trial
имеют общий flock: нельзя пересобрать engine во время теста.

Сам тест выполняется во временном systemd-unit `clean-vpn-native-trial.service`.
Закрытие SSH или Ctrl-C у ожидающей команды **не отменяет worker**: тот завершит
прогон и возврат. Unit не включается в автозагрузку и не заменяет основной unit.
Программный SIGTERM worker просит отмену с возвратом; жёсткое убийство, потеря
питания и поломка системы не дают гарантий выполнения `finally`.

## Ограничения и остановка при конфликте

- Профиль фиксирован: `154.62.226.216:443`, `wlan0`, `usb0` с
  `192.168.7.1/24`, `tun0`/MTU 1400, `--dns-usb=1`, cvks4. Старый клиент
  TLS/boring-TLS; combo/transparent, HTTP/1.1, нестандартные DNS-журналы и IPv6
  внутри туннеля не подменяются «похожим» режимом, а отклоняются.
- `--ipv6=auto` допустим **только в фактически заблокированном состоянии**:
  журнал active/dynamic=false в текущем boot/namespace, совпадающий TUN,
  фиксированные IPv6 firewall-правила, правило 10995 и только unreachable в
  таблице 19997. Проверки повторяются непосредственно перед остановкой клиента.
  ULA-адрес на TUN сам по себе не означает работающий IPv6-туннель.
  При действующем IPv6-туннеле тест откажет; native M1 остаётся IPv4-only.
  После остановки проверяется отсутствие оставшихся IPv6 правил/маршрутов/
  адресов/цепочек. Старый клиент возвращается с исходными параметрами, без
  переписывания `auto` в `off`. Независимый cvks4 остаётся включённым весь тест.
- Native M1 не воспроизводит выбранный браузерный ClientHello и не исправляет
  время по Date. Нужны уже корректные часы и работающий старый baseline.
- Это host smoke, **не Speedtest, не доказательство отсутствия утечек и не
  полноценная проверка USB-клиента**. Загрузка ограничена существующим checker,
  сравнивать её время как скорость канала нельзя. Mac/exit не перенастраиваются.
- По умолчанию после native smoke сразу происходит возврат. Для ручного curl
  с Mac можно явно дать окно: `--apply --hold-seconds=120`. Начинать curl после
  строки `native-hold`. Максимум 300 секунд, затем автоматический возврат.
- Guard, rescue, SNAT/MSS, unit-файлы и enable/disable не изменяются.
- Во время прогона нельзя делать git checkout/pull, сборку и самостоятельные
  рестарты/изменения сети. Нет поддержки нескольких администраторов одновременно.
- Текущая ветка может использовать тот же checkout, поскольку старые runtime
  файлы не меняются. Preflight откажет при изменении legacy runtime относительно
  `origin/main`. Это не общее обещание безопасного checkout любой будущей ветки.
- При конфликте владения TUN/журналами возврат **не форсируется**:
  `rollback: manual-review-required`. Сохраняем USB rescue, присылаем отчёт,
  не удаляем журналы/правила вручную. `service-restored` означает, что старый
  сервис запущен, но ожидание готовности или контрольная проверка не прошли —
  это не полный успех. `old_ready_timeout_<проверка>` показывает, где остановилось
  ожидание; тест не перезапускает сервис повторно и не ослабляет защиту.
- Неизменность команды проверяется через `busctl --json=short` (systemd),
  только по пути/argv/ignore-failure. PID, время остановки и exit status не
  входят в fingerprint. Дополнительно сравниваются wrapper, JS entry point,
  unit/drop-in содержимое и выбранные эффективные настройки. Изменения файлов
  и ожидаемый daemon-reload по-прежнему блокируют переключение/возврат.
- Тест не выполняет автоматическую перезагрузку. Если штатная очистка стала
  невозможной, перезагрузка через USB rescue остаётся отдельным решением
  оператора: прежняя автозагрузка не изменена, временный TUN/ключи в `/run`
  не сохраняются.

## Локальные проверки разработчика

```bash
node --test scripts/test-native-radxa-trial.mjs \
  scripts/test-native-trial-service.mjs scripts/test-native-trial-diagnostics.mjs \
  scripts/test-native-trial-readiness.mjs \
  scripts/test-native-trial-hold.mjs \
  scripts/test-native-trial-ipv6.mjs scripts/test-vpn-ipv6.mjs \
  scripts/test-native-engine-controller.mjs scripts/test-dns-client-options.mjs \
  scripts/test-autostart-stop-contract.mjs scripts/test-host-stop-faults.mjs
bash scripts/build-clean-vpn-native.sh
node --test scripts/test-native-tls-identity.mjs scripts/test-native-wire-interop.mjs
```

Тесты покрывают разбор действующих параметров/CA/PSK без shell eval, отсутствие
ключей/тел ответов в отчёте, успешный цикл old/native/old, baseline/start/stop/
audit/TUN ошибки, отмену с возвратом, реальные stdin/stdout pipe дочернего
процесса и прерывание цепочки сборки на первой ошибке. Не заменяют реальный
systemd/ARM64 тест этого нового runner на Radxa.
