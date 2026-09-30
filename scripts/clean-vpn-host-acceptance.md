# Host-client: обрывы, нагрузка и аудит автозапуска

Только изолированная NIC-less VM: TLS/H1 и TLS/H2 поверх IPv4, настоящий TUN,
локальные HTTPS origins и синтетические данные. Ничего не устанавливается
на Radxa/VPS или на хост лаборатории. Это не инструкция запуска production VPN.

## Запуск лаборатории

У существующего `scripts/ingress-vm-lab.mjs` появились флаги
`--ipv6 --host-resilience`. Параметры `--tools`, `--kernel`, `--resolved` и
`--verified-report` задают заранее проверенные локальные артефакты, как в IPv6 lab.
Нужен matching kernel/modules; runner не подменяет VM проверкой на рабочей сети.

Отдельная матрица (прежняя IPv6-матрица запускается без `--host-resilience`):

- остановка exit, отказ новых IPv4/IPv6 соединений без прямого fallback;
- запуск exit заново и восстановление новых HTTPS-соединений;
- DROP только внешнего TLS-пути внутри лаборатории, затем снятие DROP;
- два 60-секундных прогона, concurrency 4, upload 32 KiB / download 64 KiB;
  SHA-256 в обе стороны, проверка сертификата и адреса exit, предел 1024 запросов;
- RSS процесса VPN ограничен 256 MiB, число дескрипторов после нагрузки
  сравнивается с baseline (допуск 8); это не доказательство отсутствия медленных утечек памяти;
- lazy reconnect после idle FIN без перезапуска client, до и после нагрузки;
- `autostart/killswitch.sh` v2: новые и уже существующие UDP-потоки IPv4/IPv6,
  повторный `up` под непрерывными UDP-пробами, входящие TCP replies, отказ
  второго commit и повторное применение, чужие правила, явное снятие защиты.

## Как читать отчёт

Отдельный сценарий настоящего systemd PID1 запускается с
`--ipv6 --host-systemd --dns-conntrack=/absolute/path/to/conntrack`
и теми же параметрами tools/kernel/resolved/verified-report. Он не совмещается
с `--host-joint`, `--host-resilience` или DNS subsets. Внешнего NIC и общей с
хостом файловой системы нет. Драйвер отказывает вне специально помеченной QEMU VM.
Сценарий вызывает настоящий `autostart/install.sh`; только `NetworkNamespacePath`
и место вывода логов заданы лабораторными drop-in. Это **не** проверка раннего
boot: сеть в VM подготовлена до установки сервиса. Проверяются persist-mode,
H2, DNS/IPv4/IPv6, start/stop/restart, SIGKILL и явный recovery, чистое удаление.
Результат этого отдельного сценария — `transports[].hostSystemd`.

`status=passed` означает, что **лабораторные утверждения подтверждены**.
В историческом отчёте аудита старого kill-switch сюда входят отрицательные контрольные случаи:
утечка ранее установленного соединения считается воспроизведённым дефектом,
а не подтверждением безопасности. Итог готовности находится отдельно:
`transports[].hostResilience.acceptance=not-ready-for-deployment`, причины в
`hostResilience.gaps` (runner также выносит их в `deploymentAcceptance` /
`deploymentBlockers`).
Не переносить старый autostart на Radxa только на основании общего `passed`.
Промежуточные результаты сохраняются в `completedChecks` / `partialEvidence`
даже при падении последующего теста. Ошибка нагрузки остаётся ошибкой, а не
автоматически повторяется до получения зелёного результата.

В текущей связке требуют доработки и отдельных тестов:

- старый безусловный `ESTABLISHED,RELATED` разрешал ранее открытый прямой выход;
  v2 удаляет это исключение, оставляя только ответное направление входящего SSH;
- повторный `up` старого kill-switch сначала выполнял `down`; v2 использует
  `restore --noflush`, отдельный commit для каждой семьи IP, без общего flush.
  Старые немаркированные цепочки не мигрируются автоматически;
- старый systemd unit давал лишь 15 секунд на stop; шаблон исправлен на 420 секунд
  и `KillMode=mixed`; базовый persist-mode lifecycle под PID1 проверен ниже,
  ранняя загрузка, обновление и ошибочная остановка пока не приняты;
- незавершённый IPv6 journal после SIGKILL требует явного recovery: обычный
  `Restart=always` сам по себе не является безопасным восстановлением;
- исторический DNS crash-test восстановил DNS, но не весь исходный набор IPv4
  маршрутов (`nonDnsNetworkRestored=false`, отличие `routes`): его успех нельзя
  считать подтверждением общего rollback после SIGKILL. Новый add-only журнал
  и повторная проверка описаны ниже;
- запуск PID1/systemd, ранняя загрузка, restart/update/uninstall и потеря питания
  не проверяются этой namespace-матрицей. Для них нужна отдельная systemd VM.

Guard сам по себе не маршрутизирует ответы публичному SSH-клиенту: проверка
входящего TCP подтверждает лишь firewall-исключение. Удалённое включение полного
туннеля требует отдельного маршрута управления. Лабораторные пробы не являются
доказательством отсутствия утечек при произвольных конкурентных изменениях firewall.
Uninstaller теперь прекращает работу при ошибке stop/guard down и сохраняет
установленные файлы; это проверено как контракт шаблона. Ниже добавлен настоящий
PID1-тест **чистого** удаления, не удаления после аварийной/незавершённой остановки.

DNS-прокси в этой новой матрице выключен. Его failover, SIGKILL/restart,
недоступность exit и повторный SIGINT при cleanup проверяются отдельно:
`ingress-vm-lab.mjs --dns-host-only --dns-conntrack=...`.
Это не заменяет совместную проверку DNS + IPv6 + systemd + kill-switch.
В `--host-resilience` standalone guard проверяется до транспортной матрицы и
снимается перед ней: успешные transport/guard случаи не означают, что их
совместная работа во время SIGKILL уже принята.
Также не проверены непрерывность уже открытого TCP-потока через обрыв,
24-часовой пилот, реальные провайдерские MTU/IPv6 и USB/LAN-клиенты.

## Журнал IPv4 маршрутов host client

Host client теперь сохраняет намерение **до** добавления bypass/split-default/
RFC1918 маршрута или изменения `net.ipv4.conf.all.rp_filter`. Собственные маршруты
помечены `proto 186 metric 42760`. Совместимые существующие маршруты не меняются
и не удаляются при stop; несовместимый маршрут приводит к отказу вместо `replace`.
Это намеренное изменение поведения относительно старого клиента.

Журнал `/run/clean-vpn-host-routes-<netns>/journal.json` привязан к boot ID,
network/user namespace и идентичности интерфейсов, защищён lifetime flock.
Восстановление сначала проверяет весь набор: чужие маршруты, подменённые
интерфейсы или изменённый `rp_filter` требуют ручного разбора. Исчезновение
собственного TUN после SIGKILL допускается; его новый одноимённый экземпляр
не принимается за старый. После штатной остановки журнал становится `released`.

Проверка без изменений:

```sh
sudo env "PATH=$PATH" node scripts/clean-vpn-host-recover.mjs
```

После аварии новый запуск отказывается продолжать до явного восстановления.
`--apply` восстанавливает **только** IPv4 маршруты и `rp_filter`, не DNS, IPv6
или standalone kill-switch. В лабораторном совместном сценарии при остановленном
client recovery выполняется в порядке DNS → IPv6 → IPv4, пока standalone guard
остаётся включённым. Это не автоматическая политика `Restart=always` и не команда
для удалённого применения без проверки текущих журналов и маршрута управления.
Журнал не покрывает LAN firewall/forwarding и потерю питания: состояние в `/run`
действует только в пределах одной загрузки.

Совместная namespace-матрица: `ingress-vm-lab.mjs --ipv6 --host-joint
--dns-conntrack=...` с теми же проверенными VM-артефактами. Включает DNS UDP/TCP,
TLS H1/H2, IPv6, standalone guard, SIGKILL, явное recovery и повторный запуск.
Это по-прежнему не тест настоящего systemd PID1.

Первые совместные прогоны `qmsVd6` и `QPCoAO` остановились на TLS startup.
Диагностика показала входящий TCP на exit с нулём байт ClientHello: клиент уже
запустил таймер TLS, затем заблокировал event loop синхронной установкой DNS.
TLS/boring-TLS outbound bridge теперь ждёт готовности сетевой настройки до
открытия сокета (как eager, так и TUN-triggered connect); отменённый startup
не открывает соединение. Таймауты TLS не увеличены. Регрессии проверяют этот
порядок, отмену startup и последовательность cleanup DNS → IPv6 → IPv4.

Итог совместной матрицы: `/var/tmp/meshpn-ingress-vm-Nxxvmk/report.json`,
**49/49 PASS**, TLS H1 и H2. В обоих случаях подтверждены:

- DNS UDP/TCP и IPv4/IPv6 HTTPS через exit при включённом standalone guard;
- после SIGKILL — отказ прямых IPv4/IPv6/DNS проб и отказ запуска поверх stale journal;
- явное recovery DNS → IPv6 → IPv4 возвращает исходные IPv4 маршруты и `rp_filter`,
  при этом standalone guard продолжает блокировать прямой выход;
- новый запуск после recovery работает, штатная остановка оставляет все три
  журнала `released`, а guard остаётся до отдельного явного `down`;
- после явного `down` положительная контрольная IPv4-проба снова работает напрямую.

Промежуточный прогон `uCDJTf` подтвердил исправленный TLS startup и crash blocking,
но recovery прервал **20-секундный executor стенда**, не 120-секундный бюджет DNS.
Исправлен ограниченный запуск recovery в стенде (150 с, stdout отдельно от progress
на stderr); production DNS/TLS таймауты не увеличены.

Обновлённый локальный набор: **247/247 PASS**, без skips (DNS, host-route journal,
IPv6, bridge, guard, lifecycle contracts, диагностика, VM isolation).
`deploymentAcceptance` остаётся `not-ready-for-deployment`: systemd PID1,
boot/restart/update/uninstall этой связки, питание и nft backend ещё не приняты.
Успех совместного H1 crash-cycle не закрывает исторический H1 `ECONNRESET`
под нагрузкой. Эти результаты не относятся к USB/LAN-клиентам и живому IPv6 провайдера.

## Исправление reconnect

В лаборатории обнаружена гонка после idle-disarm: старый сокет уже `destroyed`,
но его событие `close` ещё не обработано. Новый connect мог сохранить
`tcpFramedSend`, замкнутый на старый сокет: TLS успешно устанавливался, а пакеты
отправлялись старому writer. `ensureWire()` теперь снимает старые idle-handlers
и сбрасывает writer при смене endpoint, до отправки очереди TUN.

Регрессия `idle reconnect before old close event replaces the cached framed writer`
в `test-tun-bridge-startup.mjs` воспроизводит этот порядок событий на реальном
коде CLI bridge: без исправления падает, с исправлением проходит. Это отдельное
доказательство гонки, не замена повторного прогона VM.

Прогон после исправления `/var/tmp/meshpn-ingress-vm-C5k9t7/report.json` прошёл H2
(включая idle после нагрузки), но остановился на H1 upload/download с
`ECONNRESET`. Причина этого сбоя пока не установлена; успешный последующий
прогон сам по себе не закрывает замечание о стабильности. Ранние прогоны также
выявили гонку idle writer и необходимость дождаться установки IPv6 capability
перед началом 5-секундного дедлайна первого HTTPS probe в медленной TCG VM.

## Kill-switch v2: продолжение лаборатории (2026-09-30)

Общее разрешение `ESTABLISHED,RELATED` удалено. Исключение управления теперь
ограничено TCP replies с заданного SSH-порта; allow-правила возвращают обработку
основному firewall (`RETURN`). Повторный `up` не выполняет `down`, а пересобирает
собственные цепочки одним commit на семью IP. Перед изменениями проверяются
содержимое цепочек и hooks; чужое содержимое не удаляется. Есть `flock`, проверка
обоих restore-планов, отказ при смене live scope/IPv6 policy и read-only `plan`.

Первый образ не содержал `stat` и завершился до проверок guard:
`/var/tmp/meshpn-ingress-vm-Iyt2pB/report.json`. После добавления утилиты
`/var/tmp/meshpn-ingress-vm-wkAd8m/report.json` подтвердил 44 утверждения:
блокировку новых/существующих UDP-потоков IPv4/IPv6, idempotent up, отказ при
чужом правиле и обе транспортные матрицы. H2: 339 запросов за 60.525 с;
H1: 392 за 60.313 с; дескрипторы в обоих случаях 22 → 22.

Расширенный прогон `/var/tmp/meshpn-ingress-vm-S5gVWM/report.json`: **56 утверждений
прошли**, включая непрерывные UDP-пробы во время трёх повторных `up`, существующий
входящий TCP на порту 2222 в обеих семьях IP, искусственный отказ IPv4 commit
после IPv6 commit, сохранение блокировки и успешный повтор применения.
H2: 345 запросов за 60.422 с; H1: 374 за 60.394 с. Целостность upload/download
и TLS проверены, FD 22 → 22; максимальный RSS client 118628 KiB.
Все четыре idle reconnect (до/после нагрузки, H1/H2) ответили с первой попытки.
Оба прогона оставляют `deploymentAcceptance=not-ready-for-deployment`.

Проверяется backend **iptables-legacy** в VM, не firewall живой Radxa и не nft backend.
Успех этих тестов не закрывает перечисленные выше crash/systemd gaps или
исторический H1 `ECONNRESET`. Для повторного сбоя workload теперь сохраняет
этап запроса, reused socket, сетевой tuple и объём полученного ответа; автоматических
retry, скрывающих ошибку нагрузки, нет.

Локальный регрессионный набор: 170 тестов, 0 ошибок (guard plan/validation,
autostart/uninstall contracts, IPv6, leak checker, TUN reconnect, DNS journal,
forwarder, acceptance runner и VM isolation). Контракты shell-шаблонов не заменяют
их выполнение под systemd PID1.

## Выполненный DNS crash-test (2026-09-30)

Отчёт `/var/tmp/meshpn-ingress-vm-aAnVc9/report.json`: 23 проверки, настоящий
TLS host client и DNS proxy. Проверены основной/резервный resolver, UDP/TCP,
SIGKILL и повторный запуск, недоступность exit, повторный групповой SIGINT
во время очистки. Прямых DNS-запросов в проверенных отказах не наблюдалось;
DNS journal в конце `released`. Остановка в TCG VM заняла 31.8 с — это измерение
медленной эмуляции, не прогноз времени остановки Radxa.
IPv6 runtime и systemd lifecycle в этом конкретном прогоне не были включены.

Повторный прогон с IPv4-журналом: `/var/tmp/meshpn-ingress-vm-LhmeuE/report.json`,
**24/24 PASS**, `nonDnsNetworkRestored=true`, `nonDnsDifferences=[]`.
После SIGKILL стенд явно восстанавливает host IPv4 journal **при оставшейся
DNS-защите**, затем запускает client заново; это не доказательство автоматического
восстановления systemd. Проверены backup resolver, недоступный exit, повторный
групповой SIGINT во время rollback и точное восстановление исходных маршрутов/
правил. Stop в TCG: 33.318 с. IPv6 runtime и standalone kill-switch проверяются
в отдельной совместной матрице, не этим отчётом.
Первый образ этой регрессии (`CbHIwx`) отказал до запуска client: старый fixture
монтировал `/run` с writable mode по умолчанию. Исправлен **fixture** на 0755;
проверки доверия production journal не ослаблены.

## Контрольный host-resilience прогон (2026-09-30)

`/var/tmp/meshpn-ingress-vm-TEwumg/report.json`: 40 лабораторных утверждений
подтверждены; `deploymentAcceptance=not-ready-for-deployment`. Часть утверждений
именно воспроизводит дефекты старого kill-switch, а не проверяет безопасное поведение.

| Проверка | HTTP/2 | HTTP/1.1 |
| --- | --- | --- |
| Нагрузка, 4 параллельных потока | 60.401 с, 352 запроса | 60.382 с, 416 запросов |
| Upload / download | 11 / 22 MiB | 13 / 26 MiB |
| Целостность и HTTPS | SHA-256 в обе стороны, TLS проверен | SHA-256 в обе стороны, TLS проверен |
| Дескрипторы client до / после | 22 / 22 | 22 / 22 |
| Пиковый RSS client | 111500 KiB | 113564 KiB |
| Новый HTTPS после idle FIN до / после нагрузки | 1.653 / 1.732 с | 1.579 / 1.619 с |

Все четыре idle-пробы ответили с первой попытки через exit. Проверены также
остановка/повторный запуск exit и временный DROP внешнего TLS-пути. Старый
kill-switch реально пропустил ранее установленный UDP-поток в обеих семьях,
хотя новый поток блокировал. Повторный `up` снимает защиту перед сборкой — это
отдельное наблюдение по исходнику, не замер окна пакетным захватом.

Этот успешный контрольный запуск **не закрывает** необъяснённый `ECONNRESET`
в предыдущем H1-прогоне, восстановление всех IPv4-маршрутов после SIGKILL,
совместную матрицу DNS + IPv6 + systemd или полноценный системный lifecycle.

Локальная регрессия: 150 тестов, 150 passed, 0 skipped (Node v24.13.0):

```sh
node --test scripts/test-autostart-stop-contract.mjs scripts/test-vpn-ipv6.mjs \
  scripts/test-client-leak-check.mjs scripts/test-tun-bridge-startup.mjs \
  scripts/test-dns-tunnel-journal.mjs scripts/test-dns-tunnel-forwarder.mjs \
  scripts/test-transparent-acceptance.mjs scripts/test-dns-vm.mjs
```

## Настоящий systemd PID1: базовый persist lifecycle (2026-09-30)

`/var/tmp/meshpn-ingress-vm-Q5L5AD/report.json`: **31/31 PASS**.
Настоящий `autostart/install.sh`, сгенерированные main/guard units, systemd 255,
TLS/H2, совместно DNS tunnel + IPv6 runtime + host IPv4 journal + persist guard.
Production-код в этом этапе не менялся; добавлены VM-драйвер и проверки.

Подтверждены DNS и обе семьи HTTPS через exit, `systemctl restart`, штатный stop,
точное восстановление исходных IPv4-маршрутов/`rp_filter`, три released-журнала.
При stop guard продолжает блокировать проверенные IPv4/IPv6/DNS-запросы.
После `systemctl kill --kill-whom=main --signal=SIGKILL` systemd действительно
предпринял restart, а client отказался стартовать с незавершёнными журналами;
проверенные прямые запросы остались заблокированы. Явный recovery DNS → IPv6 → IPv4
восстановил исходную сеть под guard; затем сервис снова передал HTTPS через exit.
После штатного stop настоящий uninstall удалил main unit/wrapper и вернул
исходную доступность IPv4/IPv6/DNS.

Это **не автоматическое crash recovery** и не разрешение развёртывать autostart:
`deploymentAcceptance=not-ready-for-deployment`. Не проверены ранний boot/reboot,
потеря питания, update, ошибочный stop/uninstall, tied-mode, nft backend и H1
в этом systemd-сценарии. В частности, успешный `systemctl stop` уже упавшего
процесса сам по себе не подтверждает очистку его журналов; чистый uninstall-тест
не покрывает этот случай. Следующий этап — негативные сценарии удаления/обновления.

Неудачные подготовительные прогоны сохранены: `7pZpiP` — циклический импорт
драйвера; `ilxX7b` — отсутствующий BusyBox applet `install`; `Hjhlgj` — `bash`
не находился в compiled PATH systemd минимального образа. Исправлен стенд
(отдельный entrypoint, настоящая утилита install, /usr/bin aliases), production
проверки не ослаблялись. Эти прогоны не засчитываются как успешные VPN-тесты.

Локальная регрессия после добавления стенда: **251 passed, 0 failed, 0 skipped**.
Проверки включают отказ VM-драйвера на хосте, несовместимые флаги и строгий
перечень всех 31 утверждений в итоговом отчёте; общий маркер PASS недостаточен.

## Отказ uninstall после аварии (2026-09-30)

`/var/tmp/meshpn-ingress-vm-UAxPye/report.json`: **37/37 PASS**, настоящий systemd
PID1 и persist guard. Повторена вся предыдущая матрица; дополнительно после
SIGKILL и отказа автоматического restart вызван настоящий `autostart/uninstall.sh`.
Он отказал из-за незавершённого журнала, сохранил четыре установленных файла и
активный guard. Прямые IPv4/IPv6/DNS-пробы после отказа остались заблокированы.
После явного recovery, рабочего запуска и штатного stop тот же uninstall успешно
удалил установку; исходная доступность IPv4/IPv6/DNS восстановилась.

Исправление: shell entrypoint передаёт управление Node-контроллеру
`clean-vpn-uninstall.mjs` / `lib/host-uninstall.mjs`. Успех `systemctl stop` больше
не заменяет проверку журналов. Контроллер открывает и удерживает lifetime locks
host IPv4, DNS tunnel и IPv6; разрешает снятие guard только при `released` либо
отсутствии журнала. Повреждение, занятая блокировка или незавершённое состояние
означают отказ без автоматического recovery. Журналы не удаляются. Lock descriptors
передаются непосредственно запускаемым дочерним командам.

До stop проверяется соответствие network namespace сервиса и контроллера.
Tied guard (`PartOf`/`BindsTo`) и известные зависимости автоматического stop
отклоняются до любых stop-команд; временно поддержаны только persist-mode либо
сервис без guard. Это в том числе ограничивает uninstall для **текущего tied-default
установщика**: автоматически преобразовывать существующую установку нельзя.
Также отклоняются partial installation, custom DNS state-dir и нестандартные
root/bind/private-user настройки. Этот этап не проверяет произвольные вручную
изменённые dependency graphs или конкурентное управление другим администратором.

Локальная регрессия: **285 passed, 0 failed, 0 skipped**, в том числе все позиции
незавершённых журналов, повреждение/занятая блокировка, ошибки stop/guard down,
неправильный namespace и ранний отказ неподдержанных конфигураций.

Готовность по-прежнему `not-ready-for-deployment`: остаются ранний boot/reboot,
таймаут/ошибка cleanup под PID1, падение самого uninstall между фазами, update,
автоматический recovery, tied-mode, nft backend и H1 systemd cycle. Следующий
шаг — безопасное обновление установленного сервиса и ошибки переходов;
этот PASS не разрешает перенос автозапуска на Radxa.
