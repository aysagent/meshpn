# Полный native-переход: рабочий статус

Дополнение 29 октября: host-profile поддерживает отдельные `peer_ipv4` и PSK
для нескольких клиентов одного exit. [Два клиента в systemd-лаборатории](../fixtures/clean-vpn-native-host-multi-report.json)
прошли DNS/HTTPS, независимый restart/crash, общий crash exit и cleanup.
Исправлен DNS-перехват запросов приложений с source=TUN: исключение теперь по
native SO_MARK. Совместный [wrong-clock + host-profile gate](clean-vpn-native-clock.md#совместная-приёмка-host-profile-29-октября)
прошёл: три загрузки, 19 шагов, SSH requests 3/0/1. Scoped combo lifecycle
прошёл двухклиентную матрицу. [Incoming prerequisites](clean-vpn-native-incoming.md)
проверены для boring и combo; это не приёмка приложения public-proxy/Caddy.


## Актуальный scope 2026-10-29

Последующее выполнение: [постоянная native пара активна, физические reboot и админка проверены](clean-vpn-native-daily-20261029.md).
Power-loss остаётся отдельной физической проверкой; старый Node VPN отключён.

Самостоятельный client checkpoint: [host network owner](clean-vpn-native-host-network.md).
21 реальная kernel-проверка, 14 systemd/native/USB сценариев, 23 installer
regressions; 30 проверок в трёх загрузках VM с update/rollback. Временные
физические smoke Radxa↔VPS прошли, включая engine и owner SIGKILL. Свежая админка
управляет native network owner без старого Node VPN (23 unit + 9 integration).
Сводка: [план 29 октября](clean-vpn-native-night-20261029.md). Совместная приёмка
нового host-profile с ошибочными часами завершена; физический boot/power-loss остаётся
отдельной задачей. Scoped exit owner уже реализован и прошёл отдельный
физический smoke без постоянной активации.

По уточнению пользователя старый Node.js VPN не является поддерживаемым продуктом.
Бесшовная миграция, совместимость с legacy, переключатель legacy/native и
автоматический возврат старого VPN **не являются требованиями или блокерами**.
Ниже сохранены исторические checkpoints; их migration-требования заменены этим scope.

Приоритет — самостоятельный native boring-tls с браузерным профилем:

1. Постоянный native lifecycle TUN/маршрутов/DNS и USB SNAT, без зависимости от
   старого Node.js VPN или временного trial owner; независимый kill switch.
2. В VM проверить start/stop/restart, crash recovery, отказ exit/DNS, обновление
   и rollback native-бинарника, условное восстановление часов и boot.
3. Проверить native на Radxa/VPS, затем автозагрузку; reboot и отключение питания
   учитывать раздельно. Старый VPN достаточно явно остановить/отключить перед
   native-запуском, исключив конкуренцию за TUN/маршруты/DNS.

Сохраняются требования не ломать USB rescue/SSH, чужие службы/firewall и сеть Mac.
Восстановление собственных сетевых изменений после аварии остаётся обязательным;
это не означает восстановление работы старого VPN. Node.js control plane/админка
сами по себе не legacy и этим решением не исключаются.

## История проверок

Последний checkpoint: [installed lifecycle с clock/update и native SNAT](clean-vpn-native-installed-lifecycle.md).
Два физических smoke passed, по 10 изолированных checks на Radxa/VPS,
49 gates в трёх VM boot. Постоянный Radxa network owner ещё не реализован;
журналируемое переключение автозагрузки legacy/native больше не требуется.

Новый checkpoint 2026-10-28: [binary update и Radxa/VPS приёмка](clean-vpn-native-update-report.md).
Новая именованная boring-tls установка поддерживает journalled binary rollback
и recovery до старта после boot. Проверены 46 gates в трёх QEMU boot и по 8
изолированных проверок на физических ARM64/x64. Полный native profile WAN/USB
smoke и возврат legacy прошли на повторе; первый download timeout сохранён.
Постоянная existing-host миграция и физический reboot ещё не выполнялись.

Новый checkpoint 2026-10-28: [USB-админка и физическая приёмка](../admin/NIGHT-REPORT.md).
Systemd native + условный clock recovery временно проверены с существующими
DNS/route owners Radxa; финальный smoke/rollback passed. На исправных часах
helper не запускался. Админка установлена с автозапуском только через USB;
постоянный native VPN и DNS migration не устанавливались. Независимый tcpdump
увидел native profile `matched`, legacy `mismatch`. Промежуточный failed HTTPS
smoke сохранён в отчёте. Следующий шаг — пользовательская приёмка админки и
отдельный постоянный native/boot pilot, не объявление универсальной DNS готовности.

Предыдущий checkpoint 2026-10-28: [условный clock recovery](clean-vpn-native-clock.md)
для boring-tls client подключён к systemd и прошёл три cold boot в двух VM.
[Отчёт](../fixtures/clean-vpn-native-clock-lifecycle-20261028.json). Никакого
безусловного SSH при включении; полный TLS остаётся первым шагом. Физические
узлы не менялись. Текущий приоритет — [повседневный пилот](clean-vpn-native-daily-pilot.md):
интеграция с существующими DNS/route owners, временная физическая приёмка clock
bootstrap, затем постоянный lifecycle и boot. Ниже — исторические checkpoints;
старые ограничения scope не отменяют последующее поручение довести autostart.

2026-10-27: [изолированный native runtime](clean-vpn-native-runtime.md) прошёл
standalone Linux, Docker и Podman приёмку: LAN ingress, native DNS,
ClientHello capture, crash/restart, clock-fault VM, часовой soak и временный
Docker amd64 smoke на VPS. [Итог и следующий шаг](clean-vpn-native-night-report.md),
[машиночитаемый отчёт](../fixtures/clean-vpn-native-runtime-report.json).
Следующий этап — physical LAN wiring и расширение transport lifecycle;
permanent install по-прежнему исключён.

Дополнение 2026-10-27: **22/22** проверок модели host-side ingress/recovery в
NIC-less VM; **26/26** проверок replay packaging в каждом из Docker/Podman
ARM64. Для replay используется production binary, а не test-packet engine.
Физический installer из этого не следует; public runtime launcher всё ещё
принимает только boring-tls. Задержки транзакций теперь измеряются внутри
приложения отдельно от container exec overhead.

Уточнение scope 2026-10-27: постоянную установку/enable на Radxa и VPS пользователь
отложил. На узлах — только временные проверки с rollback. Новый приоритет:
[standalone и Docker/Podman runtime, лабораторная приёмка](clean-vpn-native-night-plan.md).
Ниже сохранён предыдущий план; его пункты постоянной физической миграции пока
не выполнять.


Текущий приоритет 2026-10-26: [повседневный boring-tls с частичным браузерным
профилем](clean-vpn-native-daily-pilot.md). Профиль Chromium-derived subset
проверен реальным Radxa↔VPS smoke, engine SIGKILL и отдельным VPS pcap;
CA/hostname/PSK и caps сохранены. RTC Radxa исправлен с 2017 года после NTP sync.
**Постоянная установка пока не выполнена.** Следующий этап — миграция existing-host
units с сохранением guard/USB/foreign firewall, worker crash recovery и reboot;
H2 tuning, tickets/trust anchors и полная мимикрия отложены за этот приоритет.
Временный exit остановлен, legacy/guard/USB восстановлены.


2026-10-07. Цель — C++ data plane на client **и** exit, затем native
transparent/combo. Node остаётся control plane; совместимость с прежним Node
packet path не является обязательной. Production-развёртывания нет.
Измерение скорости отложено до полностью native схемы. Старые сравнительные
скрипты сохранены, но не являются приёмочным барьером.

## Реализовано в текущем шаге

2026-10-26: [goodput через настоящий TUN](clean-vpn-native-h2-goodput.md):
26/26 передачи по 8 MiB, четыре клиента, три повтора, два RTT/bandwidth режима.
На 100 Мбит/с / 120 мс download median 24.62 → 35.60 Мбит/с при 1/1 → 6/15 MiB;
upload 25.13 → 22.45. Netem drops=0, но baseline exit drops=51/69/200:
следующий H2 шаг — отдельные причины drops и bounded TUN backpressure.
Production caps прежние; большие окна пока не одобрены. CTest 10/10, parser 4/4.
Для boring-tls пилота исследования Chromium не барьер: нужны live smoke,
постоянный service lifecycle/DNS/recovery/reboot и корректные часы.
HTTP Date recovery есть только в Node TLS, не в native C++; NTP/RTC Radxa не закрыт.
Mac network/VPS/Radxa этим этапом не изменялись.


2026-10-26: [H2 в полноценном Linux guest](clean-vpn-native-h2-kernel.md) прошёл:
kernel accounting, контролируемый RTT и 30 циклов каждого размера окна.
10 случаев / 168 фаз / 84 восстановления / 384 соединения; SO_MEMINFO доступен.
Guest без NIC и host shares, Mac network settings не менялись. Qdisc drops=0;
при заданных 40 ms измерено в среднем 48 ms. Серии по 30 циклов заняли 144/150 s.
На 8 клиентах большие окна подняли суммарный sampled TCP send queued с 5.7 до
20.6 MiB; RSS exit — с 19.3 до 21.7 MiB. Production caps оставлены прежними.
Следующий ограниченный H2 этап — goodput при фиксированных RTT/bandwidth и
совместном учёте памяти/потерь; ticket lifecycle и trust-anchor retry остаются
отдельными задачами. Полная мимикрия Chromium всё ещё не заявляется.

Параллельно [VPS/Radxa обновлены и пересобраны](../fixtures/clean-vpn-native-device-update-report.json):
CTest 10/10 на каждом, VPS low-memory/jobs=1, Radxa low-memory/jobs=2.
Production source — 0ca74c2; следующие изменения этого checkpoint относятся к
лаборатории/harness/docs и не меняют production engine. Службы не перезапускались.
На VPS exit уже был остановлен (443 не слушал); Radxa legacy/kill-switch остались
активны, PID legacy 802 сохранился. Из-за недоступного GitHub DNS Radxa получила
проверенный git bundle по USB и архив закреплённого Brotli с проверкой SHA-256.
На Radxa разово исправлены часы (+примерно 12h40m); проблема NTP/RTC этим не закрыта.
Временный проектный swap VPS удалён после сборки. Живой client↔exit trial в этом
этапе не выполнялся; новые бинарники лежат в build directories, не установлены
в новые systemd services.

2026-10-26: закрыта короткая [H2 memory/backpressure матрица](clean-vpn-native-h2-budget.md)
для одного native exit и 1/4/8 клиентов: baseline 1/1 MiB и fixture-only
browser credit 6/15 MiB. Все 6 случаев, 36 фаз slow/no-drain и 18 циклов
отключения/восстановления прошли; есть SIGKILL, индивидуальная нагрузка каждого
медленного клиента, проверка байтов и прогресса здоровых peers, возврат FD/сессий.
Начальные SETTINGS/WINDOW_UPDATE проверены для всех 104 соединений.
Исправлена запись тестового H2 observer: одна атомарная запись в общий pipe,
чтобы сообщения нескольких процессов не перемешивались.
[Измеренный отчёт](../fixtures/clean-vpn-native-h2-budget-report.json) сохранён.
Регрессии: CTest 10/10, TLS profiles + multi-peer 18/18 (включая 32 клиента),
macOS lab parser 4/4; пропусков нет.
Production caps не изменены, browser profile не активирован, Radxa/VPS не трогали.
SO_MEMINFO под эмуляцией усечён: kernel socket memory отмечена unavailable/null.
Следующий H2 этап с Linux kernel accounting/RTT/soak выполнен checkpoint выше.
Для обсуждения caps остаётся измерить пользу при фиксированном канале.
Ticket lifecycle и trust-anchor chain selection/retry — отдельные
незавершённые задачи; точная мимикрия Chromium пока недоступна.

2026-10-26: [ML-DSA 44/65/87](clean-vpn-native-mldsa.md) разрешены в opt-in
cold профиле через штатный BoringSSL API. Отдельные временные серверные
сертификаты позволяют проверить actual CertificateVerify, независимый CH/JA3/JA4,
отказ без алгоритма, неверную подпись, CA/hostname/PSK, combo/HRR/ALPS.
Trust-anchor API исследовано: 51764 остаётся запрещённым до выбора цепочки и
bounded retry. Observer измеряет только форму списка, без экспорта IDs.
CTest 10/10, native profile integration 17/17, JS capture/policy/lab 42/42,
без пропусков; [отчёт](../fixtures/clean-vpn-native-mldsa-report.json).
Короткий H2 memory/backpressure этап выполнен следующим checkpoint выше.
Ticket lifecycle и trust-anchor retry остаются отдельными задачами.

2026-10-26: [политика совместимости bounded-cold-v1](clean-vpn-native-profile-policy.md)
экспортируется самим native engine; общие константы используются загрузчиком
профиля и capabilities. Отдельный read-only assessor сопоставляет TLS/H2 evidence
с политикой и фактическим native reference, не создаёт исполняемый профиль.
Chromium 156: blocked по TLS allowlists и H2 caps; HTTP deviations перечислены.
CTest 10/10, native profile tests 14/14, policy tests 10/10. Следующий шаг —
проверка семантической поддержки ML-DSA/trust anchors в закреплённом BoringSSL;
затем ticket lifecycle и отдельный H2 memory/backpressure эксперимент. Cipher
policy не ослаблять, точный Chrome profile пока не обещать.

2026-10-26: [реальный HTTP/2 capture и сравнение](clean-vpn-native-http2-capture.md)
готовы: 20 fresh-process Chromium samples и 6 native соединений, SETTINGS/windows,
порядок и разрешённые значения заголовков, HEADERS priority и HPACK block size.
Общая команда: `npm run lab:native:mac -- --http2-capture`. Результат — different,
а не совместимый browser profile. Политика TLS/H2 зафиксирована следующим
checkpoint выше; повышение caps и копирование navigation headers автоматически
ради совпадения не выполняются.

2026-10-26: реализован экспериментальный [ALPS/H2](clean-vpn-native-alps.md):
new codepoint 17613, реальные negotiated server SETTINGS без лишнего ACK,
профильные client SETTINGS/window, совместимость с exit без ALPS. Узкий adapter
закреплён на nghttp2 revision. Измерение браузерного H2 выполнено следующим
checkpoint выше; профиль из одного ClientHello остаётся недостаточным.

2026-10-26: добавлен [native Brotli certificate decoder](clean-vpn-native-certificate-compression.md)
с явными лимитами и opt-in полем TLS профиля. Production client обрабатывает
CompressedCertificate через BoringSSL, сохраняя CA/hostname/PSK проверки;
encoder и некорректные ответы существуют только в тестовом engine-fixture.
Полная browser fidelity по-прежнему не заявляется; ALPS/H2 реализован следующим checkpoint выше.

2026-10-26, browser capture checkpoint: добавлены bounded loopback TLS 1.3/H2
страница, серия измерений и отдельный Chromium/Podman стенд с одной командой
`npm run lab:native:mac -- --browser-capture`. Сняты 20 fresh-process cold samples
Chromium 156.0.8078.47 на Linux ARM64: 20 JA3, один JA4. Недоверенный CA отвергается;
доверие устанавливается только внутри одноразового контейнера.
[Baseline и разбор пробелов](clean-vpn-native-browser-capture.md): ext27/35/17613/51764,
ML-DSA sigalgs и запрещённые текущей политикой cipher suites. Bundle имеет статус
unsupported; native-профиль браузера не применяется, `browser_profiles:false`
остаётся. Следующий шаг — семантическая certificate compression с серверной
проверкой, затем ALPS/H2 и остальные явно отмеченные ограничения.

2026-10-26, следующий лабораторный checkpoint: добавлен
[опциональный cold TLS профиль](clean-vpn-native-tls-profiles.md) в C++ boring и
Boring-ветку combo. Настройки применяются API pinned BoringSSL; первый ClientHello
проверяется в memory BIO до wire. Независимый TCP observer проверяет поля и
JA3/JA4; capture → candidate → config check → повторный native обмен проверены.
GREASE/ECH GREASE, permutation, optional padding и HRR имеют явные ограничения.
Это синтетические fixtures, не приёмка конкретного browser build:
`browser_profiles:false` сохранён, добавлена `experimental_tls_profiles`.
Radxa/VPS не менялись. Отчёт: [TLS profile lab](../fixtures/clean-vpn-native-tls-profile-report.json).
Следующий шаг — реальные browser capture bundles, совместимость недостающих
extensions и страница/реестр профилей; H2/HTTP и resumption отдельно не завершены.


2026-10-26: физический **combo smoke и SIGKILL engine прошли** на Radxa ↔ VPS.
После разрешённой коррекции часов Radxa (отставание 5 суток 13 часов 40 минут)
восстановилась NTP-синхронизация. Подключение legacy к native exit тоже работает:
прежние отказы не доказывали несовместимость wire protocol.

Обычный цикл old → native combo → old прошёл host и USB DNS UDP/TCP, HTTPS,
проверку IP exit и загрузку. Отдельный SIGKILL прошёл блокировку контрольного
HTTPS после удаления TUN/routes и автоматическое восстановление; внешний
capture на wlan0: 0 direct packets, 443 packets к exit, 0 kernel drops.
Это ограниченный IPv4 HTTPS crash test, не полная приёмка отсутствия утечек.
Внешний VPS pcap наблюдал packet BoringSSL и transparent curl ClientHello.
Браузерные профили по-прежнему `browser_profiles:false`.

Ранние попытки интернет-benchmark были incomplete: legacy upload timeout после
восстановления и отдельный native upload timeout без HTTP-ответа. Эти ошибки
сохранены в [раннем benchmark checkpoint](../fixtures/clean-vpn-native-physical-benchmark-report.json).
Следующие диагностические прогоны — три цикла combo и три packet — завершились
без upload ошибок. Все 12 native combo uploads сопоставлены по TCP/ClientHello
на USB, uplink и exit→origin; объёмы ciphertext на USB и origin совпали. Это
свидетельство успешных потоков, не объяснение прежнего timeout.

Выявлено отдельное ограничение packet throughput: stream и connection credit H2
равнялись 65535 байтам. В `5f99f43` оба окна увеличены до 1 MiB при прежнем лимите
очередей 1 MiB. Реальное объявление окон проверено интеграционным тестом;
CTest 7/7 на x86_64/arm64, session/multi-peer/combo integration 18/18 на VPS.
[Диагностический отчёт](../fixtures/clean-vpn-native-upload-diagnostic-report.json)
содержит timings, показатели до/после, hashes и ограничения capture.
Контрольный packet benchmark после исправления завершил 3/3 цикла:
медиана download/upload **33,7/17,7 Мбит/с** против **3,6/3,5** до исправления.
Combo до изменения дал **53,1/28,8 Мбит/с** на transparent HTTPS.
Это последовательные WAN-замеры, не контролируемый A/B: origin IP между packet
прогонами изменился, короткие upload samples и legacy variation >25% сохранены
как ограничения. В каждом цикле подтверждены rollback и guard. Итоговые engine
drop counters ненулевые и сохранены отдельно от нулевых kernel drops tcpdump;
причина каждого engine drop в этой телеметрии не разделяется.
Исходный upload timeout остаётся открытым до воспроизведения с этой диагностикой.
Повторный post-fix combo SIGKILL `run-61FBxz` тоже прошёл: 2 blocked HTTPS,
0 direct packets к контрольному адресу, 473 encrypted exit packets, 0 kernel
capture drops; host/USB DNS/HTTPS и legacy восстановлены. Это выбранный IPv4
HTTPS crash test, не проверка всех протоколов. Временный exit затем остановлен,
его TUN/правила удалены, исходный `ip_forward=1` сохранён; Docker/x-ui работают.
На Radxa активны legacy/guard/USB/dnsmasq. Постоянный exit не установлен:
после его остановки восстановленная legacy-конфигурация сама по себе не даёт
интернет через этот VPS. Сетевые настройки Mac не менялись.
[Полный physical checkpoint](../fixtures/clean-vpn-native-physical-smoke-report.json).

2026-10-25: добавлена [офлайн-подготовка комплектов нескольких клиентов](clean-vpn-native-clients.md)
для уже существующего multi-peer engine и проверка 32 combo packet-соединений
из этих комплектов. Это не расширяет однопарный контракт physical direct trial.

Native boring-tls exit теперь использует один неблокирующий обработчик событий
для listener, TLS/H2-сессий и общего TUN вместо последовательного обслуживания.
Клиентский packet path также остаётся в C++; транспортные/DNS payload не
передаются через управляющий Node-процесс.

- До 32 настроенных клиентов с разными 32-байтными ключами и IPv4.
- Ключ аутентифицируется с TLS exporter; он определяет разрешённый source IP.
  Адрес из пакета не может выбрать или сменить identity.
- Ответы из TUN направляются только владельцу destination IP. Неизвестные
  адреса и неподдержанные пакеты отбрасываются. Client-to-client forwarding
  между настроенными peers по умолчанию запрещён до записи в TUN.
- Повторное соединение с занятым ключом/адресом отклоняется **до** ответа 200;
  действующий клиент не вытесняется. Потерянная сессия освобождается по EOF,
  ошибке или health deadline. Автоматической миграции сессии нет.
- До 16 незавершённых авторизаций, до 32 admissions/секунду, 5 секунд на
  TLS + H2 auth с момента accept. Это bounded admission, не обещание защиты
  от распределённого DoS или гарантированного входа нового клиента при атаке.
- Отдельные bounded очереди сессий; заполненный получатель не блокирует
  обслуживание остальных получателей общего TUN. Пакеты для заполненной
  outgoing-очереди отбрасываются и учитываются в packet counters.
- События ошибок соединений ограничены по частоте, metadata не содержит
  ключей, bearer, TLS error stack или payload. Режим `status` сохраняет
  прежний bounded control contract; состояние exit агрегированное.
- `--check-config /absolute/file.json`: проверка схемы, файлов ключей и
  TLS context без открытия TUN/listener и изменения сетевых настроек.

Реестр exit (пример формы; это не команда установки):

```json
{
  "version": 1,
  "role": "exit",
  "address": "0.0.0.0",
  "port": 443,
  "tun": "tun0",
  "cert": "/etc/clean-vpn/cert.pem",
  "key": "/etc/clean-vpn/key.pem",
  "peers": [
    { "ipv4": "10.99.0.2", "secret_path": "/etc/clean-vpn/peer-a.key" },
    { "ipv4": "10.99.0.3", "secret_path": "/etc/clean-vpn/peer-b.key" }
  ]
}
```

Client указывает свой `peer_ipv4` и `secret_path`, CA и проверяемое серверное
имя. Допустимые адреса этого этапа — `10.99.0.2..254`; dynamic IP allocation,
CIDR delegation и IPv6 data plane пока не реализованы. Повторные IP/ключи и
смешение `peers` с одиночным `secret_path` на exit отклоняются. Одиночный
`secret_path` остаётся краткой конфигурацией одной native-пары, не Node fallback.
Native DNS stub/source следует `peer_ipv4`. Фиксированный USB control profile
по-прежнему разрешает только `.2`; маршруты и DNS для остальных peers должен
подготовить внешний control plane. Регистрация/ротация peers пока требует restart.

## Лабораторные проверки

`test-native-multi-peer.mjs` подготавливает PKI/config; генерация и проверка
всех IP-пакетов выполняется **C++** fixture:

- два независимых клиента, 400 двунаправленных адресованных пакетов;
- незавершённые/частичные TLS handshakes не задерживают их вход;
- duplicate identity, неверный source и client-to-client destination не
  инжектируются в TUN и не ломают остальные сессии;
- поток новых TCP-подключений, admission/FD bound и истечение auth deadline;
- пять reconnect одного клиента при продолжающейся работе другого;
- остановленный через SIGSTOP авторизованный получатель и переполнение его
  очереди не блокируют второго клиента; после SIGCONT/reconnect обмен возвращается;
- все 32 клиента одновременно, ещё 256 адресованных пакетов;
- ограничения RSS/FD и завершение процессов;
- отрицательные конфигурации с повторными ключами/IP, лишними полями и лимитами.

Основные проверки:

```bash
cmake --build native/clean_vpn/build -j2
ctest --test-dir native/clean_vpn/build --output-on-failure
node --test scripts/test-native-multi-peer.mjs scripts/test-native-data-plane.mjs scripts/test-native-dns.mjs
CVPN_NATIVE_ONLY=1 CVPN_SOAK_SECONDS=180 node --test scripts/test-native-soak.mjs
```

`clean-vpn-native-lab.mjs HOST_BOOT_BASE QEMU_TOOLS_ROOT --native-only` использует
NIC-less VM и реальные kernel TUN, firewall/DNS/SNAT и USB-подобный peer.

На Apple Silicon Mac тот же runner поднимается одной командой через постоянный
Podman cache; см. [native lab на macOS](clean-vpn-native-macos-lab.md). Это не
отдельная упрощённая модель: внутри запускается Linux x86-64 и штатный NIC-less
QEMU/TCG сценарий.
В этом режиме нет Node client/exit, mixed-version проверок или benchmark.
Node запускается только как native control coordinator. Проверяются DNS,
TCP/UDP/fragmentation, uplink recovery, native exit restart, graceful stop,
engine crash, сохранение guard и SSH, уборка процессов. Этот VM-сценарий пока
проверяет одну native-пару, не multi-peer routing в настоящем kernel TUN.
Он также **не** проверяет native systemd installer/boot; это следующий этап.

### Зафиксированный результат 2026-10-07

- Общий regression-набор: 381/381, без пропусков; включает сохранённые
  control-plane/rollback тесты. Это не означает запуск legacy в native-only VM.
- CTest: 2/2; ASAN/UBSAN: 18/18, включая multi-peer и DNS второго клиента.
  Инструментирован собственный C++ код, не сторонние зависимости.
- DNS для `.3` проверен в отдельном network namespace без адреса `.2`, включая
  исходный адрес UDP/TCP запросов к upstream.
- Native-only endurance, 180 секунд: 936 256 пакетов с проверкой содержимого,
  0 dropped packets, 0 unexpected reconnects; 36 отсчётов ресурсов,
  peak RSS 6232 KiB, максимальный рост RSS 1188 KiB. Это тест устойчивости
  на fixture, **не** измерение скорости интернета.
- Native-only VM: 10/10 gates, `status=passed`, без внешней сети и shared FS.
  Локальный отчёт: `/var/tmp/meshpn-native-lab-CUAJqt/report.json`.
  SHA-256 проверенного production engine:
  `2464763cee6b7ca821a9dcdb301c683cea2764ddc3dbe0b8d4b19e21b2676e92`.
  Отрицательные probes намеренно возвращают ошибки — итог оценивается по
  gates, включая positive control, crash guard и cleanup.

Radxa/VPS/Mac не изменялись; развёртывание и WAN benchmark не запускались.

## Что ещё не закончено

Продолжение 2026-10-07: добавлены [прямой C++ service и systemd-лаборатория](clean-vpn-native-service.md).
Этот шаг отделяет lifecycle engine от сетевого provisioning. Старый результат
VM выше относится к предыдущей сборке и сохранён как отдельный checkpoint.

1. Эксплуатационная интеграция native-only network provisioning client и exit.
   [Route ownership/DHCP recovery для direct service](clean-vpn-native-routes.md)
   реализованы отдельным coordinator без packet IO. Добавлен [единый site profile](clean-vpn-native-network.md)
   TUN/guard/DNS/SNAT/MSS с fresh-only установкой, activation target и VM
   crash/reboot сценарием. Network manager/address/default пока — внешний владелец;
   нельзя применять профиль к существующему firewall или уже поднятому uplink.
   [Fresh installer и cold boot/reboot в VM](clean-vpn-native-install.md)
   добавлены отдельным checkpoint на fixture-сети. Direct C++ systemd
   start/stop, crash-restart обеих сторон и два peer через реальные TUN уже
   проверены отдельной лабораторией; это ещё не полный production provisioning.
   Нужны также расширенные ресурсные прогоны разных нагрузок. Не расширять
   текущий USB профиль молча.
2. Перенос transparent relay/обработки потоков в C++, защищённая судьба
   non-HTTPS трафика, негативные handshake/relay тесты.
   [Первый C++ codec/HRR checkpoint](clean-vpn-native-transparent.md) проверен
   на full/resumed TLS 1.2/1.3 (включая HRR) внутри memory BIO. Добавлены native
   enc-SNI/auth, durable replay и scoped TCP relay с backpressure/half-close.
   Scoped engine client/exit и SO_ORIGINAL_DST/REDIRECT проверяются в отдельном
   namespace с SIGKILL/restart. Public-HTTPS destination policy добавлен и
   проверяется через veth/отдельный origin namespace без внешнего Интернета.
   Добавлен standalone LAN HTTPS network guard с default-DROP остальных типов
   трафика и общей моделью владения firewall. Пять namespace проверяют оба C++
   engine, PREROUTING REDIRECT, SIGKILL client/exit, restart и отсутствие
   выбранного прямого обхода. Fresh site installer теперь связывает engine и
   firewall, создаёт replay state до публикации unit и выделяет ему единственный
   writable каталог. [Transparent systemd/cold boot](clean-vpn-native-transparent-boot.md)
   прошёл 19/19 gates на двух загрузках: сохранность байтов/прав replay,
   автозапуск обеих ролей, crash/restart, отказ при missing/corrupt state и
   восстановление только явно сохранённых fixture-байтов. Это не power-loss,
   live-token replay через reboot или physical-host приёмка.
3. [Native combo engine checkpoint](clean-vpn-native-combo.md): общий exit listener,
   выбор ветки по ClientHello и владение потоками внутри C++ реализованы.
   Проверены одновременный packet/TLS fixture и replay после exit crash.
   Единый network profile и реальные TUN/DNS/LAN проверены в NIC-less VM:
   HTTPS через transparent, TCP/UDP/DNS через boring, crash/restart обеих ролей,
   отказ прямого fallback даже после удаления split routes. Нельзя склеивать
   standalone guards вручную. [Installer/systemd приёмка](clean-vpn-native-combo-boot.md)
   дополнительно прошла 23/23 gates на двух загрузках: nested PKI/PSK, replay,
   direct C++ client/exit, установленный route coordinator, crash/autorestart и
   отказ при missing/corrupt replay без автоматического reset. Общая регрессия
   416/416; CTest normal/ASAN 6/6 и ASAN integration 16/16. Это fresh dedicated-host
   контракт, не distro migration, physical acceptance или live upgrade.
4. [Native-only смешанная нагрузка](clean-vpn-native-combo-soak.md) прошла 180 секунд:
   2 437 092 проверенных пакета, 1 907 TLS-сеансов, без packet drops/reconnect;
   FD/threads вернулись к baseline. Отдельно пройден 30-секундный ASAN/UBSAN
   прогон. Регрессия 418/418, CTest normal/ASAN 6/6, ASAN integration 10/10.
   Границы: loopback/fixture packet FD, один peer, не real-TUN или WAN benchmark.
   Дополнительно реализован [real-TUN sustained load](clean-vpn-native-combo-load.md):
   production binary обеих ролей, 180 секунд TLS/TCP/UDP/DNS с ресурсами и
   сопоставлением TX/RX, clean restart и crash/capture после нагрузки.
   Два прогона — 14/14 gates каждый; регрессия 429/429, CTest normal/ASAN 6/6.
   Добавлен [native-only directional benchmark](clean-vpn-native-combo-benchmark.md):
   три повтора раздельных upload/download/RTT для boring и transparent внутри combo,
   CPU/RSS обеих ролей, C++ генерация/проверка payload. Методика проверяется в
   NIC-less real-TUN VM; TCG не определяет скорость Интернета или hardware capacity.
   Два прогона прошли 13/13 gates; регрессия 434/434, CTest normal/ASAN 7/7.
   Сырые результаты и hashes — `fixtures/clean-vpn-native-combo-benchmark-report.json`.
   На момент лабораторной приёмки физические узлы не менялись. Последующий
   физический этап и его ограничения описаны в checkpoint в начале документа.
   Браузерные профили/UI не объявляются реализованными этим шагом.
5. Начат physical-acceptance этап с read-only
   [combo preflight](clean-vpn-native-physical-preflight.md): он проверяет
   бинарник/config/site-plan, архитектуру, units, links/routes/listeners и строгий
   dedicated firewall contract, но всегда оставляет `mutationAllowed:false`.
   Это инвентаризация для проектирования transient trial, не разрешение применить
   fresh site profile поверх работающей Radxa/VPS. Физический трафик и benchmark
   этим checkpoint ещё не запускались. Offline pair-plan дополнительно сверяет
   два свежих read-only отчёта. Одноразовый HMAC challenge доказывает совпадение
   обоих combo PSK без их публикации; публичная certificate chain проверяется
   по клиентскому CA и имени. Это по-прежнему не разрешение на мутацию.
6. После уточнения пользователя physical sandbox с отдельными namespace/veth
   [отложен](clean-vpn-native-sandbox.md): Radxa является тестовым клиентом, и
   её штатный `clean-vpn.service` можно временно остановить. Текущий путь —
   [прямой transient trial](clean-vpn-native-direct-trial.md) поверх уже
   проверенного old/native/old lifecycle. Независимый cvks4 guard и USB rescue
   сохраняются; останавливать kill switch без необходимости нельзя, поскольку
   это создаёт окно прямого выхода. В combo-конфигурации USB control теперь
   явно выбирает nested boring packet branch; transparent branch не создаёт
   второй TUN. Локальная реализация bounded combo apply, временного journalled
   REDIRECT, scoped exit NAT/FORWARD и same-boot recovery закончена; реальные
   netns/iptables и fault-тесты проходят. Физический smoke начат 2026-10-26;
   текущий блокер и результаты восстановления описаны в начале документа.

Это промежуточный этап полного переноса, **не** заявление «весь native готов».
