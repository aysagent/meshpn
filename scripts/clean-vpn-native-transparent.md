# Native transparent-tls: codec, durable admission и engine relay

2026-10-07. Добавлены C++ socket relay, durable replay journal и отдельный
экспериментальный режим client/exit в `clean-vpn-engine`. Проверены настоящие
REDIRECT/SO_ORIGINAL_DST внутри отдельного user/network namespace без uplink.
Это **не готовый production transparent/combo**: разрешены только явно заданные
IPv4:port; installer/site profile ещё не включает interception и fallback.

## Реализовано

- `native/clean_vpn/transparent_hello.hpp`: инкрементальный сбор ClientHello,
  строгие границы record/handshake/extensions/SNI, отказ при дубликатах расширений,
  64 KiB на wire-prefix и не более 128 records. Payload имеет отдельный буфер
  того же верхнего размера; входной chunk не копируется целиком.
- Variable-length SNI rewrite с обратимым изменением **одного** TLS record.
  После восстановления совпадают исходные байты ClientHello и границы records,
  включая SNI, разбитый между records. Если record не вмещает изменение, отказ
  вместо скрытой рефрагментации. Остальные расширения, включая ECH/PSK, непрозрачны.
- `transparent_handshake.hpp`: двунаправленный plaintext-handshake gate.
  HelloRetryRequest разрешает ровно один второй ClientHello с прежними SNI,
  random/session identity и предложением TLS 1.3. Он проходит ту же подмену и
  восстановление; новая destination/session при HRR не выбирается.
- Неожиданный CH2, повторный HRR, смена identity, downgrade после HRR,
  неправильный CCS, EOF посреди handshake и превышение лимитов — sticky failure.
  Таймер 10 секунд не продлевается приходом мусора/early data. Socket runtime
  вызывает `check_timeout` по монотонным часам и закрывает оба конца после
  любого исключения; сам кодек сокетами не владеет.
- После обычного ServerHello поток становится непрозрачным. Приложение и origin
  остаются TLS endpoints; relay не получает их ключи и не терминирует TLS.

## Native enc-SNI и admission

`transparent_auth.hpp` использует pinned BoringSSL, не свою реализацию криптографии:

- Отдельный native формат `n1.<base32 labels>.<public-name>`, без требования
  совместимости со старым Node enc-SNI v2. Lowercase base32 без padding,
  канонические разрезы labels по 63 символа; смена регистра не обходит replay.
- AES-256-GCM, случайный nonce 12 bytes и полный tag 16 bytes. Ключ выводится
  HMAC-SHA256 из 32-byte PSK с domain separation; public-name включён в контекст
  ключа и AAD. Derived key очищается после создания AEAD context.
- Plaintext: version (1 byte), issued seconds (uint64 BE), IPv4 (4 bytes),
  port (uint16 BE), длина исходного SNI (1 byte), исходный SNI, SHA-256 исходного
  **полного wire ClientHello prefix** (32 bytes). Exit восстанавливает prefix и
  проверяет digest; перенос токена в другой ClientHello не разрешает connect.
- До connect: AEAD → восстановление/hash → точный allowlist IPv4:port → время
  ±30 секунд → атомарное резервирование токена в общем replay-cache. Неудачный
  connect уже потребляет токен; перебора альтернативных назначений нет.
- Replay-cache ≤4096 entries, не вытесняет ещё действующие записи при заполнении.
  Очистка требует и истечения wall-clock validity, и monotonic retention >61 s.
  Время снимается под mutex, чтобы параллельные workers не давали ложный rollback.
  Настоящий откат часов переводит экземпляр в отказ; durable вариант сохраняет
  этот отказ через перезапуск.
- Destination policy сейчас — 1..64 явно разрешённых IPv4:port, без DNS,
  wildcard или default permit. Private/loopback разрешаются только как явно
  указанные fixture/административные назначения, не как общий Internet policy.

Длина DNS hostname ограничена 253 bytes. Для public-name `relay.example`
этот формат вмещает исходный SNI до 69 bytes. Более длинное имя или невозможный
record resize **отклоняются**, а не обрезаются и не отправляются напрямую.
Защищённый fallback через boring-tls ещё должен быть подключён отдельно.
Формат является новым проектным протоколом, не прошедшим независимый crypto-аудит.

## Durable replay и ключи

`transparent_replay.hpp`: exit engine требует заранее инициализированный журнал.
In-memory вариант сохранён только для компонентов/fixtures, не используется
самостоятельным transparent exit engine.

- Отдельный каталог 0700 и regular files 0600 владельца процесса; symlink,
  hardlink, повреждение, отсутствующий committed state и конкурирующий owner
  отклоняются. Компоненты пути открываются через directory fd с O_NOFOLLOW.
  Предки должны принадлежать процессу либо системному владельцу корневого
  каталога, без group/world write (кроме системного sticky tmp).
- Независимый `flock` на стабильном inode удерживается весь срок работы exit.
  Снимок до 4096 digest/issued entries: write temporary → fsync file → rename →
  fsync directory, **до** разрешения origin connect. При ошибке запись не даёт
  разрешение и живой admission остаётся в отказе. Это fsync на новое соединение,
  не на пакет; стоимость на реальном storage ещё не измерялась. Сетевые deadlines
  не ограничивают зависший kernel storage I/O; это отдельный ресурсный сценарий.
- Key/public-name scope — отдельный HMAC domain. Чужой ключ/контекст не загружает
  журнал. SHA-256 снимка обнаруживает случайное повреждение, но не заменяет
  доверие владельцу файловой системы. В журнале нет SNI, адресов или payload.
- После перезапуска загруженные записи удерживаются ещё >61 s по новым
  monotonic часам, дополнительно к wall validity. Старый monotonic epoch не
  используется; rollback ниже сохранённого wall high-water mark запрещён.
- После SIGKILL можно удалить только проверенный regular `pending` при наличии
  валидного committed state. Ни продвижения временного файла, ни автоматического
  создания пустой истории при потере `state` нет.

Первичная инициализация — отдельная явная команда `--init-transparent-replay`.
Повторная инициализация того же каталога отказывается; обычный запуск никогда
не очищает историю. Смена ключа/имени требует отдельного каталога и явного
управления его жизненным циклом. Автоматическая ротация ключей не реализована.
Восстановление старого снимка владельцем/root, удаление **всего** каталога с
повторной инициализацией и storage, нарушающий fsync, вне гарантий. SIGKILL и
смена monotonic epoch проверены; реальное отключение питания/boot recovery
этого журнала ещё не проверялось.

## Socket runtime

`transparent_socket.hpp`: C++ client/exit relay с nonblocking TCP, poll,
ограничением 1 MiB на очередь каждого направления и остановкой чтения при
backpressure. Максимум 16 активных/незавершённых сессий на listener; две стороны
одного соединения закрываются вместе при ошибке. Границы по умолчанию:
ClientHello 5 s, connect 3 s, handshake 10 s, idle 60 s, half-close drain 10 s,
общая жизнь одной сессии 600 s. Это начальные лабораторные лимиты, не обещание
готовности долгоживущих приложений. Half-close передаётся только после слива очереди.
Остановка владельца прерывает ожидающие workers. Статистика содержит только
счётчики, peak queue и фиксированные failure codes, не stream bytes.

Компонентный TCP fixture передаёт destination доверенным C++ caller. В engine
клиент получает её **только** через SO_ORIGINAL_DST принятого сокета и проверяет
allowlist. Если original tuple совпадает с локальным listener tuple, соединение
отклоняется: прямой вход не становится forward proxy. Сокеты и данные не выходят
в Node; firewall, DNS и интерфейсы сам engine не меняет.

## Экспериментальная engine configuration

`transparent_config.hpp` — отдельная строгая схема. Обязательные поля:
`version: 1`, `transport: "transparent-tls"`, `role: "client" | "exit"`,
`listen: {ipv4, port}`, `public_name`, `secret_path` (32-byte PSK),
`destinations: [{ipv4, port}, ...]` (1..64 без дубликатов).
Для client обязательно `exit: {ipv4, port}`; для exit — `replay_directory`.
Поля TUN/DNS/сертификатов boring-tls здесь запрещены. Никакого wildcard
destination, разрешения произвольного Internet connect или implicit fallback.

Команды **для отдельно подготовленной лабораторной конфигурации**, не Radxa:

```sh
clean-vpn-engine --check-config /absolute/transparent-exit.json
clean-vpn-engine --init-transparent-replay /absolute/transparent-exit.json
clean-vpn-engine --config /absolute/transparent-exit.json --service
clean-vpn-engine --config /absolute/transparent-client.json --service
```

`--check-config` проверяет схему/секрет без записи/lock журнала; реальный запуск
дополнительно проверяет durable state. Только service mode, sd_notify readiness,
SIGTERM/SIGINT останавливают listener и workers. Node control stdin и packet-fd
здесь не используются. `--capabilities` сохраняет основной boring-tls контракт
и отдельно описывает scoped `experimental_transports.transparent-tls`.

Семантика HRR и выравнивания ClientHello/ServerHello на границах records сверена
с [RFC 8446 §4.1.4 и §5.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1).
Нативный codec намеренно требует отдельную границу ClientHello также для TLS 1.2.

## Лабораторная проверка

```sh
cmake -S native/clean_vpn -B native/clean_vpn/build
cmake --build native/clean_vpn/build --parallel 2
ctest --test-dir native/clean_vpn/build --output-on-failure
node --test scripts/test-native-transparent.mjs
```

Существующие pinned dependencies должны быть подготовлены обычной native-сборкой.
`build-clean-vpn-native.sh` теперь собирает все CTest targets, включая
`service-notify-test`, `transparent-test` и `transparent-replay-test`, перед запуском CTest, а также
`transparent-socket-test` для отдельного полного TLS/TCP прогона.

В `transparent-test` все ClientHello, TLS records и application bytes создаёт и
проверяет C++. Node только создаёт временный тестовый сертификат и читает итог:

- 475 комбинаций разбиения records и входных chunks, точное восстановление;
- 10 000 детерминированных мутаций, некорректные длины/дубликаты/лимиты;
- негативные HRR/state/timeout/EOF проверки и перекрытие 0-RTT record с ответом;
- AEAD, привязка Hello/destination/suffix, время/clock rollback, заполнение и
  истечение replay-cache, 16 конкурентных попыток использовать один токен;
- 18 настоящих BoringSSL handshake: TLS 1.2, TLS 1.3 и TLS 1.3 с HRR,
  каждый full/resumed, chunks 1/7/16384 bytes;
- ClientHello в реальном handshake разбит на три TLS records, в том числе внутри
  SNI. Проверяются сертификат/hostname, факт resumption, количество HRR и
  16 KiB application data в каждом направлении.

В этих 18 handshake endpoints соединены **memory BIO**, но используют настоящий
native encrypted routing token вместо placeholder. Дополнительно
`transparent-socket-test` проверяет реальную loopback TCP-цепочку
application → native client → native exit → origin:

- TLS 1.2 и TLS 1.3/HRR с проверкой сертификата, 2 MiB echo и half-close;
- replay, неверный ключ, изменённый ClientHello, запрещённый адрес, plaintext,
  слишком длинный или незавершённый prefix не открывают новый origin socket;
- ограничение admission включает slow/incomplete ClientHello;
- 8 MiB к медленному получателю с проверкой SHA-256, фактическими остановками
  чтения и измеренным peak queue не более 1 MiB (это **не** speed benchmark);
- отмена владельца прерывает worker, ожидающий ClientHello.
- durable journal: перезапуск listener не разрешает повторный token; ошибка
  storage не открывает origin socket; новый token после валидного рестарта работает.

`transparent-replay-test`: restart, 16 конкурентных попыток, scope другого ключа,
clock rollback с persisted poison, capacity/retention после смены monotonic epoch,
небезопасные/потерянные/повреждённые файлы и настоящий SIGKILL в шести точках
записи (open/write/fsync/rename/directory fsync/возврат admission).

Отдельный engine-прогон использует `unshare --user --map-root-user --net`:
внутри только loopback, kernel REDIRECT и два отдельных процесса штатного
`clean-vpn-engine`. Test application помечает только свои сокеты, чтобы origin
connect exit-процесса не попал в тот же OUTPUT REDIRECT. C++ fixture проверяет
смену network namespace и отсутствие интерфейсов кроме lo **до** сетевых команд.
Нет fallback на namespace хоста при отсутствии unshare/netfilter.
Проверены TLS 1.2/1.3-HRR, отказ прямому входу, строгая схема, отсутствие
автоматической инициализации журнала, один owner, SIGKILL exit и отказ повторному
токену после нового процесса; при отсутствующем exit перехваченный HTTPS
не уходит напрямую. SIGTERM обоих процессов завершает их с кодом 0.
Это выбранный IPv4 TCP-путь, не полная leak/IPv6/DNS или site-profile приёмка.

Реальный ECH и принятие/отказ 0-RTT ещё не проверены; сохранение opaque bytes не
доказывает маршрутизацию ECH. TLS 1.2 оставляет сертификат origin видимым на wire;
enc-SNI не обещает скрыть все метаданные приложения.

Предыдущий codec/auth/socket checkpoint: normal и ASAN/UBSAN, CTest 4/4,
выбранные native-регрессии 81/81 без skip. Новый engine/durable checkpoint
прошёл normal и ASAN/UBSAN CTest **5/5**, оба transparent-прогона (включая
namespace engine), выбранные native-регрессии **82/82**, без skip. Radxa-trial
unit/fixture tests не запускались на физической Radxa.
Дополнительно installer/network-profile/route-service/service-unit/trial-service
регрессии **55/55** без skip. Повторного VM boot/site прогона новым бинарником
в этом checkpoint не было; прежние boot-отчёты относятся к предыдущей ревизии.
В final socket-прогонах peak outbound queue на exit — 933888 bytes при лимите
1048576; чтение действительно приостанавливалось. Число paused polls зависит от
планировщика и не является latency/throughput метрикой.

## Следующая точка

1. Общая Internet destination policy вместо scoped allowlist, provisioning и
   lifecycle interception; явная политика ключей/ротации.
2. Расширенные crash/restart/boot/ресурсные сценарии, реальный ECH/0-RTT.
3. Включение в native-only network profile. Non-HTTPS и неподдержанный TLS —
   только явно защищённый native путь либо блокировка, никакого cleartext/direct
   fallback. Затем единый native combo listener и transport selection.

Native engine уже содержит экспериментальный scoped transparent relay.
Готовность этого пути не означает готовность transparent/combo site deployment.
