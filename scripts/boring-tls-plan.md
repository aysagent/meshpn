# План: `--type=boring-tls` и паритет с Chrome (Node.js + C/C++ helper)

Полная копия утверждённого плана + спецификация IPC и режимы HTTP/2.

## Решение по архитектуре (зафиксировано)

**Вариант B:** отдельный процесс **`boring-tls-helper`** (C/C++, статический BoringSSL). Node только оркестрирует (`child_process.spawn`). N-API TLS в процессе Node не используется в этой версии.

## Стек

- Приложение: Node.js (`scripts/clean-vpn.js`).
- TLS: исполняемый `boring-tls-helper` + BoringSSL.
- Запуск helper только из Node; override: `CLEAN_VPN_BORING_TLS_HELPER` или `--boring-tls-helper=PATH`.
- Teardown: закрытие stdin / SIGTERM / при таймауте SIGKILL.

## Цели по слоям

| Слой | Цель |
|------|------|
| TLS ClientHello | JA3/JA4, расширения, GREASE — BoringSSL + настройки близкие к Chromium (итеративное сближение) |
| HTTP/2 в Node | Компромисс: после TLS используется Node `http2.connect`; для строгого режима без H2 fingerprint — `--http-vers=1.1` |

### Режимы HTTP (зафиксировано)

1. **Дефолт (`--type=boring-tls`, без `--http-vers=1.1`):** TLS через helper, затем тот же код, что и `--type=tls` — приоритет ALPN `h2`, Node SETTINGS из `resolveCleanVpnHttp2Settings`. TLS-байты на wire ближе к Chrome; **HTTP/2 preface/SETTINGS остаются от Node**.
2. **Строгий:** `--http-vers=1.1` совместно с `boring-tls` — только HTTP/1.1 поверх TLS (нет слоя H2 fingerprint со стороны Node).
3. **Фаза 2 (roadmap):** при необходимости полного паритета H2 — nghttp2 или эквивалент **внутри helper**, без других языков.

## Протокол Node ↔ helper (stdio)

Все сообщения **фазы 1** — кадр: **4 байта длины big-endian** + полезная нагрузка (UTF-8 JSON). Порядок байт сетевой (BE).

1. **Parent → helper:** один кадр конфигурации `config`.
2. **Helper → parent:** один кадр ответа `response`.
3. **Фаза 2:** поток **сырых байт TLS application data** (plaintext): всё, что parent пишет в **stdin** helper после конфигурации, уходит в `SSL_write`; всё, что helper читает из `SSL_read`, пишется в **stdout**. **stderr** helper зарезервирован под логи (не смешивать с stdout после старта фазы 2).

### Поля `config` (JSON)

| Поле | Тип | Описание |
|------|-----|----------|
| `host` | string | IPv4 или hostname (рекомендуется уже разрешённый IPv4 со стороны Node) |
| `port` | number | TCP порт |
| `ca_pem` | string | PEM одного или нескольких CA |
| `servername` | string | SNI в ClientHello |
| `verify_host` | string | имя для проверки сертификата (CN/SAN), как `checkServerIdentity` |
| `alpn` | string[] | например `["h2","http/1.1"]` |
| `handshake_timeout_ms` | number | таймаут рукопожатия |
| `profile` | string | зарезервировано (например `chrome-default`); пока влияет только на логирование / будущие пресеты |
| `log_ja3` | bool | если `true`, после исходящего ClientHello на stderr: `ja3_md5=` и `ja3_sorted_md5=` (порядок-инвариантный); при `ja3_verbose` добавляются обе строки до MD5 и `hex_preview` handshake |
| `ja3_verbose` | bool | расширенный JA3 на stderr; имеет смысл вместе с `log_ja3` |
| `client_hello_profile` | object | опционально: настройка TLS 1.3 cipher suites и named groups под сохранённый профиль браузера; см. ниже |

#### Объект `client_hello_profile`

Передаётся из `clean-vpn` при `--boring-tls-clienthello-profile=PATH` (или `CLEAN_VPN_BORING_TLS_CLIENTHELLO_PROFILE`): файл JSON schema **v1** — [`lib/boring-tls-clienthello-profile.mjs`](lib/boring-tls-clienthello-profile.mjs), обычно созданный `ja3-snif-server --profile-save-path=…` после `GET /ja3-snif`.

| Поле | Тип | Описание |
|------|-----|----------|
| `cipher_suites` | number[] | Полный список после удаления GREASE (как в JA3): сначала типично **TLS 1.3**, затем **TLS 1.2**. Helper выставляет TLS 1.3 порядок через патч BoringSSL и при наличии TLS 1.2 id включает **`TLS1_2…TLS1_3`** и `SSL_CTX_set_cipher_list` для второго блока в том же порядке — так восполняется JA3-поле cipher. Дубликаты среди TLS 1.3 по-прежнему отвергаются API стека. Полное совпадение JA3 с эталоном браузера может не достигаться из‑за порядка расширений / ec_point_formats — см. «Ограничения» |
| `supported_groups` | number[] | id named groups (**порядок** для `SSL_CTX_set1_groups_list`): классические `23,24,25,29,30` (P-256…X448), постквантовые/гибриды из BoringSSL — **`4588` (`X25519MLKEM768`)**, **`25497` (`X25519Kyber768Draft00`)**, **`514` (`MLKEM1024`)** и др.; см. `NamedGroupOpenSslName` / `SSL_GROUP_*` в `openssl/ssl.h` |
| `ec_point_formats` | number[] | сохраняется в файле профиля для JA3; **пока не задаёт BoringSSL** отдельным API — см. раздел «Ограничения» |
| `ja3_string` | string | эталонная строка JA3 до MD5 (как в ja3-snif); при расхождении MD5 helper печатает expected(profile) vs actual(wire) |
| `ja3_md5` | string | опционально: ожидаемый MD5 JA3 (32 hex lowercase); сравнение после отправки ClientHello |
| `ja3_strict` | bool | если `true` и digest не совпал — handshake считается ошибкой (`ja3 profile mismatch (strict)`), код выхода 13 |
| `permute_extensions` | bool | опционально: проброс в `SSL_CTX_set_permute_extensions` BoringSSL; **`false`** — фиксированный порядок расширений стека (иногда ближе к отладке; с порядком Chromium всё равно может не совпасть) |

**ALPN:** в реальном соединении список `alpn` в `config` задаёт **только** `clean-vpn` (`resolveTlsAlpnProtocols`, `--http-vers`). Поле `tls_info.alpn` в файле профиля — справочно (JA3 на содержимое ALPN не смотрит).

### JA3 в логах (без tcpdump)

#### Алгоритм (единый для Node и boring-tls-helper)

- **JA3 wire** (классический Salesforce JA3): после handshake type/length — поля ClientHello; из списков шифров, типов расширений и named groups удаляются значения **GREASE** (RFC 8701, тот же набор, что в `tls-clienthello-ja3.mjs` и в `helper_main.cc`). Строка до MD5: `legacy_decimal,ciphers-dash,ext_types-dash,curves-dash,ec_point_formats-dash` (десятичные числа); MD5 от UTF-8 строки в **нижнем** hex. Порядок элементов в каждом списке — **как на проводе**. Это совместимо со сверкой по открытым JA3 DB для **конкретного** захвата.

- **JA3 sorted** (порядок-инвариантный внутренний отпечаток): те же компоненты после GREASE-filter, но каждый из четырёх списков (cipher suites, extension types, supported groups, ec point formats) **сортируется по возрастанию** перед сборкой строки в том же формате и MD5. Стабилен при перестановке порядка расширений/шифров (типично для Chromium с `permute_extensions`); **не** подменяет классический JA3 при сравнении с БД.

Реализации должны совпадать: [`scripts/lib/tls-clienthello-ja3.mjs`](./lib/tls-clienthello-ja3.mjs) и `ComputeJa3FromClientHelloBody` в [`native/boring_tls/helper_main.cc`](../native/boring_tls/helper_main.cc). Регрессия: одинаковые `ja3_md5` / `ja3_sorted_md5` на stderr helper и при разборе того же TCP в Node (`npm run test:boring-tls-smoke`).

Эталонный расчёт в JS: [`tls-clienthello-ja3.mjs`](./lib/tls-clienthello-ja3.mjs). На **exit** (`--type=tls`) при `--tls-log-ja3` или `CLEAN_VPN_TLS_LOG_JA3=1` — в stdout печатаются **wire** и **sorted** MD5 (и при `--ja3-verbose` — обе строки до MD5). На **client** с `--type=boring-tls` helper на stderr выводит `ja3_md5=` и `ja3_sorted_md5=`; после успешного ответа конфиг-кадра clean-vpn дублирует их строками `[clean-vpn] boring-tls JA3 wire md5=…` и `… JA3 sorted md5=…`. Для одной TCP-сессии digest из потока и из helper совпадают. **`--type=tls` в Node** на клиенте сырой ClientHello не считается — смотрите лог exit или используйте boring-tls на клиенте.

Мини-сервер [`ja3-snif-server.mjs`](ja3-snif-server.mjs): в JSON `GET /ja3-snif` поля `ja3` (wire) и `ja3_sorted`; при `--profile-save-path` в файл профиля добавляются опциональные `ja3_sorted_md5` и `ja3_sorted_string`.

Подробный разбор GREASE-очищенных полей и префикса в hex: **`--ja3-verbose`** (сам включает JA3). Env: при уже заданном `CLEAN_VPN_TLS_LOG_JA3` можно добавить `CLEAN_VPN_JA3_VERBOSE=1`.

**Важно:** эталонный **JA3 (MD5)** строится только из типов расширений, шифров и т.д.; **строки внутри ALPN (h2 vs http/1.1) в JA3 не входят**. Поэтому при `--http-vers=1.1` digest часто совпадает с режимом h2+http/1.1, а отличие смотрите в логах `offered_alpn` / в Wireshark.

Регрессия: `npm run test:boring-tls-smoke`; обновление MD5 эталона: `node scripts/dev-print-boring-tls-ja3.mjs`.

### Поля `response` (JSON)

- Успех: `{"ok":true,"alpn":"<negotiated>"}` (`alpn` может быть пустой строкой если не согласован).
- Ошибка: `{"ok":false,"error":"<текст>"}` и процесс helper завершается с ненулевым кодом.

## Сборка helper

Каталог `native/boring_tls/`: CMake, зависимость BoringSSL (FetchContent, закреплённый коммит), цель `boring-tls-helper`. Команда из корня репо:

Зависимости CMake: **git**, **patch** (POSIX), **cmake ≥ 3.16**, компилятор **C++17**, сеть для первого clone **BoringSSL** (`FetchContent`, закреплённый коммит — полный clone без shallow, иначе Git не находит SHA на некоторых системах).

При конфигурации CMake дерево BoringSSL проверяется на ожидаемый **SHA** (`MESHVPN_BORINGSSL_PINNED_SHA` в `native/boring_tls/CMakeLists.txt`) и при необходимости автоматически патчится файлом **`native/boring_tls/patches/boringssl-meshvpn-tls13-cipher-order.patch`** (порядок TLS 1.3 cipher в ClientHello через `SSL_CTX_set_tls13_client_cipher_order`). Если коммит BoringSSL обновили без обновления патча — конфигурация завершится ошибкой с указанием перегенерировать патч или откатить SHA.

```bash
npm run build:boring-tls-helper
# эквивалентно (собирается только boring-tls-helper, без тестов BoringSSL):
cmake -S native/boring_tls -B native/boring_tls/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/boring_tls/build --target boring-tls-helper
```

На **VPS с малым RAM** (типичная ошибка `c++: fatal error: Killed signal terminated program cc1plus` на ~80% — это **OOM**, ядро убивает компилятор): используйте **`npm run build:boring-tls-helper-lowmem`** (один параллельный job) или вручную `--parallel 1`. При нехватке памяти временно отключите swapless-хост или добавьте **swap** (`fallocate`/`swapon`). После обновления репозитория при старом каталоге `build/` выполните заново `cmake -S … -B …`, чтобы подтянулось `BUILD_TESTING=OFF` для вложенного BoringSSL.

Бинарь: `native/boring_tls/build/boring-tls-helper` (или см. `CMAKE_RUNTIME_OUTPUT_DIRECTORY`).

## Интеграция clean-vpn

- `--type=boring-tls` на **client**; на **exit** тот же сервер, что и `--type=tls` (алиас по типу).
- Остальные флаги TLS (`--tls-server-name`, `--tls-client-sni`, `--http-vers`, `--tls-cert-dir`, `--shared-hmac-key`) — как у `tls`.
- **`--boring-tls-clienthello-profile=PATH`** (env `CLEAN_VPN_BORING_TLS_CLIENTHELLO_PROFILE`): перед **каждым** TCP/TLS к exit файл перечитывается; блок передаётся в helper как `client_hello_profile`. Без флага — дефолтный порядок TLS 1.3 cipher/groups в BoringSSL (без профиля).
- **`--boring-tls-profile-ja3-strict`** (env `CLEAN_VPN_BORING_TLS_JA3_STRICT`): строгое совпадение `ja3_md5` из файла с фактическим ClientHello helper.

## Файл профиля и ja3-snif-server

- Запуск: `node scripts/ja3-snif-server.mjs --profile-save-path=/path/profile.json` (или env `JA3_SNIF_PROFILE_SAVE_PATH`).
- После успешного **`GET /ja3-snif`** профиль (компактный JSON: `user_agent`, JA3-компоненты с порядком, `ja3_md5`, `tls_info`) записывается **атомарно** (temp + rename).

## Ограничения (GREASE, padding, порядок расширений)

- **JA3** в файле считается по правилам Salesforce с **удалением GREASE** из списков. На wire браузер всё равно вставляет GREASE; побайтовое совпадение ClientHello и **JA4** могут отличаться даже при верных cipher/group и совпавшем JA3 MD5. Порядок **TLS 1.3 cipher suites** в ClientHello задаётся профилем через патч BoringSSL (`SSL_CTX_set_tls13_client_cipher_order`); GREASE-cipher по-прежнему добавляет стек отдельно.
- **Padding** (расширение 21) и **полный порядок расширений** задаются стеком BoringSSL (в т.ч. `permute_extensions`); без форка под Chromium **полное совпадение JA3** с профилем, снятым с Chrome/Chromium, **часто недостижимо** даже при верных cipher/group — особенно при **`ja3_strict`**. Имеет смысл смотреть в логах сравнение `ja3_string` или не использовать строгий режим, если цель только рабочий VPN.
- Следующий шаг (spike): управление GREASE/padding/порядком расширений на стороне BoringSSL.

## Риски

| Риск | Смягчение |
|------|-----------|
| Два процесса | Приемлемо; оптимизация позже |
| Зомби helper | Teardown в JS + тест lifecycle |
| Дрейф Chrome | Обновление эталона и профиля BoringSSL |
| Коллизия OpenSSL ↔ BoringSSL | Снята выносом TLS в отдельный процесс |

## Spike notes (исполнение)

- ~~Закрепить коммит BoringSSL в CMake.~~
- ~~JA3 golden: `scripts/lib/tls-clienthello-ja3.mjs` + эталон MD5 в `scripts/test-boring-tls-smoke.mjs` (обновление: `node scripts/dev-print-boring-tls-ja3.mjs`).~~
- **JA4** и побайтовое совпадение ClientHello с конкретной сборкой Chromium — по желанию (отдельный эталон/pcap).
- **Фаза 2** — см. раздел «Фаза 2» (полный H2 fingerprint в helper).

## Регрессионные тесты (локально, без продакшена)

После `npm run build:boring-tls-helper`:

- `npm run ja3-snif-server` — локальный HTTPS (`127.0.0.1:8443`), JSON по `GET /ja3-snif`: User-Agent, JA3 и поля ClientHello для сравнения с Wireshark; опционально `--profile-save-path` для автосохранения компактного профиля; см. [`scripts/ja3-snif-server.mjs`](ja3-snif-server.mjs).
- `npm run test:boring-tls-smoke` — проверки: бинарь, ошибки конфига/TCP, stdin EOF, полный TLS 1.3 к `tls.Server`, **JA3** (ALPN `h2` + `http/1.1` как у client в clean-vpn), отсутствие `ja3_md5` на stderr без `log_ja3`, **JA3 stderr при `log_ja3`**, **SIGTERM** после handshake (не Windows).

## Что остаётся вне автотестов

1. **Прод e2e:** client `--type=boring-tls` ↔ exit `--type=tls` на реальном VPS/сертификатах.
2. **Сборка в CI:** закрепить образ/agents с CMake + C++17 при необходимости.
3. **Фаза 2 / JA4** — по необходимости см. выше.
