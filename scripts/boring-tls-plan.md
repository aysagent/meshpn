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
| `log_ja3` | bool | если `true`, после исходящего ClientHello на stderr: `ja3_md5=`, `ja3_sorted_md5=`, **`ja4=`** (FoxIO JA4.md), **`ja4_alt_sni_alpn_in_j4c=`** (JA4_c как ja3.zone: sorted ext с 0000, без 0010), **`ja4_raw_o`**, **`ja4_raw_r`**, **`ja4_raw_r_alt_sni_alpn=`** (ja3.zone-style raw); при `ja3_verbose` — строки JA3 до MD5, компоненты JA4 (`ja4_a`/`ja4_b`/`ja4_c`, `ja4_c_alt_sni_alpn_in_hash`) и `hex_preview` handshake |
| `ja3_verbose` | bool | расширенный JA3 на stderr; вместе с `log_ja3` или при наличии **`extension_types`** в профиле включает TLS msg callback в helper для JA3/JA4 и диффа расширений |
| `client_hello_profile` | object | опционально: настройка TLS 1.3 cipher suites и named groups под сохранённый профиль браузера; см. ниже |

#### Объект `client_hello_profile`

Передаётся из `clean-vpn` при `--boring-tls-clienthello-profile=PATH` (или `CLEAN_VPN_BORING_TLS_CLIENTHELLO_PROFILE`): файл JSON schema **v1** — [`lib/boring-tls-clienthello-profile.mjs`](lib/boring-tls-clienthello-profile.mjs), обычно созданный `ja3-snif-server --profile-save-path=…` после `GET /ja3-snif`.

| Поле | Тип | Описание |
|------|-----|----------|
| `cipher_suites` | number[] | Полный список после удаления GREASE (как в JA3): сначала типично **TLS 1.3**, затем **TLS 1.2**. Helper выставляет TLS 1.3 порядок через патч BoringSSL и при наличии TLS 1.2 id включает **`TLS1_2…TLS1_3`** и `SSL_CTX_set_cipher_list` для второго блока в том же порядке — так восполняется JA3-поле cipher. Дубликаты среди TLS 1.3 по-прежнему отвергаются API стека. Полное совпадение JA3 с эталоном браузера может не достигаться из‑за порядка расширений / ec_point_formats — см. «Ограничения» |
| `supported_groups` | number[] | id named groups (**порядок** для `SSL_CTX_set1_groups_list`): классические `23,24,25,29,30` (P-256…X448), постквантовые/гибриды из BoringSSL — **`4588` (`X25519MLKEM768`)**, **`25497` (`X25519Kyber768Draft00`)**, **`514` (`MLKEM1024`)** и др.; см. `NamedGroupOpenSslName` / `SSL_GROUP_*` в `openssl/ssl.h` |
| `ec_point_formats` | number[] | сохраняется в файле профиля для JA3; **на клиенте TLS 1.3 BoringSSL не отправляет ext 11** — см. `ssl/extensions.cc` форка; паритет чаще при смешанном TLS 1.2–1.3 или патче |
| `extension_types` | number[] | **Эталон захвата и диагностика**, не декларативный список «что отправить»: helper не итерирует это поле как команду на расширения (кроме типа **5** → OCSP). Multiset-diff с wire: stderr **`profile_vs_wire extensions:`**. При **`ja3_verbose`** — **`profile_vs_wire ciphers:`** и **`profile_vs_wire ja4_sig_algs:`** |
| `client_hello_extra_extensions` | `{type, hex}[]` | опционально: **opaque replay** тел расширений с захвата (hex — тело расширения без заголовка типа/длины). Типы **GREASE** и типы, которые **всегда** задаёт стек/профиль (**0, 5, 10, 11, 13, 16, 21, 23, 35, 41, 43, 45, 50, 51, 65281** — см. `MESHVPN_OPAQUE_EXTENSION_SKIP_TYPES`), helper **не ставит** вторым блоком. Типы **18** и **27** экспортируются из ja3-snif в opaque: если BoringSSL уже отправил такой тип, четвёртый патч (**`boringssl-meshvpn-extra-extensions-emit-dedup.patch`**) **не дублирует** его при вставке. Передаётся в форк BoringSSL и добавляется на wire **перед** расчётом padding и **перед** PSK |
| `signature_algorithms` | number[] | опционально: расширение **13**; задаётся **`SSL_CTX_set_verify_algorithm_prefs`** (публичный API закреплённого BoringSSL) |
| `signature_algorithms_cert` | number[] | опционально: расширение **50**; **`SSL_CTX_set_meshvpn_client_signature_algorithms_cert`** — только со вторым патчем (`boringssl-meshvpn-client-signature-algorithms-cert.patch`) |
| `ja3_string` | string | эталонная строка JA3 до MD5 (как в ja3-snif); при расхождении MD5 helper печатает expected(profile) vs actual(wire) |
| `ja3_md5` | string | опционально: ожидаемый MD5 JA3 (32 hex lowercase); сравнение после отправки ClientHello |
| `ja3_strict` | bool | если `true` и digest не совпал — handshake считается ошибкой (`ja3 profile mismatch (strict)`), код выхода 13 |
| `permute_extensions` | bool | проброс в `SSL_CTX_set_permute_extensions` BoringSSL. **Если ключ отсутствует** — **`true`** (как Chromium): между рукопожатиями может меняться порядок типов расширений на wire → меняется **wire JA3**, а **`ja3_sorted_md5`** при том же профиле остаётся стабильным. **`false`** — фиксированный порядок расширений стека (удобно для эталонного wire-JA3 и для `ja3_strict`). **`ja3_strict: true` вместе с `permute_extensions: true`** — ошибка конфигурации: helper не выполняет handshake |
| `ja4` | object | опционально: эталон с ja3-snif — **`{ "fingerprint": "…" }`** передаётся из сохранённого профиля; при расхождении с фактическим ClientHello helper пишет **`warning: ja4 profile mismatch`** на stderr (handshake не прерывается). Компоненты `ja4_a`/`ja4_b`/`ja4_c` в файле профиля — только для человека; в IPC достаточно `fingerprint` |
| `emit_sni` | bool | **`clean-vpn`** через преобразование профиля **всегда** передаёт **`emit_sni: true`**: захват к ja3-snif по IP часто без расширения server_name, а к именованному хосту без SNI CDN даёт **`CERTIFICATE_VERIFY_FAILED`** при **`verify_host`**. В эталонных JA4/JA3 из файла маркер **`i`** (нет SNI в снимке) может расходиться с фактическим **`d`** на wire — ожидаемо |

**Файл профиля (disk):** опционально **`clienthello_emit_sni`** — отражает захват (есть ли тип расширения **`0`**); для человека и сверки с экспортом ja3-snif. При сборке IPC **`profileFileToHelperClientHelloBlock`** поле **`clienthello_emit_sni`** на **`emit_sni`** helper не маппится — всегда **`true`**.

**JA4 (FoxIO):** один отпечаток `ja4_a_ja4_b_ja4_c`; алгоритм совпадает с [`tls-clienthello-ja4.mjs`](./lib/tls-clienthello-ja4.mjs) и `ComputeJa4FromClientHelloBody` в helper. Две цифры в середине **JA4_a** после `i`/`d` — число cipher и число **экземпляров** расширений на проводе (без GREASE): каждый повтор **одного и того же типа** считается отдельно — типичный признак дубликата после ошибочного opaque. Расхождение вроде **1515→1519** при том же числе шифров часто означает **+4 лишних блока расширений**. Для эталона без дубликатов см. также multiset-diff **`profile_vs_wire`**. Раньше: расхождение **15 vs 11** обычно означало, что **BoringSSL шлёт меньше расширений**, чем браузер в ja3-snif. **`clean-vpn`** с профилем всегда шлёт **SNI** на wire (**`d`**, плюс одно расширение типа **0**), даже если в файле эталон **`i`**; вклад SNI в diff JA4 с снимком по IP — ожидаем. **`JA4_c`** зависит от набора типов расширений (без SNI/ALPN в части сортировки) и от списков **signature algorithms** в расширениях **13** и **50**, объединённых **в порядке обхода расширений на проводе**. Поэтому полное совпадение JA4 с браузерным снимком не гарантируется только профилем cipher/groups — стек BoringSSL может отличаться по расширениям и содержимому 13/50; при **`permute_extensions`** относительный порядок ext **13** и **50** на wire может менять **`JA4_c`**.

**Сверка при расхождении с сайтом или другим инструментом:** **`ja4_raw_r`** — JA4.md JA4_r (средний сегмент без 0000 и 0010). **`ja4_raw_r_alt_sni_alpn`** выровнен под отображение **ja3.zone**: средний сегмент — отсортированные типы расширений **с SNI 0000**, **без ALPN 0010** (как у них в примере с браузером). Совпадение с сайтом возможно только при **одних и тех же байтах** ClientHello (например, у эталона есть **`0029`**, у нас на wire его нет → другой `ja4_a` и другой список).

**Ожидаемый wire-JA3 из файла профиля:** при профиле из `ja3-snif` поля `ja3_md5` / `ja3_string` соответствуют **конкретному** захвату. Если включена перестановка расширений (`permute_extensions` по умолчанию), фактический wire-JA3 между сессиями **не обязан** совпадать с этим снимком. **`clean-vpn`** в этом режиме **не передаёт** в helper `ja3_md5` / `ja3_string`, пока не включён **`--boring-tls-profile-ja3-strict`** (тогда в профиле должно быть **`permute_extensions: false`**).

**ALPN:** в реальном соединении список `alpn` в `config` задаёт **только** `clean-vpn` (`resolveTlsAlpnProtocols`, `--http-vers`). Поле `tls_info.alpn` в файле профиля — справочно (JA3 на содержимое ALPN не смотрит).

### Почему в `extension_types` больше типов, чем на wire (audit)

1. **Профиль не теряет расширения при сохранении:** список типов в JSON — это GREASE-очищенный снимок ja3-snif (`buildCompactProfileDocument`).
2. **Раньше helper не «дорисовывал» типы по списку:** BoringSSL сам решал, какие расширения офферить; поле использовалось для диагностики и для OCSP при типе **5**.
3. **Multiset-diff:** строка **`extra_in_profile(multiset)=…`** — типы, которые есть в профиле, но отсутствуют среди типов на wire (без GREASE); **`extra_on_wire`** — наоборот.

### Карта типов (mapping): API стека vs opaque

| Тип (IANA) | Имя / роль | Как воспроизводится сегодня |
|------------|------------|-----------------------------|
| 0 | server_name | `emit_sni` + имя из конфига (clean-vpn всегда **true**) |
| 5 | status_request | тип в **`extension_types`** → `SSL_CTX_enable_ocsp_stapling` |
| 10 | supported_groups | **`supported_groups`** в профиле |
| 11 | ec_point_formats | только эталон в профиле; TLS 1.3-only часто **нет** на wire |
| 13 | signature_algorithms | **`signature_algorithms`** → `SSL_CTX_set_verify_algorithm_prefs` |
| 16 | ALPN | поле **`alpn`** в IPC конфиге helper |
| 18 | signed_certificate_timestamp | **opaque** из захвата при необходимости; если стек уже добавил — dedup при emit (четвёртый патч) |
| 27 | compress_certificate | то же |
| 21 / 23 / 35 / 65281 | padding, EMS, ticket, secure_renegotiation | стек — не opaque (helper denylist) |
| 43 | supported_versions | стек BoringSSL при TLS 1.3 |
| 45 | psk_key_exchange_modes | стек |
| 50 | signature_algorithms_cert | **`signature_algorithms_cert`** + второй патч |
| 51 | key_share | стек |
| 17613 / прочие | проприетарные / ECH и т.д. | при необходимости **opaque** из захвата |

### Стратегия паритета (реализовано)

- **Гибрид:** точечные патчи (cipher **13/50**, порядок TLS 1.3 cipher) + **opaque replay** для остальных типов с провода Chrome.
- **`client_hello_extra_extensions`** в файле профиля и в IPC: массив **`{ "type": uint16, "hex": "<тело расширения>"`**.
- Сервер **может** разорвать handshake на неизвестные или некорректные тела — это осознанный риск паритета по байтам.

### Wire JA3 vs JA3 sorted и `permute_extensions`

- **JA3 (wire)** зависит от **порядка** типов расширений (и шифров, групп и т.д.) **на проводе** после фильтра GREASE — как у классических JA3 DB.
- **JA3 sorted** сортирует те же списки перед сборкой строки, поэтому **не меняется**, если меняется только перестановка расширений при неизменном множестве полей профиля — это основной стабильный отпечаток при «живом» Chromium-подобном ClientHello.
- В экспортируемый JSON профиля (`buildCompactProfileDocument`) записывается **`permute_extensions: true`**; при необходимости байт-в-байт совпадения wire-JA3 со старым снимком задайте в файле **`permute_extensions: false`**.
- **GREASE** по-прежнему исключается из строк JA3; случайные GREASE на wire не должны путаться с вариативностью от `permute_extensions`.

### JA3 в логах (без tcpdump)

#### Алгоритм (единый для Node и boring-tls-helper)

- **JA3 wire** (классический Salesforce JA3): после handshake type/length — поля ClientHello; из списков шифров, типов расширений и named groups удаляются значения **GREASE** (RFC 8701, тот же набор, что в `tls-clienthello-ja3.mjs` и в `helper_main.cc`). Строка до MD5: `legacy_decimal,ciphers-dash,ext_types-dash,curves-dash,ec_point_formats-dash` (десятичные числа); MD5 от UTF-8 строки в **нижнем** hex. Порядок элементов в каждом списке — **как на проводе**. Это совместимо со сверкой по открытым JA3 DB для **конкретного** захвата.

- **JA3 sorted** (порядок-инвариантный внутренний отпечаток): те же компоненты после GREASE-filter, но каждый из четырёх списков (cipher suites, extension types, supported groups, ec point formats) **сортируется по возрастанию** перед сборкой строки в том же формате и MD5. Стабилен при перестановке порядка расширений/шифров (типично для Chromium с `permute_extensions`); **не** подменяет классический JA3 при сравнении с БД.

Реализации должны совпадать: [`scripts/lib/tls-clienthello-ja3.mjs`](./lib/tls-clienthello-ja3.mjs) и `ComputeJa3FromClientHelloBody` в [`native/boring_tls/helper_main.cc`](../native/boring_tls/helper_main.cc). Регрессия: одинаковые `ja3_md5` / `ja3_sorted_md5` на stderr helper и при разборе того же TCP в Node (`npm run test:boring-tls-smoke`).

**JA4:** [`scripts/lib/tls-clienthello-ja4.mjs`](./lib/tls-clienthello-ja4.mjs) и `ComputeJa4FromClientHelloBody` в том же `helper_main.cc`; при `log_ja3` на stderr строка `ja4=`. Регрессия: smoke-сверка JA4 helper ↔ Node по одному TCP.

Эталонный расчёт в JS: [`tls-clienthello-ja3.mjs`](./lib/tls-clienthello-ja3.mjs). На **exit** (`--type=tls`) при `--tls-log-ja3` или `CLEAN_VPN_TLS_LOG_JA3=1` — в stdout печатаются **wire** и **sorted** MD5 JA3 и строка **`ja4=`** (и при `--ja3-verbose` — развёрнуто). На **client** с `--type=boring-tls` helper на stderr выводит `ja3_md5=`, `ja3_sorted_md5=` и `ja4=`; после успешного ответа конфиг-кадра clean-vpn дублирует их строками `[clean-vpn] boring-tls …`. Для одной TCP-сессии digest из потока и из helper совпадают. **`--type=tls` в Node** на клиенте сырой ClientHello не считается — смотрите лог exit или используйте boring-tls на клиенте.

Мини-сервер [`ja3-snif-server.mjs`](ja3-snif-server.mjs): в JSON `GET /ja3-snif` поля `ja3` (wire) и `ja3_sorted`; при `--profile-save-path` в файл профиля дополнительно попадают **`ja4`** (`fingerprint`, при успешном расчёте — `ja4_a`/`ja4_b`/`ja4_c`), опциональные `ja3_sorted_md5` и `ja3_sorted_string`.

Подробный разбор GREASE-очищенных полей и префикса в hex: **`--ja3-verbose`** (сам включает JA3). Env: при уже заданном `CLEAN_VPN_TLS_LOG_JA3` можно добавить `CLEAN_VPN_JA3_VERBOSE=1`.

**Важно:** эталонный **JA3 (MD5)** строится только из типов расширений, шифров и т.д.; **строки внутри ALPN (h2 vs http/1.1) в JA3 не входят**. Поэтому при `--http-vers=1.1` digest часто совпадает с режимом h2+http/1.1, а отличие смотрите в логах `offered_alpn` / в Wireshark.

Регрессия: `npm run test:boring-tls-smoke`; обновление MD5 эталона: `node scripts/dev-print-boring-tls-ja3.mjs`.

### Поля `response` (JSON)

- Успех: `{"ok":true,"alpn":"<negotiated>"}` (`alpn` может быть пустой строкой если не согласован).
- Ошибка: `{"ok":false,"error":"<текст>"}` и процесс helper завершается с ненулевым кодом.

## Сборка helper

Каталог `native/boring_tls/`: CMake, зависимость BoringSSL (FetchContent, закреплённый коммит), цель `boring-tls-helper`. Команда из корня репо:

Зависимости CMake: **git**, **patch** (POSIX), **cmake ≥ 3.16**, компилятор **C++17**, сеть для первого clone **BoringSSL** (`FetchContent`, закреплённый коммит — полный clone без shallow, иначе Git не находит SHA на некоторых системах).

При конфигурации CMake дерево BoringSSL проверяется на ожидаемый **SHA** (`MESHVPN_BORINGSSL_PINNED_SHA` в `native/boring_tls/CMakeLists.txt`) и при необходимости последовательно патчится файлами **`native/boring_tls/patches/boringssl-meshvpn-tls13-cipher-order.patch`** (порядок TLS 1.3 cipher в ClientHello), **`native/boring_tls/patches/boringssl-meshvpn-client-signature-algorithms-cert.patch`** (расширение **50** и `SSL_CTX_set_meshvpn_client_signature_algorithms_cert`), **`native/boring_tls/patches/boringssl-meshvpn-client-hello-extra-extensions.patch`** (opaque: `SSL_CTX_meshvpn_add_client_hello_extension`, вставка перед padding/PSK) и **`native/boring_tls/patches/boringssl-meshvpn-extra-extensions-emit-dedup.patch`** (не добавлять opaque-тип, если блок расширений уже содержит такой тип — см. `meshvpn_clienthello_extensions_contains_type`). Если коммит BoringSSL обновили без обновления патчей — конфигурация завершится ошибкой.

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
- **`--boring-tls-profile-ja3-strict`** (env `CLEAN_VPN_BORING_TLS_JA3_STRICT`): строгое совпадение `ja3_md5` из файла с фактическим ClientHello helper; в JSON профиля нужно **`permute_extensions: false`** (иначе `clean-vpn` и helper отвергнут конфигурацию как несовместимую с перестановкой расширений).

## Файл профиля и ja3-snif-server

- Запуск: `node scripts/ja3-snif-server.mjs --profile-save-path=/path/profile.json` (или env `JA3_SNIF_PROFILE_SAVE_PATH`).
- После успешного **`GET /ja3-snif`** профиль (компактный JSON: `user_agent`, JA3-компоненты с порядком, `ja3_md5`, **`ja4`**, при наличии списки **`signature_algorithms`** / **`signature_algorithms_cert`**, **`client_hello_extra_extensions`** (opaque тела расширений с захвата, без типов из denylist), `tls_info`) записывается **атомарно** (temp + rename).

## Ограничения (GREASE, padding, порядок расширений)

- **JA3** в файле считается по правилам Salesforce с **удалением GREASE** из списков. На wire браузер всё равно вставляет GREASE; побайтовое совпадение ClientHello и **JA4** могут отличаться даже при верных cipher/group и совпавшем JA3 MD5. Порядок **TLS 1.3 cipher suites** в ClientHello задаётся профилем через патч BoringSSL (`SSL_CTX_set_tls13_client_cipher_order`); GREASE-cipher по-прежнему добавляет стек отдельно.
- **Padding** (расширение 21) и **полный порядок расширений** задаются стеком BoringSSL; по умолчанию для `client_hello_profile` включена **`permute_extensions`** (как у Chromium). Строка **`profile_vs_wire extensions:`** на stderr — multiset-diff типов расширений (без GREASE) между профилем и wire; при совпадении multiset при **`ja3_verbose`** выводится заметка о расхождении **порядка**. Для эталонного wire-JA3 — **`permute_extensions: false`** и **`ja3_strict`** при необходимости. Без дополнительных патчей **полное совпадение JA3/JA4** с Chrome **часто недостижимо**.
- **Signature algorithms:** расширение **13** — **`SSL_CTX_set_verify_algorithm_prefs`**; **50** — второй патч (**`SSL_CTX_set_meshvpn_client_signature_algorithms_cert`**). В сохранённый профиль попадают **`signature_algorithms`** / **`signature_algorithms_cert`** из разбора ClientHello (`signatureAlgorithmsFromClientHelloBody` в `tls-clienthello-ja3.mjs`).
- **Opaque расширения:** патчи BoringSSL (`boringssl-meshvpn-client-hello-extra-extensions.patch` + **`boringssl-meshvpn-extra-extensions-emit-dedup.patch`**) и поле **`client_hello_extra_extensions`** в профиле; при успешной загрузке непропущенных opaque на stderr — **`meshvpn_opaque_extensions_added=N`**.
- **JA4 raw / типы расширений:** в строках `ja4_raw_*` каждый тип — **4 hex-цифры (uint16 big-endian)**. Расширение **Extended Master Secret** — IANA **23** (decimal), на проводе это **`0017`**, не **`0023`**. Последовательность **`0023`** в JA4 — это тип **0x0023 = 35** (например **session_ticket**), его наличие не означает EMS.
- **Extended Master Secret (ext 23 / в JA4 hex `0017`):** BoringSSL для ClientHello с минимальной версией **TLS 1.2** по умолчанию добавляет EMS. По умолчанию helper **подавляет** EMS, пока в **`extension_types`** **нет** типа **23** (decimal); если **23** есть — EMS уходит на провод. Если **`extension_types` отсутствует или пустой**, EMS подавляется. Поле **`emit_extended_master_secret`** (boolean) переопределяет это явно. На stderr — строка **`extended_master_secret ClientHello`**.
- **OCSP status_request (ext 5):** при типе **5** в **`extension_types`** профиля helper вызывает **`SSL_CTX_enable_ocsp_stapling`**.
- **EC point formats (ext 11):** для TLS **1.3-only** ClientHello BoringSSL **не отправляет** ext 11 (`ext_ec_point_add_clienthello`); без TLS 1.2 в минимальной версии или патча форка JA3 по ec_point_formats может расходиться с Chrome.

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
- **JA4** (FoxIO): расчёт в [`scripts/lib/tls-clienthello-ja4.mjs`](lib/tls-clienthello-ja4.mjs) и в **`boring-tls-helper`** (`ComputeJa4FromClientHelloBody`); профиль с `--profile-save-path` включает объект **`ja4`**; регрессия JA4: `npm run test:boring-tls-smoke` и `node scripts/test-tls-clienthello-ja4.mjs`.
- **Фаза 2** — см. раздел «Фаза 2» (полный H2 fingerprint в helper).

## Регрессионные тесты (локально, без продакшена)

После `npm run build:boring-tls-helper`:

- `npm run ja3-snif-server` — локальный HTTPS (`127.0.0.1:8443`), JSON по `GET /ja3-snif`: User-Agent, **JA3**, **JA3 sorted**, **JA4**, поля ClientHello для сравнения с Wireshark; опционально `--profile-save-path` для автосохранения компактного профиля; см. [`scripts/ja3-snif-server.mjs`](ja3-snif-server.mjs).
- `npm run test:boring-tls-smoke` — проверки: бинарь, ошибки конфига/TCP, stdin EOF, полный TLS 1.3 к `tls.Server`, **JA3** (ALPN `h2` + `http/1.1` как у client в clean-vpn; эталонный wire digest при **`permute_extensions: false`**), **JA4** на stderr при `log_ja3` (сверка с Node по тому же TCP), отсутствие `ja3_md5=`/`ja4=` на stderr без `log_ja3`, **JA3/JA4 stderr при `log_ja3`**, **`permute_extensions`** — разный wire JA3 при неизменном **`ja3_sorted_md5`**, конфликт **`ja3_strict` + permute**, **SIGTERM** после handshake (не Windows).
- `npm run test:tls-ja4` — JA4 по спецификации FoxIO (`scripts/test-tls-clienthello-ja4.mjs`), без сборки helper.

## Что остаётся вне автотестов

1. **Прод e2e:** client `--type=boring-tls` ↔ exit `--type=tls` на реальном VPS/сертификатах.
2. **Сборка в CI:** закрепить образ/agents с CMake + C++17 при необходимости.
3. ~~**Фаза 2 / JA4 в helper** — по необходимости дублировать JA4 в native helper для паритета с ja3-snif.~~ (JA4 в helper и smoke-сверка с Node.)
