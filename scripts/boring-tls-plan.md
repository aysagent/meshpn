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
| `log_ja3` | bool | если `true`, после исходящего ClientHello — строка `boring-tls-helper: ja3_md5=…` на stderr; при `ja3_verbose` добавляются поля и `hex_preview` handshake |
| `ja3_verbose` | bool | расширенный JA3 на stderr; имеет смысл вместе с `log_ja3` |

### JA3 в логах (без tcpdump)

Эталонный расчёт JA3: [`tls-clienthello-ja3.mjs`](./lib/tls-clienthello-ja3.mjs). На **exit** (`--type=tls`) при `--tls-log-ja3` или `CLEAN_VPN_TLS_LOG_JA3=1` — по входящему TCP до полного ClientHello. На **client** с `--type=boring-tls` — тот же digest на stderr helper при пробросе `log_ja3`/`ja3_verbose` из clean-vpn. Для одной TCP-сессии digest exit и helper совпадает. **`--type=tls` в Node** сырый ClientHello не экспонирует — JA3 в этом процессе не пишется; смотрите лог exit или используйте boring-tls на клиенте.

Подробный разбор GREASE-очищенных полей и префикса в hex: **`--ja3-verbose`** (сам включает JA3). Env: при уже заданном `CLEAN_VPN_TLS_LOG_JA3` можно добавить `CLEAN_VPN_JA3_VERBOSE=1`.

**Важно:** эталонный **JA3 (MD5)** строится только из типов расширений, шифров и т.д.; **строки внутри ALPN (h2 vs http/1.1) в JA3 не входят**. Поэтому при `--http-vers=1.1` digest часто совпадает с режимом h2+http/1.1, а отличие смотрите в логах `offered_alpn` / в Wireshark.

Регрессия: `npm run test:boring-tls-smoke`; обновление MD5 эталона: `node scripts/dev-print-boring-tls-ja3.mjs`.

### Поля `response` (JSON)

- Успех: `{"ok":true,"alpn":"<negotiated>"}` (`alpn` может быть пустой строкой если не согласован).
- Ошибка: `{"ok":false,"error":"<текст>"}` и процесс helper завершается с ненулевым кодом.

## Сборка helper

Каталог `native/boring_tls/`: CMake, зависимость BoringSSL (FetchContent, закреплённый коммит), цель `boring-tls-helper`. Команда из корня репо:

Зависимости CMake: **git**, **cmake ≥ 3.16**, компилятор **C++17**, сеть для первого clone **BoringSSL** (`FetchContent`, закреплённый коммит — полный clone без shallow, иначе Git не находит SHA на некоторых системах).

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

- `npm run ja3-snif-server` — локальный HTTPS (`127.0.0.1:8443`), JSON по `GET /ja3-snif`: User-Agent, JA3 и поля ClientHello для сравнения с Wireshark; см. [`scripts/ja3-snif-server.mjs`](ja3-snif-server.mjs).
- `npm run test:boring-tls-smoke` — проверки: бинарь, ошибки конфига/TCP, stdin EOF, полный TLS 1.3 к `tls.Server`, **JA3** (ALPN `h2` + `http/1.1` как у client в clean-vpn), отсутствие `ja3_md5` на stderr без `log_ja3`, **JA3 stderr при `log_ja3`**, **SIGTERM** после handshake (не Windows).

## Что остаётся вне автотестов

1. **Прод e2e:** client `--type=boring-tls` ↔ exit `--type=tls` на реальном VPS/сертификатах.
2. **Сборка в CI:** закрепить образ/agents с CMake + C++17 при необходимости.
3. **Фаза 2 / JA4** — по необходимости см. выше.
