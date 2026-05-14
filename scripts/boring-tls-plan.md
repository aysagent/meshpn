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

### Поля `response` (JSON)

- Успех: `{"ok":true,"alpn":"<negotiated>"}` (`alpn` может быть пустой строкой если не согласован).
- Ошибка: `{"ok":false,"error":"<текст>"}` и процесс helper завершается с ненулевым кодом.

## Сборка helper

Каталог `native/boring_tls/`: CMake, зависимость BoringSSL (FetchContent, закреплённый коммит), цель `boring-tls-helper`. Команда из корня репо:

Зависимости CMake: **git**, **cmake ≥ 3.16**, компилятор **C++17**, сеть для первого clone **BoringSSL** (`FetchContent`, закреплённый коммит — полный clone без shallow, иначе Git не находит SHA на некоторых системах).

```bash
npm run build:boring-tls-helper
# эквивалентно:
cmake -S native/boring_tls -B native/boring_tls/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/boring_tls/build -j
```

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

- `npm run test:boring-tls-smoke` — семь проверок: бинарь, ошибки конфига/TCP, stdin EOF, полный TLS 1.3 к `tls.Server`, **JA3** (ALPN `h2` + `http/1.1` как у client в clean-vpn), **SIGTERM** после handshake (не Windows).

## Что остаётся вне автотестов

1. **Прод e2e:** client `--type=boring-tls` ↔ exit `--type=tls` на реальном VPS/сертификатах.
2. **Сборка в CI:** закрепить образ/agents с CMake + C++17 при необходимости.
3. **Фаза 2 / JA4** — по необходимости см. выше.
