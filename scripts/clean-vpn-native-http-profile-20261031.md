# Ограниченный HTTP-профиль, 31 октября

Экспериментальный cold профиль теперь задаёт User-Agent для HTTP/1.1 и HTTP/2,
порядок четырёх HTTP/2 псевдозаголовков и допускает отсутствие клиентского
SETTINGS_MAX_CONCURRENT_STREAMS (3). Это отдельные параметры приложения;
совпадение ClientHello/JA3/JA4 не подтверждает их автоматически.

Пример: [chromium-156-bounded-http.json](../fixtures/native-tls-profiles/chromium-156-bounded-http.json).
Он производен от прежнего ограниченного Chromium 156 TLS-профиля; UA и порядок
псевдозаголовков взяты из сохранённого [browser capture](../fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47-h2.json).
Это HeadlessChrome/Linux, а не произвольный пользовательский Chrome.
На Radxa/VPS этот новый профиль и бинарник **не установлены**.

```json
"http": {
  "user_agent": "ExampleBrowser/1.0",
  "http2_pseudo_header_order": [":method", ":authority", ":scheme", ":path"]
}
```

В объекте допустимо одно или оба поля. UA — 1–512 печатных ASCII байт без
пробелов по краям; CR/LF/NUL, Unicode и дополнительные поля отвергаются до
соединения. Все четыре pseudo-header обязательны, каждый ровно один раз.
Значения остаются `POST`, `https`, заданное имя exit и `/clean-vpn`.
Авторизация exporter+PSK сохраняется, клиентский JSON не может подменить её.
Профиль без `http` сохраняет прежнее поведение, в том числе отсутствие UA.

## Что измерено

Linux ARM64, NIC-less контейнер, без TUN, маршрутов, системного DNS или изменения
рабочих узлов. Независимый TLS endpoint расшифровывает локальный тестовый поток,
разбирает реальные H2 кадры и HPACK через существующий observer. Три свежих
процесса fixture дали шесть cold samples (повторы до ожидаемого HTTP 403).
[Сохранён разбор фактических кадров в обезличенном виде](../fixtures/native-browser-captures/native-bounded-http-20261031.json):
без bearer, URL, authority и ключевого материала.

Во всех samples совпали заданные UA, порядок pseudo-headers, один SETTINGS
с IDs 1/2/4/6 и окно 1 MiB. Независимый H1 endpoint также увидел UA и фиксированный
аутентифицированный POST. Отдельные native integration проверяют H1/H2 и combo,
ALPS/fallback, неверные CA/имя/PSK, reconnect и ограничения профиля.

Повтор после CMake build с fixture:

```bash
CVPN_BUILD=native/clean_vpn/build node --test scripts/test-native-http-profile-wire.mjs
CVPN_BUILD=native/clean_vpn/build node --test scripts/test-native-tls-profile.mjs
node --test scripts/test-native-profile-policy.mjs
```

Новые [capabilities](../fixtures/clean-vpn-native-profile-policy-capabilities-20261031.json)
описывают `bounded-cold-http-v1`; прежняя dated evidence не переписана.

Отдельный [отчёт по трём полям запроса](../fixtures/clean-vpn-native-http-request-fields-20261031.json)
показывает совпадение UA, порядка pseudo-headers и порядка IDs SETTINGS.
Полный prefix diff включён в тот же документ: значения окон, остальные headers,
priority и HPACK продолжают различаться. Такой результат не разрешает профиль
политикой и не доказывает browser equivalence. HTTP-поля измерены на собственном
TLS endpoint; пассивный encrypted pcap их не раскрывает.

```bash
node scripts/clean-vpn-native-h2-compare.mjs --request-fields BROWSER.json NATIVE.json
```

## Сохранившиеся различия

Browser имеет stream window 6 MiB, connection window 15 MiB, header limit
256 KiB; наш профиль сохраняет 1 MiB/1 MiB/8 KiB. Сервер по-прежнему принимает
только один authenticated stream, push запрещён, queue/memory caps не повышены.
Отсутствие client SETTINGS 3 не расширяет server admission policy.

Chromium посылает HEADERS priority (exclusive, weight 256), native — нет.
Закреплённый nghttp2 в `nghttp2.h` прямо объявляет `pri_spec` устаревшего
`nghttp2_submit_request` игнорируемым; изменение одного аргумента не даст
wire-мимикрию. Нужна отдельная проверяемая доработка, здесь она не реализована.
Также различаются GET navigation и POST carrier, обычные headers/HPACK, тело,
тайминги и повторное использование соединений. Browser comparison остаётся
`different`, `browserEquivalent:false`. ALPS не согласуется capture endpoint;
его negotiated поведение отдельно проверяют native fixtures.

[Итоговая проверка](../fixtures/clean-vpn-native-http-profile-20261031.json): CTest 14/14,
native profile integration 22/22, независимые H1/H2 wire 2/2, policy 11/11; без
пропусков. SHA engine и fixture закреплены отдельно в receipt.
