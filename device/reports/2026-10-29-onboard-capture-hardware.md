# Обновление двух P4 и аппаратная проверка захвата профиля

29 октября 2026. Финальная прошивка обеих плат: **bfa0756**, `PROFILED_TLS=1`,
ESP-IDF 5.5.5. Wi-Fi Mac, firewall, роутер и прошивки C6 не менялись.
Camic ESP32-S3, подключённая рядом, не прошивалась.

## Найденный и исправленный дефект

Первая профилированная сборка зациклилась на старте: `Stack protection fault`
в задаче main, до запуска USB и админки. Символизация UART-дампа показала
`__ssprint_r` / `_svfprintf_r`; стек main — 6144 байта, а кадр `app_main` —
4336 байт. Локальные полные VPN status/config оставляли недостаточно места для
вложенных вызовов при инициализации профилированного TLS на P4.

Исправление bfa0756:

- LED читает два нужных флага через существующие getters, без полного VPN status.
- Загрузка конфигурации вынесена в отдельный noinline helper; её кадр не остаётся
  на стеке на протяжении всего startup/основного цикла.
- Кадр `app_main`: P4 816 байт, S3 784; helper 1392/1408 байт.
- Компилятор ограничивает кадры app_main.c до 2048 байт и сохраняет `.su` отчёт.
  Это контроль размера отдельных кадров, не доказательство максимума всей цепочки.

Обе платы восстановлены без кнопок и переподключения: Waveshare через её UART
CH343, Stamp через встроенный USB Serial/JTAG. Перед записью сверены eFuse MAC
в той же открытой ROM-сессии; recovery прошла с первой попытки на каждой плате.
После восстановления финальная повторная прошивка обеих плат прошла уже штатно:
HS CDC → ROM → MAC check → запись → watchdog reset → возвращение app CDC.
NVS не стиралась. MAC-привязки Waveshare и Stamp остались раздельными.

## Реальный браузер и платы

Chrome **156.0.8078.49** на Mac, отдельные временные browser profiles, настоящие
страницы и API прошивки по USB. Никакой имитации API/NVS или внешнего capture
сервиса в этих проверках нет. Сертификаты/системные доверенные CA не устанавливались.

| Проверка | Waveshare | Stamp |
|---|---|---|
| Локальный ClientHello capture | PASS | PASS |
| Preview JA3/JA4 перед сохранением | PASS | PASS |
| Сохранённый профиль | wave Mac Chrome | stamp Mac Chrome |
| Профиль появился выбранным в форме | PASS | PASS |
| Авторизация capture API | без токена HTTP 401 | без токена HTTP 401 |
| Второй одновременный capture | HTTP 409 | HTTP 409 |
| Cancel без добавления профиля | PASS | PASS |
| Истечение без ClientHello | 25.28 s, expired | 25.28 s, expired |
| Неверный ожидаемый JA3 при импорте | HTTP 422, не сохранён | HTTP 422, не сохранён |
| Каталог пережил повторную прошивку | PASS | PASS |
| Каталог пережил отдельный API reboot | PASS | PASS |
| VPN сам не включился | остался disabled | остался disabled |
| Wi-Fi после reboot | online | online |
| Соседняя плата при reboot | uptime 24→43 s | uptime 14→32 s |

Отпечатки реальных захваченных соединений:

- Waveshare: JA3 `f788b6ed9628e07dd92a2ee64afdd1b9`,
  ID `c-8132a64de3cc88c3e56e85f1`.
- Stamp: JA3 `f28dcf55ecc9bb20238bfaafd79a9595`,
  ID `c-332730f197f0589bd585cdf5`.
- JA4 у обоих: `t13d1517h2_8daaf6152771_cb7bf5808d99`.

Различие JA3 соответствует отдельным снимкам с переставляемыми расширениями
Chromium. Два профиля оставлены в своих платах, по одному на устройство.
Выбор в рабочей VPN-конфигурации не менялся, Save and apply для включения VPN
не нажимался. Предыдущие ключи/endpoint и Wi-Fi настройки не заменялись.

## После обновления

- HTTP-админки доступны на 192.168.10.1 и 192.168.12.1; локальный захват использовал
  настроенные имена dongle.local и dongle-stamp.local.
- `curl -4 --interface en17/en19 https://example.com`: HTTP 200, 577 bytes с каждой
  платы после окончательной прошивки и reboot (0.160 / 0.366 s).
- По 20 снимков status после reboot: USB host_ready и Wi-Fi online, uptime растёт.
  Main stack minimum remaining: 2932 / 2948 байт. В последних снимках свободно
  internal 84351 / 85755, DMA 44747 / 46151 байт. Короткие снимки не доказывают
  отсутствие утечки или достаточность памяти при одновременном VPN/capture.
- USB-local HTTP: warm-up + один измеряемый ответ по 8 MiB, обе платы завершили
  без предупреждений/ребутов. Waveshare **52.57**, Stamp **55.32 Mbit/s**.
  Это локальная передача board→USB→Mac, не скорость Wi-Fi/VPN/интернета; короткие
  проверки шли параллельно, поэтому это smoke-test, не сравнительный benchmark.
- Host suite PASS; сборки P4/P4/S3 с compile-time stack guard PASS.

## Артефакты и оставшиеся проверки

Локально, вне git: `device/perf-results/onboard-hardware-20261029/`:
`*-flash.log`, `*-recovery.log`, `*-capture.json/png`, `*-lifecycle.json`,
`*-verified.json`, `verify-final.log`, `https-final.log`,
`wave-usb-local/usb-local-5DCKuc`, `stamp-usb-local/usb-local-sTFIGS`.
Первый запуск perf runner был остановлен sandbox на read-only `route` проверке;
эти failed preflight каталоги сохранены, в измерения не включены.

Телефон/Safari и AP-path захвата ещё не проверены. Успешный аппаратный VPN-сеанс
с текущим native exit, выбор сохранённого профиля в активном VPN, wire JA3/JA4
при reconnect, HTTP/2 traffic и память под этой нагрузкой остаются отдельной
приёмкой. Локальный входящий peer на Mac ограничен текущим Block all incoming;
firewall не менялся, внешний exit в этой сессии не запускался. DIRECT AP+STA soak
и прежняя RF-асимметрия также не закрываются этими USB-проверками.
