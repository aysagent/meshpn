# Stamp-P4 + AddOn C6: первая аппаратная проверка

29 октября 2026. Параллельно подключены Waveshare P4 и Camic ESP32-S3.
Wi-Fi Mac не переключался; flash соседних плат не изменялась.

## Идентификация и прошивка

- Stamp: ESP32-P4 v1.3, eFuse MAC E8F60AE25DC3, 16 MiB flash,
  32 MiB PSRAM; отдельная локальная привязка .board-binding-m5_stamp_p4_c6.json.
- Первичная запись возможна через встроенный USB Serial/JTAG 303a:1001:
  usb_reset программно ввёл плату в ROM. Проверены модель/target образа и MAC;
  flash-p4-verified.py повторно прочитал MAC в том же соединении перед записью.
  Для этого первого provisioning использован явный идентифицированный USJ-порт,
  а не автоматический выбор flash-device.py (он выбирает HS app/ROM).
- После одной записи через USJ обычный RTS reset оставил плату в загрузчике.
  Восстановлено watchdog reset без ручных кнопок и без повторной записи.
- После запуска доступен HS NCM+CDC, serial E8F60AE25DC3. Штатная команда
  BOARD=m5_stamp_p4_c6 P4_REVISION=1 bash scripts/flash.sh прошла полный цикл
  1200-baud app → HS ROM → MAC verification → flash → watchdog → app CDC.
- Встроенный USJ остаётся отдельным каналом логов; HS используется для Ethernet
  и штатной последующей автопрошивки. Кнопки/переподключение не требовались.

## Два найденных сбоя и исправления

1. После сканирования C6 повторяет STA_START/AP_START без соответствующего STOP.
   Повторный esp_netif_start доходил до netif_add и assert «netif already added».
   Добавлена проверка членства в netif_list внутри esp_netif_start_api, в lwIP
   контексте. Это учитывает добавленный, но ещё не поднятый STA, поэтому обычный
   netif_is_up недостаточен. После реального STOP интерфейс добавляется штатно.
   SDK не изменён: P4 собирает проверяемую проектную копию esp_netif_lwip.c.
   Лог после исправления подтверждает игнорирование повторных STA/AP событий;
   затем STA получает DHCP, USB/AP NAPT включены.

2. Первый /api/status вызвал отдельный PANIC в httpd. Снят coredump:
   handler_api_status → time → gettimeofday → lock_init_generic → abort.
   Ленивое создание s_time_lock не смогло выделить внутреннюю память, уже занятую
   большим JSON диагностики. В начале app_main устанавливаются cJSON hooks:
   сначала PSRAM, затем обычная byte-addressable память; free остаётся совместимым.
   Mutex libc времени инициализируется до запуска сетевых задач и HTTP.

## Проверки

- SDIO 4-bit/40 MHz, C6 INIT и STA/AP работают на профиле GPIO43–48/reset42.
  C6 не перепрошивался. Точная версия его firmware ещё не зафиксирована.
- Mac: HS NCM, en19, DHCP 192.168.12.2, gateway 192.168.12.1.
  macOS IORegistry USBSpeed=3 (High-Speed), отдельный serial Stamp.
- Админка http://dongle-stamp.local/login: HTTP 200, адрес 192.168.12.1.
- STA DHCP 192.168.1.19; AP 192.168.13.1, SSID MeshPN_9d5575.
  Сохранённый Wi-Fi профиль сохранился; VPN выключен.
- HTTPS example.com с curl --interface en19: HTTP 200, 577 bytes, ~0.2 s.
- После обоих исправлений: 20 status-запросов за 30 s, boot_count=28 неизменен,
  uptime 353→383 s, USB/STA online; internal free ~89 KiB,
  historical minimum ~67 KiB. До финальной повторной прошивки новых PANIC не было.
- Полный test-host.sh прошёл. Дополнительные тесты выполняют patched SDK callback
  (повторный START down/up, STOP/restart, STA+AP) и реальные cJSON parse/print/delete
  с 2000 узлов и production hooks; ASan/UBSan.
- Сборки Stamp и Waveshare с исправлениями прошли. Waveshare не прошивалась.

Это начальная проверка, не длительный soak или замер WAN-пропускной способности.
Приёмка AP на телефоне, VPN и три контролируемых автопрошивки с наблюдением
uptime соседней платы остаются отдельными пунктами общего плана.

## Финальная установленная версия

Установлен commit **69c4276**, build API без dirty. Повторная штатная
автопрошивка через HS завершилась возвратом CDC с тем же serial.
После неё boot_count=29, STA/USB online, VPN off. Локальная загрузка 8 MiB
за 1.203 s: **55.79 Mbit/s**; это плата → Mac, не WAN benchmark.
После нагрузки десять последовательных status-запросов не изменили boot count;
internal free 89731 B, historical minimum 67408 B. Приложение доступно по
http://dongle-stamp.local/ (USB 192.168.12.1).
