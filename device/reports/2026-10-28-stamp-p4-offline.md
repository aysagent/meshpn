# Stamp-P4 + AddOn C6: подготовка без платы, 28 октября 2026

Профиль scaffold заменён полной конфигурацией P4 HS. Основания и распиновка:
[инструкция](../docs/m5-stamp-p4-c6.md). USB2_HOST_DP/DM работают с выделенным
HS PHY; GPIO26/27 остаются FS и для этой сборки не используются.

Реализовано:

- 16 MiB flash, PSRAM 200 MHz/XIP, HS NCM/CDC, SDIO CLK43/CMD44/D0–D3 45–48,
  reset/power enable GPIO42; логи на встроенном USB Serial/JTAG.
- Отдельный USB product Stamp и локальная привязка board + target + eFuse MAC.
  Старые привязки Waveshare/XIAO сохранены. Первичная ROM-привязка требует PORT.
- P4 проверяет ROM MAC в одном соединении с записью, включая app → ROM.
  Неопределённый выбор, чужой MAC/модель и неверная сборка не допускаются.
- CMake проверяет выбор платы и генерирует meshvpn-board.json; helper проверяет
  board/target/profile до сброса. Добавлены три npm-команды Stamp.
- Отдельный P4_REVISION=3 с отдельным sdkconfig/build; по умолчанию v1.x.

Проверки:

| Проверка | Результат |
|---|---|
| Stamp v1, build-m5_stamp_p4_c6-ncm-3818274904-wg1 | Успешно; app 0x138630, 59% раздела свободно |
| Stamp v3, build-m5_stamp_p4_c6-ncm-551722236-wg1 | Успешно; app 0x138ea0, 59% раздела свободно |
| Waveshare, build-waveshare_esp32_p4_wifi6-ncm-963284969-wg1 | Успешно |
| XIAO, build-xiao_esp32s3-ncm-3803681612-wg1 | Успешно |
| Полный scripts/test-host.sh | Успешно, включая ASan/UBSan и TLS trust проверки |
| Финальный tests/test_flash_device.py | 42 теста успешно |
| Итоговые sdkconfig и бинарники Stamp | Проверены GPIO, HS, flash, console, board identity, USB product |
| git diff --check | Успешно |

Полный host suite запускался до добавления двух последних отрицательных
проверок ROM ambiguity / отсутствующей build identity; финальные 42 flash-теста
затем выполнены отдельно. Все USB-объекты этих тестов — моки, реальная плата
не перечислялась, не сбрасывалась и не прошивалась. Wi-Fi Mac не менялся.

Не подтверждены: ревизия реального Stamp, совместимость заводской C6 firmware,
качество HS-подключения, iPhone NCM, скорость и автопрошивка реального Stamp.
Вечерняя аппаратная приёмка добавлена в plan.md и инструкцию. Заводская C6
прошивка не включена в образ P4 и автоматически не заменяется.
