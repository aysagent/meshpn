# P4 / C6 Wi-Fi 6: проверка 25 октября 2026

Текущий uplink ограничен роутером: HTTP-страница gateway `192.168.1.1` сообщает
модель **ZTE F680**. [Спецификация ZTE](https://www.zte.com.cn/z/h5KJQT.html)
указывает 802.11b/g/n на 2,4 ГГц и a/n/ac на 5 ГГц. 802.11ax у этой модели
не заявлен. Это согласуется с AP record платы: 11n=true, 11ax=false,
secondary_channel=0. Название модели получено со страницы без авторизации;
настройки роутера не менялись.

ESP32-C6 поддерживает Wi-Fi 6 в диапазоне 2,4 ГГц. Для него 802.11ax — HE20;
HT40 относится к 802.11n. [ESP-IDF 5.5.5](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32c6/api-guides/wifi.html#wifi-bandwidth-mode)
и [спецификация C6](https://documentation.espressif.com/esp32-c6_datasheet_en.html).

## Изменения

- P4 при настройке STA/AP задаёт 20 МГц и разрешает b/g/n/ax. Если C6 явно
  отвергает AX (NOT_SUPPORTED/INVALID_ARG), сохраняется рабочий b/g/n режим с
  предупреждением; реальная маска видна в статусе. Остальные ошибки передаются
  вызывающему коду. XIAO сохраняет прежний HT40 профиль.
- `wifi.radio.sta_protocol` / `ap_protocol`: readback маски и отдельных b/g/n/ax
  разрешений. Это **не согласованный режим соединения**.
- В основной строке Wi-Fi различаются «Wi-Fi 6 allowed», отсутствие AX у
  текущей точки и недоступный negotiated mode. Список сетей отмечает AX в
  ответах `/api/wifi/scan`; открытие админки по-прежнему не запускает скан.
- `wifi.hosted.coprocessor_firmware` запрашивается один раз после ассоциации,
  в manager task, вне HTTP. При ошибке повторов нет. Запрос negotiated PHY
  разрешён после успешного version RPC; любая его ошибка также защёлкивается,
  чтобы старый C6 не создавал периодические таймауты. Native S3 getter сохранён.
- Protocol/firmware данные сохраняются в sanitized performance reports.

## Что подтверждено на подключённой P4

Привязанная плата `E8F60AE395D0` автоматически прошита; boot #64,
приложение `d463600-dirty` с изменениями этого этапа.

- STA/AP bandwidth readback: **20/20 МГц**.
- STA/AP protocol readback тогда: **0x47 / 0x47**. Уточнение 26 октября:
  ESP-Hosted 1.4.7 терял аргумент интерфейса в getter, поэтому оба запроса
  читали STA. Независимое подтверждение AP этим снимком не получено.
- Текущая точка по-прежнему сообщает **802.11n без AX**, канал 4/20 МГц.
- STA подключена; USB DIRECT HTTP запрос к 1.1.1.1 получил HTTP 301.
- На установленной заводской C6 firmware RPC `0x15e` не ответил за пять секунд.
  Firmware version поэтому **unknown**, а не версия host component.
  Поздние снимки собираются примерно за 97 мс; периодических попыток версии нет.
- Negotiated PHY API недоступен. Фактическое HE20 соединение **не подтверждено**.
- Для AP AX был запрошен, но прежний readback недостоверен; HE beacon/client
  association отдельно не проверялись. Getter исправлен 26 октября и проверен
  на разных масках STA/AP (7/3); это не проверка согласованного AX-соединения.
- Wi-Fi Mac не переключался. C6 slave firmware не перепрошивалась.

Для подтверждения uplink Wi-Fi 6 нужна доступная точка с 802.11ax на **2,4 ГГц**.
На F680 переключатель/новая прошивка P4 эту аппаратную возможность не добавит.
Для подтверждения AP Wi-Fi 6 нужен AX-capable клиент и проверка фактической
ассоциации/beacons. `protocol bitmap` сам по себе этого не доказывает.

## Проверки кода

Сборки P4 и XIAO; полный host suite на IDF 5.5.5; ASan/UBSan варианты radio cache
с отсутствующим/доступным firmware RPC; однократность запроса и latch ошибок,
readers без RPC, HE20/bgnax configure, явный legacy fallback и передача ошибок.
UI проверяет различие разрешённых протоколов и negotiated mode. Performance
runner suite: 57 passed. После выравнивания stub AX constant с IDF (`0x40`)
целевые radio/config/UI/export tests повторены.
