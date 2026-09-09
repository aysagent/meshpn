# MeshPN performance testing

Цель — отделить предел платы от ограничений USB, Wi‑Fi радиоканала и WAN. Каждый эксперимент меняет только один параметр прошивки.

## 1. Фиксируем baseline

Перед каждой прошивкой сохранять:

```bash
git rev-parse HEAD
git status --short
git diff -- device/boards/xiao_esp32s3/sdkconfig.defaults
bash device/scripts/test-host.sh
```

Результат host-тестов должен быть чистым. Для аппаратного результата использовать таблицу/JSON с commit, датой, версией IDF, профилем USB, настройками AP/HTTPS, RSSI, каналом и температурой.

## 2. Автоматический локальный throughput-тест

Интернет speedtest не использовать как основной показатель: он смешивает скорость платы с качеством WAN. Поднять `iperf3 -s` на проводном компьютере в той же LAN, куда подключён STA роутера. Клиентом выступает устройство за AP или USB Ethernet.

Для каждого пути выполнить минимум 5 прогонов TCP по 30 секунд, отбросить первый и сохранить JSON:

```bash
iperf3 -c 192.168.1.100 -t 30 -J > ap-down-01.json
iperf3 -c 192.168.1.100 -t 30 -R -J > ap-up-01.json
```

Повторить для:

| Сценарий | AP | USB | Что измеряет |
|---|---:|---:|---|
| AP idle | traffic | management only | AP→STA NAT |
| USB idle | management only | traffic | USB→STA NAT |
| AP + USB | traffic | traffic | совместное использование радио и CPU |
| AP disabled | n/a | traffic | контрольный USB baseline |

Скрипт-обёртка должен запускать серии прогонов, проверять код возврата, извлекать `bits_per_second`, `retransmits`, `jitter_ms` из JSON и печатать median/p10/p90. Сохранять также stderr и timestamp; не сравнивать одиночный лучший прогон.

## 3. Контроль условий

- Один и тот же роутер, канал, положение платы, сервер и клиент.
- На клиенте отключить cellular fallback, сторонний VPN/proxy и параллельные загрузки.
- Не открывать админку во время прогона: scan может временно прервать APSTA.
- Зафиксировать RSSI и negotiated channel width (HT20/HT40); HT40 — только запрос, а не гарантия.
- Для AP и USB использовать разные клиенты либо явно проверять таблицу маршрутов, чтобы телефон не выбрал другой интерфейс.

## 4. Автоматический сбор телеметрии

До и после серии каждые 2 секунды записывать `/api/status` (или эквивалентный endpoint) в NDJSON. Минимальные поля:

`timestamp`, `sta_connected`, `sta_rssi`, `sta_channel`, `ap_clients`, `usb_link`, `usb_tx_dropped`, `usb_tx_retried`, `ap_ip4_rx`, `usb_ip4_rx`, `temperature`, `heap_internal_free`, `heap_internal_min`, `heap_dma_free`, `heap_psram_free`, `heap_psram_min`.

Автоматически проверять:

- нет reboot/watchdog/USB disconnect в журнале;
- counters не растут аномально относительно baseline;
- minimum heap и PSRAM не имеют монотонного падения;
- AP/USB остаются подняты после серии и после reconnect STA.

Если endpoint ещё не отдаёт поле, фиксировать это как отдельный пробел, а не подставлять ноль.

## 5. Latency и потеря пакетов

Параллельно с `iperf3` запускать `ping` на LAN-сервер (не в интернет) и записывать min/median/p95/max. Отдельно выполнить UDP-тест `iperf3 -u` с фиксированной скоростью 5 и 10 Mbit/s; сравнить datagrams lost и jitter. Это выявляет перегрузку буферов, которую TCP может скрывать ретрансляциями.

## 6. Нагрузочная и регрессионная проверка

Автоматизировать 30–60 минутный сценарий: throughput 10 минут, idle 5 минут, повторить 3 раза; затем перезапустить роутер и проверить автоматический reconnect. После этого выполнить USB unplug/replug, sleep/resume клиента и повторно проверить DHCP, DNS, AP и админку.

Критерии стабильности: нет reset/USB flap, DHCP восстанавливается, AP-клиент получает интернет, админка доступна по USB, minimum heap не уменьшается от цикла к циклу.

## 7. Как принимать следующий Wi‑Fi эксперимент

1. Прошить образ и убедиться, что boot/AP/USB исправны.
2. Выполнить одинаковую серию baseline и новой версии (не менее 5 прогонов на направление).
3. Сравнивать median и p10, а не только максимум; отдельно учитывать drops/retransmits и стабильность.
4. Оставлять изменение только если прирост повторяется минимум в двух сериях и нет регрессии USB/AP или памяти. Иначе откатывать одним коммитом.

Текущие подробности APSTA и адреса интерфейсов: [`device/docs/apsta-benchmark.md`](device/docs/apsta-benchmark.md). Исторические результаты USB: [`device/docs/benchmark-gonogo.md`](device/docs/benchmark-gonogo.md).
