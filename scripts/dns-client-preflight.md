# DNS v1: один read-only отчёт для VPS 2 и Radxa

Новая команда дополняет прежнюю диагностику связью «работающая служба →
процесс/интерфейс → наблюдаемые источники конфигурации». Это **не установщик**:
не меняет resolver, маршруты, firewall, forwarding или unit-файлы; не запускает,
не останавливает и не перезагружает службы. SSH-доступ ассистенту не нужен.

Из актуальной копии репозитория на **VPS 2**:

```bash
sudo node scripts/dns-client-preflight.mjs --client=vps2 --probe
```

На **Radxa** (в root-shell `sudo` не требуется):

```bash
sudo node scripts/dns-client-preflight.mjs --client=radxa --probe
```

Скопировать **весь вывод** между `CLEAN-VPN DNS CLIENT PREFLIGHT BEGIN/END`,
подписав машину. Root нужен только для полноты чтения: в прежнем отчёте VPS 2
netplan-файл был недоступен с EACCES. Можно запустить без root: недостающие
права попадут в отчёт, а не будут сочтены отсутствием конфигурации.
Права root не включают никаких setters в скрипте.

`--probe` отправляет реальные запросы `example.com` через **текущий** resolver;
они могут уйти напрямую. Уберите флаг, если нужны только локальные чтения.
Даже успешные DNS-пробы не являются тестом отсутствия утечек. Отчёт содержит
IP, домены, имена интерфейсов, config paths и разрешённые DNS-параметры argv:
перед публикацией его следует просмотреть. Environment, полные argv, журналы,
значения неизвестных параметров и исполняемых hooks не выводятся.

## Что добавлено к прежнему отчёту

- Для трёх фиксированных служб — MainPID, InvocationID, расположение unit/
  drop-ins, состояние, необходимость daemon-reload и признаки namespace/root
  overrides. `ExecStart` и `Environment` не запрашиваются.
- Для активного `dnsmasq.service` — executable из узкого списка, start-time
  процесса, совпадение cgroup службы и net/mnt/PID namespace с диагностикой.
  PID/start-time/InvocationID повторно проверяются до/после сбора конфигов.
  Если процесс сменился, его данные не объявляются согласованным снимком.
- Из argv dnsmasq — только разрешённые DNS-параметры и источники config. Для
  `conf-file`/`conf-dir` читаются лишь `/etc/dnsmasq.conf` и поддерево
  `/etc/dnsmasq.d`; выход canonical path за эти корни запрещён. Произвольные
  пути, stdin-конфиг, hooks, servers-file/resolv-file и неизвестный синтаксис
  требуют review, не исполняются и не обходятся как доверенные источники.
- Поддерживаются простые unquoted include и однородные suffix-фильтры conf-dir:
  исключающие `.old` либо включающие `*.conf`. Смешанные фильтры, loops/repeats,
  quotes/неизвестные опции отмечают неполноту. Не реализуется полный parser
  dnsmasq и не утверждается, что текущие bytes уже загружены процессом.
- На networkd-клиенте — `NETWORK_FILE`, DNS/domains и состояние из
  `/run/systemd/netif/links/<ifindex>`, затем отфильтрованный выбранный `.network`
  файл с проверкой метаданных до/после чтения. Это надёжнее угадывания выбранного
  файла по имени, но runtime-format остаётся version-dependent. Drop-ins и
  политика uplink всё равно проходят review по основному diagnostic inventory.

Семантика источников сверена с [руководством dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).
Runtime `NETWORK_FILE` используется [systemd 249 sd-network](https://github.com/systemd/systemd/blob/v249/src/libsystemd/sd-network/sd-network.c);
это свидетельство выбора, не разрешение перезаписывать networkd-owned `eth0`.

## Ограничения и интерпретация

Ownership-часть: командный бюджет 30 секунд, каждая команда до 3 секунд/16 KiB;
не более 8 networkd links, 48 шагов source graph, depth 4, 32 выбранных файлов
на directory. Каждый config до 32 KiB, его фильтрованный вывод до 16 KiB.
Предыдущая диагностическая часть сохраняет свой бюджет 60 секунд и concurrency 4.
Файловые чтения ограничены по объёму; deadline кооперативный, не обещание прерывания
зависшего kernel/filesystem I/O. Спецфайлы/сырые устройства не читаются как config.

`assessment.status`:

- `needs-evidence-or-repair`: есть недостающие/конфликтующие сведения, ошибка
  чтения или необходимость отдельного baseline repair.
- `ready-for-manual-review`: достаточная для ручного review выборка; **не**
  разрешение на установку, не доказательство loaded config и не результат пилота.

`installationAllowed` всегда false. Для VPS 2 остаётся явный выбор политики
`ru-central1.internal`/`auto.internal`; для Radxa — baseline resolver, полный
разбор источников dnsmasq и DHCP DNS option 6. Обоим нужны отдельное согласование
живых изменений, независимый аварийный доступ и пилот. Скрипт не исправляет
сломанный symlink и не включает resolved. Не собирает ACL/xattrs/capabilities,
не устанавливает блокировки менеджеров и не доказывает атомарность всего снимка.

## Проверки

`npm run test:dns-client-preflight`: фильтрация секретов, смена PID/InvocationID,
namespace/cgroup mismatch, EACCES, inode drift, source loops/limits/escape,
NXDOMAIN при exit=0, deadline, non-systemd refusal и отсутствие setters.
Набор вместе с прежними diagnostic/inspect: **63/63 PASS**.
Read-only smoke на текущем non-systemd окружении корректно отказался считать
его живым поддержанным клиентом; DNS probes не отправлялись. Это не live PASS
на VPS 2 или Radxa и не новый VM-прогон.
Общий Node acceptance — **1511/1511 PASS**, без skips:
`/var/tmp/meshpn-acceptance-WX0uMf/report.json`. Браузеры/VM в этом этапе не запускались.
