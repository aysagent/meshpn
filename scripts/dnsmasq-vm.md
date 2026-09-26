# dnsmasq: systemd и reboot в изолированной VM

Отдельный режим `--case=dnsmasq` существующего VM runner. Не расширяет `all`,
не устанавливает службы на хост и не является live installer для Radxa.
QEMU использует TCG, `-nic none`, без общей файловой системы с хостом.
В госте настоящий systemd PID1 и dnsmasq, синтетический USB peer через veth,
настоящий adapter → exit → TLS DoH fixture. В интернет гость не выходит.

```bash
node scripts/dns-vm-lab.mjs \
  --tools=/absolute/path/to/verified-qemu-tools \
  --kernel=/boot/vmlinuz-MATCHING-LOCAL-KERNEL \
  --resolved=/absolute/path/to/systemd-resolved \
  --dnsmasq=/absolute/path/to/dnsmasq \
  --case=dnsmasq
```

Подготовка QEMU/tools и ограничения kernel/modules — в [dns-vm-lab.md](dns-vm-lab.md).
Общий builder пока требует `--resolved`, но службу resolved в данном режиме
не запускает. Исходный dnsmasq executable и скопированные файлы получают SHA-256
в image manifest. Пакеты QEMU сверяются с APT metadata: отсутствие metadata —
ошибка, не повод отключать проверку. Можно передать `APT_CONFIG` с отдельным
временным каталогом подписанных Ubuntu metadata, не обновляя host APT-кэш.

## Службы и порядок

- Guard ставится ещё guest init до systemd; network зависит от guard.
- Адаптер — отдельная Type=notify служба, READY только после DNS readiness.
- Контроллер держит flock и исполняет файловую транзакцию непосредственно в
  своём процессе: здесь нет parent-owned RPC из namespace SIGKILL-стенда.
- dnsmasq — отдельная служба с ExecStartPre, проверяющим разрешённый context и
  snapshot файла. Она **не зависит от живости адаптера/контроллера**: при их
  отказе остаются DHCP и локальные имена.
- DNS-потребитель запускается после контроллера и останавливается при потере
  его зависимости от адаптера. Статус oneshot consumer не является непрерывным
  мониторингом dnsmasq: после SIGKILL самого dnsmasq проверяется отказ DNS и
  явное восстановление через контроллер, а не автоматический рестарт демона.

OUTPUT guard блокирует прямые upstream IPv4/IPv6 TCP/UDP53; localhost DNS stub
разрешён отдельным правилом. USB INPUT/FORWARD тоже защищены. В госте
`resolv.conf` изначально синтетический с localhost dnsmasq и остаётся неизменным;
миграция dangling symlink настоящей Radxa здесь не воспроизводится.
Независимый транзитный USB FORWARD-трафик измеряется в отдельном
[namespace-стенде](dnsmasq-lab.md), не в этой VM. dnsmasq запускается с
`--no-daemon` как привилегированный fixture; эти units не являются шаблонами
production hardening или установщиком штатной службы Radxa.

Runtime cache активации сверяется с MainPID/InvocationID systemd и snapshot
конфига. Наличие файла журнала само по себе не считается загруженной конфигурацией.
Новая активация проверяет файл, разрешает конкретный snapshot и запускает службу.
Служба не получает разрешения перечитать произвольный изменённый конфиг.

## Конечная матрица

Две загрузки на одном disposable ext4-диске:

1. Отказ guard не запускает зависимые службы.
2. Protected readiness, системный DNS и DHCP DORA настоящего USB-клиента.
3. Stop/restart контроллера не снимает защиту и сохраняет transaction ID.
4. Отказ exit: нет direct fallback, DHCP и локальные имена доступны.
5. SIGKILL адаптера: consumer остановлен, dnsmasq/DHCP остаются; явный restart
   восстанавливает защищённый путь.
6. SIGKILL dnsmasq: DNS недоступен без fallback, journal recovery возвращает
   службу и прежнюю DHCP аренду.
7. Чужая правка конфига не затирается при disable, журнал сохранён.
8. Explicit disable возвращает точный baseline и подтверждается UDP/TCP queries.
9. Новый start с released journal запрещён под вновь проверенным guard.
10. Reboot: старый journal/context отклоняется, файлы сохраняются, consumer не
    запускается. Driver явно архивирует старую эпоху и создаёт новую синтетическую
    конфигурацию; затем повторяет protected readiness/DHCP и explicit disable.

Ожидается 12 проверок (два критерия повторены на второй загрузке). Host runner
проверяет разные boot ID, marker ядра reboot, systemd sync/unmount и все критерии,
не только строку PASS. Диск и ограниченные serial logs остаются для разбора.

Прогон 2026-09-26: **12/12 PASS в двух загрузках**, QEMU 8.2.2 TCG, systemd 255,
dnsmasq 2.90, kernel 5.4.210, Node 24.13.0. Direct baseline queries в protected
phase — 0, positive controls после disable прошли, host DNS files unchanged.
Локальный отчёт: `/var/tmp/meshpn-dns-vm-wUVAii/report.json`; initrd SHA256:
`950ffb2341735611b59c109fbc23f187673b80137e36f5f2f432defeb1ea3249`.
Manifest и serial logs лежат рядом; это временные артефакты, не файлы репозитория.
Отдельно Node acceptance **1191/1191** и три namespace dnsmasq-теста — PASS.
Регрессия общего builder: прежний resolved/systemd VM-режим **11/11 PASS в двух
загрузках**, `/var/tmp/meshpn-dns-vm-ZfTjNz/report.json`, host DNS unchanged.

## Что результат не доказывает

После reboot нет автоматического принятия старого журнала. До явного решения
оператора могут быть недоступны и DNS, и DHCP; это проверка отказа под защитой,
**не обещание unattended availability**. Архивирование эпохи делает только
test driver после проверки своих файлов, не универсальный recovery backend.

Нет физического power-loss, убийства backend внутри setter, hot hardware reset,
настоящего USB gadget/arm64 или независимого uplink pcap. QEMU перезапускается
host runner после корректного guest reboot с тем же диском.
В госте systemd хостовой версии (255), не версия Radxa 252. Supervisor-операции
выполняет systemd вне процесса с flock: произвольный SIGKILL контроллера посреди
`systemctl restart` этим этапом не сертифицируется.

Дальше — resolved 249/networkd и политика облачных доменов VPS 2, затем
согласованные пользовательские dry-run/apply/recovery скрипты и пилоты по
[матрице](dns-client-matrix.md). DNS v1 этим VM-этапом не закрывается.
