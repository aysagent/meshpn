# DNS после reboot: offline-протокол и подготовка VM

Это следующий **подготовительный** этап после [SIGKILL/restart adapter](dns-adapter-process.md).
Реализованы pure state machine и read-only preflight, **не VM launcher, не live
backend, не systemd installer**. Настоящий reboot/power-cut пока не проверен.

```bash
npm run dns:boot
npm run dns:boot -- --scenario=power-loss
npm run test:dns-boot
npm run dns:vm-preflight

# Только metadata проверки явно подготовленных гостевых артефактов:
npm run dns:vm-preflight -- --qemu=/absolute/qemu-system-x86_64 \
  --kernel=/absolute/guest-kernel --initrd=/absolute/guest-initramfs --disk=/absolute/guest.raw
```

`dns:boot` не читает файлы хоста. Сценарии: fresh, previous-boot (по умолчанию),
same-boot, corrupt, adapter-down, disable, power-loss. Последний **симулирует
переход состояния**, не отключает питание. Во всех отчётах `vmStarted=false`,
`rebootTested=false`, `powerLossTested=false`; `--apply` отсутствует.

## Предлагаемый порядок

```text
Новая загрузка: допуск приложений закрыт; наличие guard ещё не подтверждено
  → установка и проверка boot guard
  → чтение persistent intent и проверка текущего владельца DNS
  → текущий context: продолжить его durable intent
    чужая загрузка/context: сохранить журнал, остановиться для review
  → при явно разрешённой новой эпохе: новый baseline и durable intent
  → adapter bound → protected UDP + TCP readiness
  → DNS apply + read-back + durable ack
  → допуск защищённых приложений; guard остаётся
```

Названия действий в JSON — **предложения для будущего исполнителя**, не вызовы
firewall/systemd/D-Bus. `admitted` описывает желаемое состояние допуска, а не
доказывает фактическую блокировку пакетов. Evidence booleans должны поступать
из независимых реальных проверок; offline-модель сама их не измеряет.

Новая загрузка обнуляет guard/readiness/admission. Наличие прежнего active journal
не доказывает ни живой adapter, ни firewall, ни владение новым resolved.
Journal с другим boot ID или owner/context не применяется автоматически, даже
если значения DNS выглядят знакомо. Прежний snapshot нельзя восстанавливать на
новый uplink. Для новой эпохи нужны explicit approval, выделенный owned link,
проверенный **текущий** baseline и сохранённый старый journal. Это модель будущего
enrollment/epoch протокола: существующий namespace journal не мигрирует, нового
формата записи на диск/архивации/автоматического adoption здесь ещё нет.

В той же загрузке/context durable restore intent продолжается как restore,
не превращается при старте в apply. Explicit disable: durable disable intent →
восстановление текущего baseline → read-back/durable ack → снятие guard → допуск
baseline DNS. Missing/corrupt/released journal сам по себе не разрешает снять
защиту. Ошибка guard installation оставляет допуск закрытым и ожидает настоящего
подтверждения установки, а не заявляет `guardVerified=true`.

## Почему недостаточно одного systemd Before=

`network-pre.target` — пассивная точка синхронизации, пригодная для firewall
перед настройкой сети, но сервис должен её подтянуть и фактические потребители
должны соблюдать ordering. Само имя target ничего не фильтрует.
[systemd special targets, v255](https://github.com/systemd/systemd/blob/v255/man/systemd.special.xml).

`Before=`/`After=` задают порядок, но не являются зависимостью успешного запуска.
Для контролируемого guest workload потребуется явная dependency/failure policy,
а не только сортировка unit-файлов. Даже это не доказывает отсутствие DNS из
initramfs, DHCP hooks или неучтённого раннего сервиса.
[systemd unit dependencies, v255](https://github.com/systemd/systemd/blob/v255/man/systemd.unit.xml).

VM-протокол должен отдельно проверять ранний период до network setup, отказ
установки guard, поздний старт storage/adapter и попытки DNS раннего consumer.
Live units и host firewall этим пакетом не создаются.

## Preflight и границы будущей VM

`dns:vm-preflight` только читает metadata четырёх артефактов. По умолчанию ищет
QEMU в `/usr/bin/qemu-system-x86_64` и kernel в `/boot/vmlinuz`; **не берёт host
initramfs или host disk автоматически**. Initramfs и disk нужно указать отдельно.
QEMU проверяется на read/execute, остальные файлы — на read; пустые и нерегулярные
файлы отклоняются, symlink disk отклоняется. Никаких exec/download/mount/disk writes.
Пути не попадают в JSON. Наличие `/dev/kvm` — metadata hint, устройство не открывается.

Даже при пустом `blockers` всегда `launchAuthorized=false` и
`artifactVerificationRequired=true`: metadata не проверяет подписи, hashes,
содержимое гостя, происхождение образа, права на изменения или поддержку QEMU.
Это список доступности файлов, не security attestation и не успешный boot.

Будущий стенд: TCG без требования KVM, фиксированные CPU/RAM/deadline, `-nic none`,
без shared host filesystem/physical disks/host ports; private копия только
гостевого диска и отдельный serial/QMP control. У QEMU сетевой default нельзя
оставлять неявным. [QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html).
Ядро/initramfs/guest binaries должны быть проверены до запуска. Host initramfs
может содержать посторонние конфигурации/секреты и не используется как fixture.

## Матрица, которую ещё нужно выполнить в VM

- Чистая загрузка с guard-before-consumer, положительным DNS sentinel control.
- Успешный protected startup, graceful reboot, новый boot ID и отказ слепого adoption.
- Жёсткое завершение QEMU между intent/fsync/rename/ack с сохранённым guest disk.
- Повреждённый/отсутствующий/устаревший journal, неготовый storage, занятый порт,
  недоступный exit, отказ guard и попытки раннего DNS: без baseline fallback.
- Разрешённая новая эпоха не перезаписывает старый journal; явное отключение
  восстанавливает только baseline текущего владельца.

SIGKILL QEMU моделирует потерю guest RAM/процессов, но host page cache остаётся.
Даже такой прогон нельзя автоматически назвать физическим power-loss proof:
нужно явно описать disk cache/flush модель и fault injection. Не использовать
режим, игнорирующий guest flush, как доказательство durable correctness.

В текущем окружении preflight обнаружил kernel, но не QEMU/KVM; гостевые initramfs
и disk не предоставлены. Скачивание/подготовка инструментов вынесены на отдельное
подтверждение. Пока выполнены только offline тесты, не настоящие VM-сценарии.
