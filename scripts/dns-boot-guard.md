# DNS: ранняя защита при загрузке

`dns-boot-guard.mjs` — фиксированный root entrypoint для общего
[guard executor](dns-client-guard.md). Это компонент будущей opt-in установки,
**не готовый установщик** и не команда для запуска на текущих VPS/Radxa.
Пока проверяется в NIC-less VM; живые настройки не изменялись.

## Политика и полномочия

Будущий установщик явно создаёт `/etc/clean-vpn/dns/guard-policy.json`:

```json
{
  "schema": 1,
  "kind": "clean-vpn-dns-boot-policy",
  "enabled": true,
  "firewallBackend": "nf_tables",
  "input": { "schema": 1, "client": "vps2", "id": "<32 lowercase hex>" }
}
```

Это схема, не готовый конфиг: ID генерируется при установке. Для Radxa input
дополнительно содержит `usbInterface` и `usbAddress`, как у общего guard.
Backend выбирается явно: `legacy` либо `nf_tables`, без автоматического перехода.
Все четыре iptables/ip6tables и restore binary должны соответствовать выбору.

Файл: root-owned regular, один hardlink,0600,≤8KiB, no-follow чтение.
Родительские каталоги принадлежат root и не доступны группе/остальным на запись.
Перед каждой операцией проверяются policy identity, инструменты, boot ID,
namespace и удерживаемый flock. Неизвестные поля и небезопасные объекты отклоняются.
Политика не содержит секретов и не принимается из аргумента с произвольным путём.

CLI имеет `--start` (проверить/обеспечить guard), `--inspect` (только чтение)
и служебный `--attest-namespace` для ExecStartPre. Ни release, ни исправления
DNS baseline, ни принятия DNS-журнала после reboot в нём нет.

## Служба

`dnsBootGuardUnit(backend)` возвращает unit без `[Install]`. До установки ещё
нужны план, review владельца сети и согласованный откат. Не копируйте VM units.

- `Before=network-pre.target` вместе с `Wants=network-pre.target` задаёт ранний
  порядок. **Одного порядка недостаточно:** контролируемому network manager
  нужны `Requires` + `After` guard, чтобы отказ guard блокировал его запуск.
  Произвольные ранние сервисы и initramfs этим не защищены.
  [Systemd network targets](https://systemd.io/NETWORK_ONLINE/).
- Короткий `ExecStartPre=+` выполняется с полными root-полномочиями: проверяет
  systemd PID1 и равенство network namespace, атомарно сохраняет только boot ID
  и namespace в root0700 `/run/clean-vpn-dns-guard/namespace.json` (0600).
  Это ephemeral attestation, не recovery journal. Префикс `+` выбран явно:
  основной процесс с урезанными capabilities не может читать namespace PID1.
  [Systemd service command prefixes](https://github.com/systemd/systemd/blob/v255/man/systemd.service.xml).
- Основной процесс имеет только CAP_NET_ADMIN; для legacy дополнительно
  CAP_NET_RAW. NoNewPrivileges, PrivateDevices, ProtectSystem и прочие
  ограничения остаются. CAP_SYS_PTRACE ему не выдаётся. При EACCES к namespace
  PID1 требуется защищённая attestation **этой же загрузки и namespace**.
- Стабильный `/run/clean-vpn-dns-guard/lock` удерживается через `flock -F`.
  CLI проверяет свой exclusive whole-file flock через fdinfo. Mutating restore
  child наследует открытый lock, чтобы пережить SIGKILL родителя без потери
  сериализации до окончания commit. Отдельный mid-commit SIGKILL этого child
  пока не проверен; это не результат crash-матрицы journal.
- `/run` доступен на запись из sandbox для стандартного `/run/xtables.lock`.
  Отдельный private XTABLES_LOCKFILE не используется: он нарушил бы сериализацию
  с другими firewall managers. Нет global flush/restore чужого firewall.
- Нет ExecStop/ExecStopPost и автоматического release. `systemctl stop` не
  снимает правила. Повторный start проверяет реальные chains, не только active
  состояние oneshot. Ошибка после первого family commit оставляет его защиту.

## Граница интеграции

При reboot guard снова применяет явно установленную boot policy с тем же ID.
Старый DNS journal не читается и не присваивается. Защита может работать, даже
когда DNS controller отказывает по старому boot/context; это fail-closed, не
обещание unattended DNS availability.

Общий persistent guard journal пока генерирует собственный ID при enable.
**Совместная live-установка этих двух компонентов ещё не готова:** нужны явная
привязка journal к boot-policy ID, общий lock, проверенное восстановление baseline
и транзакция отключения boot policy/dependency dropins. Нельзя просто включить
оба entrypoint с разными ID: ownership checks должны отказать.

VPS2 cloud-name policy, Radxa baseline repair/USB ownership, клиентские preflight
и24-часовые пилоты остаются отдельными критериями [DNS v1](dns-v1.md).

## Проверка

```bash
npm run test:dns-boot-guard
```

В `dns:vm-lab --case=systemd` используется именно этот CLI и unit sandbox.
В VM добавлены только отказ ExecStartPre для dependency-теста и ограниченный
log sink вместо отсутствующего journald. Outer init guard защищает гостевой lo
до PID1; его старые правила удаляются только после проверки нового guard.
Fixture-only release выполняется после проверки восстановленного DNS baseline;
в публичном CLI такого режима нет.

2026-09-27: **16/16 проверок в двух загрузках VM, PASS**,
`/var/tmp/meshpn-dns-vm-7CL1sN/report.json`. Systemd255/legacy firewall,
QEMU8.2.2 TCG2 vCPU. Host DNS snapshots/guest resolv.conf неизменны;
baseline queries0, разные boot ID, настоящие sync/unmount/reboot/poweroff.
Все462 копии JS исходников совпали с manifest. Это VPS2-shaped boot policy
в синтетическом x64 госте, не live VPS2/arm64 Radxa.

Node1659/1659 PASS (`/var/tmp/meshpn-acceptance-3CbkEG/report.json`).
Общий namespace guard/journal повторён для обоих профилей на nf_tables:
16 SIGKILL,2 lock conflicts,11 packet checks PASS. Это не mid-restore kill.

Ошибка ранних VM попыток не скрыта: `jqvXEQ` подтвердил EACCES к namespace PID1,
`YAGZeS` —226/NAMESPACE при попытке nsfs bind, `t4JqoX` — отказ проверки
authority до исправления synthetic `/run` на0755. `6vuw9h`/`xrw3uq` — первые
попытки с менее точной диагностикой. Их reports/logs находятся под
`/var/tmp/meshpn-dns-vm-<имя>/`; ни одна не считается PASS.
