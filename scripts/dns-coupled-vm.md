# Coupled DNS coordinator: systemd и потеря гостя

Отдельные режимы существующего NIC-less QEMU-стенда для
[совместного link/address/resolved journal](dns-coupled-journal.md).
Это VM-only исполнитель, **не live-установщик** для VPS/Radxa.

Проверено 2026-09-26: lifecycle **11/11 PASS**, две загрузки,
`/var/tmp/meshpn-dns-vm-QiEv8R/report.json`.
Повтор старого systemd-режима — **11/11 PASS**,
`/var/tmp/meshpn-dns-vm-GBznOd/report.json`; coupled namespace regression —
PASS (~183 секунды, 17 controller SIGKILL).
Node acceptance после изменений — **1323/1323 PASS**, без skips:
`/var/tmp/meshpn-acceptance-eWYgro/report.json`; VM protocol/host-refusal tests — 42/42.

Whole-guest crash — **3/3 PASS**, шесть загрузок. Финальная матрица выполнена
параллельными одиночными `--case=coupled-cut:POINT` на трёх независимых свежих дисках:

- `apply:DNSEx:set`: `/var/tmp/meshpn-dns-vm-LbNCji/report.json`.
- `restore:DNSEx:set`: `/var/tmp/meshpn-dns-vm-prvnJs/report.json`.
- `link-released`: `/var/tmp/meshpn-dns-vm-yWyXSz/report.json`.

Во всех отчётах host DNS files unchanged, baseline queries during protection=0,
положительный контроль baseline после disable пройден, owned link удалён.

При разработке были два неуспешных прогона стенда: таймаут 15 секунд генерации
fixture RSA под TCG (`/var/tmp/meshpn-dns-vm-YlbUeF/report.json`) и буферизация
`cut-ready` в дочернем `disable` (`/var/tmp/meshpn-dns-vm-c0RXqK/report.json`).
Первый исправлен отдельным VM-only лимитом 120 секунд для генерации сертификата
(DNS deadlines прежние), второй — наследованием guest console у cut-worker.
Они не считаются успешной power-cut матрицей. Все три точки после исправления
повторены на свежих дисках; результаты выше.

```bash
node scripts/dns-vm-lab.mjs \
  --tools=/absolute/private-tools-directory \
  --kernel=/boot/vmlinuz-MATCHING-RUNNING-KERNEL \
  --resolved=/absolute/trusted/systemd-resolved \
  --case=coupled

# Те же пути, отдельная ограниченная матрица аварий:
# ... --case=coupled-cuts
# Одна из этих же трёх точек, например:
# ... --case=coupled-cut:restore:DNSEx:set
npm run test:dns-vm
```

Предусловия и provenance инструментов — в [VM-лаборатории](dns-vm-lab.md).
Host DNS/firewall/routes/services не изменяются; SSH, Интернет в госте,
TUN, host shared filesystem и аппаратное ускорение не нужны. В госте
синтетические DNS/CA/адреса, настоящий systemd PID1, resolved, loopback adapter,
enc-SNI exit и проверяемый TLS DoH fixture. Это не образ VPS 2 с точной версией 249.

## Lifecycle

`coupled` проверяет службы, а не только RPC child-контроллер:

- Ошибка guard не допускает старта adapter/controller/consumer.
- Один `flock` удерживается самим Node-контроллером (`-F`); readiness предшествует consumer.
- Создание dummy-link, адрес/UP и DNS-state выполняются общим координатором.
- Остановка controller сохраняет защиту; повторный старт продолжает тот же journal ID.
- Отказ exit не разрешает fallback; SIGKILL adapter останавливает зависимые службы,
  последующий запуск восстанавливает ту же транзакцию.
- Чужие Domains не перезаписываются; оба журнала сохраняются при отказе disable.
- Явный disable снимает настройки, удаляет принадлежащий VPN link, затем guard.
  UDP/TCP baseline становится доступен как положительный контроль наблюдателя.
- Released journal не разрешает повторное включение без нового epoch.
- После настоящего systemd reboot старые boot/context отклоняются, оба файла
  сохраняются побайтно, исчезнувший link не создаётся автоматически; guard остаётся.

Для продолжения теста явный fixture-оператор архивирует **оба** журнала и создаёт
новую транзакцию. Эта операция не является автоматическим recovery и не
предлагается как готовая команда восстановления живого клиента.

Синтетический baseline расположен на другом dummy-link и не содержит `~.`,
чтобы не соревноваться с VPN DNS-link. DHCP renew/reapply проверяется отдельно
в [networkd namespace-стенде](dns-networkd-lab.md), не в этом госте.

## Потеря VM

`coupled-cuts` — три свежих диска, по две загрузки каждого:

| Точка SIGKILL QEMU | Сохранённый root journal | Child journal |
| --- | --- | --- |
| `apply:DNSEx:set` | settings/apply, level=4, pending=true | created |
| `restore:DNSEx:set` | settings/restore, level=5, pending=true | created |
| `link-released` | unlink/restore, level=0, pending=false | released |

Host убивает QEMU по контрольному событию, без дополнительного guest sync.
Теряются все процессы, kernel state и RAM гостя. Следующая загрузка читает
ext4-диск; host сравнивает оба прочитанных журнала с контрольной точкой. Затем
проверяется отказ старого epoch под guard и отдельная новая enable/disable
транзакция. PASS требует точного набора проверок и смены boot ID, а не одного
маркера успешного завершения.

Это **не физический power loss хоста/диска**: host page cache переживает SIGKILL.
`physicalPowerLossTested=false`, `inProcessHotResetTested=false`; QEMU запущен
с `-no-reboot`, повторную загрузку явно делает launcher. Старые `all`, `systemd`
и `dnsmasq` матрицы не подменяются этим режимом.

Ограничения DNS v1 и последующие клиентские пилоты остаются в
[конечном чек-листе](dns-v1.md). Рабочие адреса и политика внутренних доменов
клиента этим fixture не выбираются.
