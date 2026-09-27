# Coupled DNS coordinator: systemd и потеря гостя

Отдельные режимы существующего NIC-less QEMU-стенда для
[совместного link/address/resolved journal](dns-coupled-journal.md).
Это VM-only исполнитель, **не live-установщик** для VPS/Radxa.

Текущая интеграция использует настоящий boot guard CLI и отдельный adapter CLI
с DynamicUser/credentials. Coupled controller и boot guard держат один
`/run/clean-vpn-dns-guard/lock`; постоянный guard journal привязан к ID boot policy.
Снятие защиты требует завершённых root/link журналов, актуального context и
отсутствия принадлежащего VPN интерфейса. Настройки uplink не восстанавливаются
из старого снимка: ими по-прежнему управляет networkd.

После переноса координации в [общий controller](dns-client-controller.md):
**19/19 PASS в двух загрузках**, `/var/tmp/meshpn-dns-vm-NGWKRQ/report.json`.
Все474 JS copies соответствуют этому срезу. Baseline queries0, positive controls
PASS, host DNS unchanged. Node1735/1735 PASS (`meshpn-acceptance-mCnlAj`).

До выделения общего controller, 2026-09-27: **19/19 PASS в двух загрузках**,
`/var/tmp/meshpn-dns-vm-ZHZoKE/report.json`. Node **1674/1674 PASS**,
`/var/tmp/meshpn-acceptance-BIoAF2/report.json`. Все464 JS-копии этого образа
совпали с исходниками. Регрессия прежнего resolved fixture —20/20 PASS,
`/var/tmp/meshpn-dns-vm-hYAVIb/report.json`.

При подключении исправлены состав образа (отсутствовавшая boot policy), допуск
CLI fixture и VM-only observer к coupled-фазам. Отказы `YUfJ7E`, `f7yZYj`,
`GLCkS6`, `K85i7L` не считаются PASS; их отчёты/логи сохранены, пересоздаваемые
образы удалены. В матрице `ux34V3` первая точка прошла, но запуск adapter после
второй аварии завершился отказом после первого соединения с exit, до READY и DNS setters. Причина этого
конкретного отказа не установлена: stderr был отключён, PrivateTmp утрачен после
выхода службы. Поэтому добавлен guest-only PID1-opened log и ограниченные
редактированные failure records; DNS deadlines не увеличены. Это диагностическое
дополнение после lifecycle-прогона выше, не доказательство исправления timeout.
Node после этого дополнения —1674/1674 PASS,
`/var/tmp/meshpn-acceptance-bTHMkQ/report.json`.

Финальный повтор аварийных точек отдельными ограниченными запусками —
**3/3 PASS, шесть загрузок, по9 проверок**:

- `apply:DNSEx:set`: `/var/tmp/meshpn-dns-vm-FmlilO/report.json`.
- `restore:DNSEx:set`: `/var/tmp/meshpn-dns-vm-0FXAJ6/report.json`.
- `link-released`: `/var/tmp/meshpn-dns-vm-OyQuDh/report.json`.

Во всех трёх случаях guard active в момент обрыва, root/link/guard прочитаны
после загрузки без изменений, старый context отвергнут, independent boot guard
проверен до сети. После явного fixture archive новая транзакция и disable
завершены; baseline queries0 во время защиты, положительный baseline контроль
пройден, host DNS/guest resolv.conf неизменны. Финальный `FmlilO` содержит464
JS-копии текущих исходников; `0FXAJ6` отличается только последующими unit assertion
и логированием другого systemd driver, `OyQuDh` — только этим другим driver.
DNS/link/guard и исполняемый coupled driver у всех трёх совпадают.
Прежний необъяснённый startup failure остаётся в истории; повтор PASS не
доказывает его причину. Настоящая версия клиента/пилот этим не проверены.

## Исторические результаты до общего boot guard

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
- Общий boot/DNS `flock` удерживается самим Node-контроллером (`-F`);
  readiness настоящего непривилегированного adapter предшествует consumer.
- Guard CLI проверен до network; stop не удаляет правила. Активный DNS-link
  запрещает release; пропавший guard journal рядом с DNS-state не принимается
  как новая установка, защита сохраняется.
- Создание dummy-link, адрес/UP и DNS-state выполняются общим координатором.
- Остановка controller сохраняет защиту; повторный старт продолжает тот же journal ID.
- Отказ exit не разрешает fallback; SIGKILL adapter останавливает зависимые службы,
  последующий запуск восстанавливает ту же транзакцию.
- Чужие Domains не перезаписываются; все три журнала сохраняются при отказе disable.
- Явный disable снимает настройки, удаляет принадлежащий VPN link, затем guard.
  UDP/TCP baseline становится доступен как положительный контроль наблюдателя.
- Released journal не разрешает повторное включение без нового epoch.
- После настоящего systemd reboot старые boot/context отклоняются, все три файла
  сохраняются побайтно, исчезнувший link не создаётся автоматически; guard остаётся.

Для продолжения теста явный fixture-оператор архивирует **все три** журнала и создаёт
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
ext4-диск; host сравнивает root/link/guard журналы с контрольной точкой. Во всех
трёх точках guard journal ещё active и принадлежит предыдущему boot. Затем
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

## Installed read-only baseline в том же lifecycle

Новый прогон `/var/tmp/meshpn-dns-vm-KXJ20n/report.json`: **21/21 PASS**, две
загрузки; Node1841/1841 PASS (`meshpn-acceptance-N3lmI5`). Добавлены два
`installed-cli-baseline-and-refusals`, по одному на boot: реальный entrypoint
из `/opt/clean-vpn`, bundle/config opt-in, тот же flock и настоящий networkd.
Положительный baseline и отказы без opt-in, без lock и при несовпадающей
domain-policy проверены до запуска adapter. Все502 JS-копии manifest совпадают
с исходниками этой записи. Baseline queries0 под guard, positive controls PASS,
host DNS unchanged; прежние guard/откат/stale-journal критерии сохранены.

Fixture временно использует DNS10.129.0.2 без отправки запросов к нему, а затем
останавливает networkd и точно возвращает loopback sentinel, NSS/resolver,
маршрут и policy. Нелокальный DNS нужен для проверки именно uplink-profile:
manager API resolved сообщает localhost DNS с индексом loopback. Это не DHCP
renew/reconfigure проверка и не полный Ubuntu rootfs; прежний networkd namespace
стенд остаётся отдельным. Никакие VM authority gates не сняты; установленный
CLI **только читает**, реальные setters/установщик и live пилоты ещё предстоят.
Ошибки подготовки этого прогона и ограничения — [installed authority](dns-installed-authority.md).
