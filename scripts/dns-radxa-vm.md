# Radxa paired coordinator: systemd/reboot и аварийная остановка гостя

Изолированный VM-стенд для [общего координатора](dns-radxa-journal.md).
Не устанавливает службы на хост/VPS/Radxa. QEMU TCG, `-nic none`, без shared
filesystem, без SSH и доступа гостя в Интернет. Реальные systemd PID1, dnsmasq,
adapter → числовой exit → проверяемый TLS DoH fixture, USB peer через veth.

```bash
node scripts/dns-vm-lab.mjs \
  --tools=/absolute/verified-qemu-tools \
  --kernel=/boot/vmlinuz-MATCHING-RUNNING-KERNEL \
  --resolved=/absolute/systemd-resolved \
  --dnsmasq=/absolute/dnsmasq \
  --case=radxa

# Отдельная конечная матрица, три свежих диска:
# те же параметры + --case=radxa-cuts
# Одна точка: --case=radxa-cut:resolver:restore:set
```

Builder пока требует `--resolved`, но не запускает его службу в этом режиме.
Provenance tools/APT metadata и kernel/modules: [общая VM-инструкция](dns-vm-lab.md).
Старые `all`, `systemd`, `dnsmasq`, `coupled` матрицы не расширяются автоматически.

## Исполнитель и persistent resolver

Контроллер напрямую исполняет обе файловые транзакции, держа общий flock:
parent-owned RPC здесь нет. Guard устанавливается guest init до systemd,
network/adapter/controller/consumer имеют проверяемые зависимости. dnsmasq
не зависит от живости adapter/controller, поэтому может сохранять DHCP и
локальные имена при их отказе.

Синтетический гостевой `/etc` копируется в приватный каталог на ext4-диске
`/state/dnsmasq/resolver-etc` и монтируется **каталогом**, а не отдельным файлом.
Systemd units сохраняются, atomic rename resolver виден NSS, inode объектов
переживает потерю RAM. Исходный `resolv.conf` — ссылка на отсутствующий
`/run/systemd/resolve/stub-resolv.conf`. Включение выбирает regular localhost
resolver; disable возвращает ссылку без снятия guard. Явный localhost:53 probe
проверяет ответ dnsmasq до выбора системного resolver и имеет отдельный VM gate.

Откат восстанавливает и исходное DHCP option 6 (`1.1.1.1`). Поэтому после новой
DHCP аренды клиентский DNS остаётся заблокирован guard — это точный исходный
конфиг, не обещание исправного baseline. Локальные имена проверяются через
dnsmasq **до** повторного DHCP; после него проверяется блокировка прямого DNS.

Только test driver после проверки rollback отдельно снимает guard для baseline
positive controls. Это не действие coordinator или service stop. Архивирование
старой эпохи также явно делает driver; live-сервисы не получают такой политики.

## Конечные проверки

Lifecycle: 12 проверок в двух загрузках — failed guard, readiness/DHCP, restart
controller с тем же ID, отказ exit, SIGKILL adapter с сохранением DHCP, SIGKILL
dnsmasq/recovery, чужой resolver без перезаписи трёх journals, offline rollback
под guard, отказ start после rollback, reboot со старой эпохой и новая явная
fixture-транзакция. После reboot сравниваются побайтно все три журнала.

Три whole-guest crash точки, по две загрузки на отдельном диске:

| Точка SIGKILL QEMU | Фаза coordinator | Dnsmasq journal | Resolver journal |
| --- | --- | --- | --- |
| `resolver:apply:set` | resolver | apply/complete | apply-intent |
| `resolver:restore:set` | restore-resolver | apply/complete | restore-intent |
| `dnsmasq:restore:daemon:set` | restore-dnsmasq | restore, cursor=1, pending | restored |

Host сверяет все три журнала после ext4 recovery с событием cut-ready и требует
нового boot ID, отказа stale adoption и фиксированного набора критериев.
SIGKILL QEMU не моделирует физический power loss диска хоста: его page cache
жив. Hot reset внутри одного процесса QEMU не проверяется.

## Статус прогонов

Проверки 2026-09-27: lifecycle **12/12 PASS в двух загрузках**,
`/var/tmp/meshpn-dns-vm-nh7rFm/report.json`, host DNS files unchanged.
Аварийная матрица **3/3 PASS, шесть загрузок**:
`/var/tmp/meshpn-dns-vm-ef69KR/report.json`. Все три журнала сохранены;
старые эпохи не приняты автоматически. Регрессия прежнего dnsmasq VM-режима:
**12/12 PASS в двух загрузках**, `/var/tmp/meshpn-dns-vm-lKuXk0/report.json`.
Повтор paired namespace — PASS (15 controller SIGKILL). Unit-протокол и
host-refusal: 50/50 PASS.

Первый lifecycle `/var/tmp/meshpn-dns-vm-Je010H/report.json` выявил ошибку теста:
локальное имя проверялось после восстановления DHCP DNS `1.1.1.1`, который
guard правильно блокировал. Порядок проверок исправлен; этот прогон не PASS.
Первый cut-run `/var/tmp/meshpn-dns-vm-FDg67x/report.json` собран до исправления
и упал на той же проверке после загрузки; не считается успешным.

Общий Node-прогон `/var/tmp/meshpn-acceptance-7KFITe/report.json`: 1439/1440,
упал прежний `owner exit kills a TERM-resistant descendant (stdio=ignore)`.
Отдельный повтор process-тестов 3/3 PASS; причина общего сбоя не установлена,
отчёт сохранён, это не успешный acceptance.
Финальный повтор без работающих VM — **1440/1440 PASS**, без skips:
`/var/tmp/meshpn-acceptance-2Kesg9/report.json`. Это Node suite, не новый
браузерный acceptance; причину предыдущего process-test сбоя он не устанавливает.

## Граница

Это x64 guest/systemd 255, не реальная Radxa arm64/systemd 252. Физический USB,
точные client units/includes, независимый uplink pcap и live install/rollback
остаются клиентским этапом. После stale refusal могут быть недоступны DNS/DHCP;
результат не означает unattended recovery. Критерии [DNS v1](dns-v1.md) не
ослабляются этим стендом.
