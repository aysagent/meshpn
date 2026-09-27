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

Контроллер напрямую исполняет обе файловые транзакции, держа общий boot/DNS
flock `/run/clean-vpn-dns-guard/lock`: parent-owned RPC здесь нет. Настоящий
boot guard CLI проверяется до сети; только после обеих его IP-семей удаляется
внешний init guard. Постоянный guard journal привязан к boot policy ID и USB
ifindex/MAC/адресу, старое состояние не присваивается. Network/adapter/controller/consumer
имеют проверяемые зависимости. Настоящий adapter CLI работает с DynamicUser и
credentials отдельно от exit/origin fixture. Его readiness включает4 UDP/TCP
A/AAAA запроса. dnsmasq
не зависит от живости adapter/controller, поэтому может сохранять DHCP и
локальные имена при их отказе.

Синтетический гостевой `/etc` копируется в приватный каталог на ext4-диске
`/state/dnsmasq/resolver-etc` и монтируется **каталогом**, а не отдельным файлом.
Systemd units сохраняются, atomic rename resolver виден NSS, inode объектов
переживает потерю RAM. В текущем режиме исходный `resolv.conf` — явно заданный
regular localhost-file (`nameserver 127.0.0.1`), как после будущего согласованного
repair. Стенд не ремонтирует реальную Radxa. Явный localhost:53 probe
проверяет ответ dnsmasq до выбора системного resolver и имеет отдельный VM gate.

Откат восстанавливает и исходное DHCP option 6 (`1.1.1.1`). Поэтому после новой
DHCP аренды клиент снова использует исходный DNS. Локальные имена проверяются
через dnsmasq **до** повторного DHCP. Explicit disable сначала завершает все
три DNS-журнала, затем внешний контроллер требует `verifyRadxaGuardRestore`
(exact localhost baseline + загруженная конфигурация текущего dnsmasq) перед
каждой release-операцией guard journal. После этого выполняются положительные
baseline controls. Service stop сам ничего не откатывает и guard не снимает.
Архивирование всех четырёх журналов после stale refusal явно делает fixture
driver; live-сервисы не получают такой политики. Старый dangling-stub rollback
сохраняется в namespace/unit тестах и никогда не проходит новый release proof.

## Конечные проверки

Lifecycle: 20 проверок в двух загрузках — failed guard, boot CLI до сети,
отдельный непривилегированный CLI adapter, отказ release при active DNS и
отказ нового bind при потерянном guard journal, readiness/DHCP, restart
controller с тем же ID, отказ exit, SIGKILL adapter с сохранением DHCP, SIGKILL
dnsmasq/recovery, чужой resolver без перезаписи четырёх journals, offline rollback
с проверкой daemon перед release, отказ start после rollback, reboot со старой
эпохой и новая явная fixture-транзакция. После reboot сравниваются побайтно все
четыре журнала. VM использует2 vCPU MTTCG, обычные DNS deadlines не увеличены.
Radxa CLI fixture использует P-256 сертификат вместо RSA2048: при холодном
TLS в TCG наблюдался DNS_TIMEOUT1597мс при реальном deadline1500мс. Это изменение
только synthetic DoH origin, не production crypto/deadline или отключение CA.
Режимы прежних systemd/coupled и namespace RSA fixtures не изменены.
Адаптер VM получает `--openssl-config=/dev/null`: после bind синтетический
`/etc` остаётся private0700 журналом и недоступен DynamicUser. Остальная очистка
окружения, credentials, пустой capability set и TLS verification сохранены.

Три whole-guest crash точки, по две загрузки на отдельном диске:

| Точка SIGKILL QEMU | Фаза coordinator | Dnsmasq journal | Resolver journal |
| --- | --- | --- | --- |
| `resolver:apply:set` | resolver | apply/complete | apply-intent |
| `resolver:restore:set` | restore-resolver | apply/complete | restore-intent |
| `dnsmasq:restore:daemon:set` | restore-dnsmasq | restore, cursor=1, pending | restored |

Host сверяет все четыре журнала после ext4 recovery с событием cut-ready и требует
нового boot ID, отказа stale adoption и фиксированного набора критериев.
SIGKILL QEMU не моделирует физический power loss диска хоста: его page cache
жив. Hot reset внутри одного процесса QEMU не проверяется.

## Диагностика текущей интеграции

После переноса координации в [общий controller](dns-client-controller.md):
**20/20 PASS в двух загрузках**, `/var/tmp/meshpn-dns-vm-gVjWqh/report.json`.
Все474 JS copies соответствуют этому срезу. Baseline queries0, positive controls
PASS, host DNS unchanged. Node1735/1735 PASS (`meshpn-acceptance-mCnlAj`).

До выделения общего controller: **20/20 PASS в двух загрузках**, 2026-09-27,
`/var/tmp/meshpn-dns-vm-BOtUpP/report.json`. Все466 JS-копии совпали с рабочими
исходниками. Guard до сети, отдельный CLI adapter, четыре persistent journal,
DHCP при отказе adapter, SIGKILL dnsmasq/recovery, отказ чужому resolver и
offline disable с loaded-daemon proof проверены. Baseline queries0 во время
защиты, positive controls после release пройдены, host DNS unchanged.

Новая аварийная матрица: **3/3 PASS, шесть загрузок, по9 проверок**,
`/var/tmp/meshpn-dns-vm-Z9nHVV/report.json`. Все четыре журнала совпали с
checkpoint после перезагрузки; baseline queries0, host DNS unchanged.
Образ матрицы собран до окончательного VM-only `--openssl-config` аргумента
и возврата RSA в несвязанной systemd/coupled fixture-ветке; эти две правки и
unit assertion — единственные отличия JS snapshot. Radxa coordinator/guard
и DNS-транзакции совпадают. Аварийная матрица не проверяет adapter restart
после bind `/etc`: именно этот путь на окончательных исходниках проверен
отдельным lifecycle `BOtUpP` выше.

2026-09-27: unit/VM-protocol127/127, полный Node1677/1677 PASS,
`/var/tmp/meshpn-acceptance-okPKfI/report.json`. Это не VM acceptance.

Неуспешные прогоны сохранены отдельно:

- `4c8JXb`: после adapter SIGKILL непривилегированный новый Node получил EACCES
  на `/etc/ssl/openssl.cnf`, потому что synthetic `/etc` уже private directory.
- `2oZDwG`: попытка задать OPENSSL_CONF не сработала — production unit правильно
  очищает эту переменную через UnsetEnvironment. Использован явный VM-only
  Node argument; проверка очистки окружения не удалялась.
- `i82SnF`: первый запрос после холодной загрузки превысил1500мс:
  DNS_TIMEOUT, elapsed1597мс. Это измеренный timeout, не отключение CA или
  прямой fallback. Radxa CLI fixture переведён на P-256 без изменения deadline.

Отчёты и serial logs остаются в соответствующих `/var/tmp/meshpn-dns-vm-*/`.
Пересоздаваемый образ `4c8JXb` удалён для освобождения места; отчёт, manifest и
console log сохранены. Эти отказы не учитываются как PASS.

## Исторические прогоны: dangling baseline без общего boot journal

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
