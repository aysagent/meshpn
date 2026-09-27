# Unit-файлы установленного контроллера (offline plan)

`compileDnsControllerServicePlan({schema:1, client:'vps2', firewallBackend:'legacy'})`
из `lib/dns-controller-service-plan.mjs` возвращает четыре фиксированных
артефакта. Разрешены `legacy` и `nf_tables`; Radxa этим renderer пока не
поддержана. Ничего не записывается и не запускается, `installationAllowed=false`.
Это подготовка установщика, не инструкция ручной установки на VPS.

- `clean-vpn-dns-client.service` запускает установленный `--start` под тем же
  inherited flock, что использует boot guard. Зависит от guard, adapter,
  resolved и networkd. `RemainAfterExit=yes`; обычный stop не восстанавливает DNS.
- `clean-vpn-dns-disable.service` явно выполняет `--disable`, сначала останавливая
  start-service. Adapter ему не нужен: восстановление должно работать при его
  отказе. Операция восстанавливает текущий boot, **не удаляет boot policy или
  файлы установки** и не является постоянным отключением интеграции.
- Два manager drop-in задают `Requires`/`After` для boot guard, чтобы запуск
  resolved/networkd не продолжался при отказе защитной службы.

Нет `[Install]`, auto-enable, перезапусков служб, daemon-reload или ExecStop
с неявным откатом. Публикация drop-ins — существенное изменение boot graph:
её должен выполнять установщик с проверкой владельца, возможностью аварийного
восстановления и журналом. Нельзя просто скопировать эти четыре файла на
живой клиент, особенно без проверенного независимого доступа.

Контроллер сохраняет initial mount/net/pid namespaces: его authority gate
сравнивает их с PID1 и читает credentials в mount namespace DynamicUser adapter.
Поэтому здесь намеренно нет ProtectSystem/PrivateTmp/PrivateDevices и подобных
mount-sandbox настроек. Ограничены capabilities, семейства сокетов, создание
новых namespaces, число FD/процессов, время запуска/остановки; используется
NoNewPrivileges. CAP_SYS_PTRACE нужен для межпроцессных `/proc` проверок;
CAP_NET_RAW выдаётся только для legacy firewall. Этот конкретный набор прошёл
отдельную VM-проверку systemd-unit; простой запуск CLI под root её не заменяет.
Основание для различия namespace/sandbox настроек —
[документация systemd249](https://github.com/systemd/systemd/blob/v249/man/systemd.exec.xml).

Четыре unit tests проверяют точные зависимости, сериализацию, отсутствие
неявного restore/enable, фиксированные команды и отклонение неизвестных
параметров. Сами unit tests не являются проверкой установленного service lifecycle.

Для следующей проверки подготовлен отдельный VM case `--case=installed-units`
в `dns-vm-lab.mjs` (с теми же обязательными tools/kernel/resolved).
Он публикует неизменённые четыре artifacts внутри NIC-less VM, запускает
реальные службы, проверяет системные A/AAAA, stop без отката, restart той же
транзакции, SIGKILL adapter с остановкой зависимого controller и disable без
adapter. Два прогона разделены штатной перезагрузкой после disable, не crash
активной транзакции.
Managers в этом tiny guest уже активны до публикации drop-ins: ранний boot
graph установленных drop-ins и полный дистрибутив этим сценарием не доказаны.

## Результат VM

`/var/tmp/meshpn-dns-vm-SGJprZ/report.json`: **8/8 PASS, две загрузки**,
срез `6961374`. Все261 installed source files совпали с этим commit по manifest.
Шаблоны unit-файлов не изменялись ради стенда; прошли старт с ограниченными
capabilities, системные UDP A/TCP AAAA, stop без отката, повторный start того же
журнала, SIGKILL adapter со снятием active-state зависимого controller и disable
без adapter. Собственный link удалён; journals released; host DNS unchanged.

| Загрузка | Первый start | Повторный start | disable |
| --- | ---: | ---: | ---: |
| 1 | 178224мс | 31189мс | 179672мс |
| 2 | 178552мс | 32184мс | 180736мс |

Здесь замерены systemctl job **и последующие чтения результата**. Сам unit
сохранил TimeoutStartSec=180; внешний observer имеет200секунд. Все Result=success,
ExecMainStatus=0. Запас в TCG мал; это не оценка скорости VPS/Radxa.

Это service lifecycle, не полный leak-test: исходный DNS10.129.0.2 в этом
минимальном fixture не является отвечающим upstream; отрицательный NSS-ответ
при аварии сам по себе не доказывает отсутствие пакетов к нему. Uplink pcap,
положительный контроль восстановленного upstream, installer/boot publication
и active-transaction reboot не входят в этот PASS. Прежние namespace проверки
guard остаются отдельным evidence. Live-клиент и DNS v1 этим не закрыты.
После сверки manifest удалены только пересоздаваемые guest tree/initrd/kernel;
report, serial logs, manifest и raw disk с завершёнными журналами сохранены.
