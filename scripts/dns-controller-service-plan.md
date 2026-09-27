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
CAP_NET_RAW выдаётся только для legacy firewall. Этот конкретный набор требует
положительной VM-проверки systemd-unit: успешный запуск CLI под root её не заменяет.
Основание для различия namespace/sandbox настроек —
[документация systemd249](https://github.com/systemd/systemd/blob/v249/man/systemd.exec.xml).

Четыре unit tests проверяют точные зависимости, сериализацию, отсутствие
неявного restore/enable, фиксированные команды и отклонение неизвестных
параметров. Пока это **не проверка установленного service lifecycle**.

Для следующей проверки подготовлен отдельный VM case `--case=installed-units`
в `dns-vm-lab.mjs` (с теми же обязательными tools/kernel/resolved).
Он публикует неизменённые четыре artifacts внутри NIC-less VM, запускает
реальные службы, проверяет системные A/AAAA, stop без отката, restart той же
транзакции, SIGKILL adapter с остановкой зависимого controller и disable без
adapter. Два прогона разделены штатной перезагрузкой после disable, не crash
активной транзакции. Результат ожидается; наличие сценария не считается PASS.
Managers в этом tiny guest уже активны до публикации drop-ins: ранний boot
graph установленных drop-ins и полный дистрибутив этим сценарием не доказаны.
