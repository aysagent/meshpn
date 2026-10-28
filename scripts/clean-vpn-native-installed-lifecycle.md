# Installed native lifecycle: checkpoint 2026-10-28

Именованная boring-tls установка теперь включает опциональный clock recovery
и совместима с binary updater. Связка временно проверена на настоящей Radxa
через существующего владельца DNS/маршрутов, независимый kill switch и VPS.
**Это ещё не постоянная миграция и не физическая boot-приёмка.**

## Что добавлено

Fresh installer принимает `--clock-profile=/absolute/private.json` только для
boring-tls client с внешними network/guard units. Профиль содержит:

```json
{
  "version": 1,
  "host": "192.0.2.1",
  "port": 22,
  "user": "cvpn-clock",
  "identity": "/private/identity",
  "known_hosts": "/private/known-hosts"
}
```

`host` должен совпадать с IP exit в native config. Это заранее проверенный
SSH endpoint с отдельным ограниченным ключом; installer не настраивает sshd,
не создаёт пользователей и не получает доверие через ssh-keyscan.
Ключ, raw Ed25519 pin, helper, config и recovery unit копируются в installation
bundle. Часы и службы установщик не запускает. В `clock-state/` отдельно
хранятся бюджет попыток и нижняя граница времени: обновление ELF их не сбрасывает.

Clock recovery и updater используют один flock. Пока идёт обновление или
остался незавершённый журнал, clock helper не выполняет запрос/коррекцию/restart.
Вне обновления сохраняется прежнее условие: только native time failure, одна
попытка на boot, полный повтор TLS-проверок после реальной коррекции.
У engine нет CAP_SYS_TIME.

`clean-vpn-usb-snat.mjs --status --native-unit=native-NAME.service` проверяет
готовый notify service, остановленный legacy и активные BindsTo-зависимости.
Режим по умолчанию по-прежнему проверяет `clean-vpn.service`. Новый флаг сам
не переключает установленный SNAT unit на native и не изменяет firewall
при `--status`.

## Физическая приёмка

На каждой машине отдельный unconnected namespace: **10/10**, включая
обновление client/exit, плохой кандидат, SIGKILL updater, сохранение clock floor
и отсутствие автоматической clock attempt. Host VPN при этих проверках
не останавливался.

Затем на Radxa выполнены два полных временных installed smoke. Последний:

- legacy/native/restored: DNS 4/4, HTTPS 2/2, скачивание 1 MiB;
- USB на Mac во всех трёх фазах: DNS 4/4, HTTPS 3/3, 1 MiB;
- проверка native-владельца SNAT;
- явный read-only запрос времени через ограниченный SSH account с pinned key;
- обновление установленного ELF, затем реальные DNS/HTTPS;
- кандидат с кодом 77: rollback и повторные DNS/HTTPS;
- PID владельца маршрутов/DNS сохранился, автоматическая clock attempt
  не появилась, исходный ELF возвращён;
- guard и возврат legacy — `verified`.

Кандидат — доверенный прежний ELF с хвостом-маркером, а не новая C++ версия.
Тестовый network unit подтверждает активность внешнего trial owner; сам DNS
и маршруты остаются у этого owner. Постоянным network service он не является.
Новый независимый pcap в этом checkpoint не снимался; профиль проверялся native
config и переносился без изменения. Предыдущая wire-приёмка — в
[отчёте binary update](clean-vpn-native-update-report.md).

## VM и регрессии

**49/49 gates, три разных kernel boot ID**: installed clock unit, обновление,
передача данных, rollback, прерванная транзакция, recovery до старта следующего
boot, сохранность установки и отказ запуска при отказе guard.
В VM постоянные артефакты восстанавливаются с ext4 в initramfs; это не
отключение питания физической платы и не испытание её flash.

Первый новый boot-прогон выявил ошибку стенда: clock unit не копировался в
постоянный набор units. Исправлены сохранение и inventory, все три загрузки
повторены успешно. Ошибка не скрыта за повторным pass.

Локально: 69 Node + 14 Python тестов. Linux installer/transaction/trial:
86 passed, 1 существующий skip. На Radxa финальные installer/update/SNAT:
41/41. Отдельно SNAT + boot-evidence: 25/25. Linux-specific build prerequisite
тест в расширенном Mac-прогоне отказал из-за отсутствующего flock;
соответствующая Linux-матрица прошла.

[Компактное свидетельство](../fixtures/clean-vpn-native-installed-lifecycle-20261028.json),
[полный boot report](../fixtures/clean-vpn-native-installed-boot-20261028.json).

## После проверки и следующий этап

Legacy VPN, kill switch, USB rescue/SNAT и admin broker Radxa восстановлены.
Временные установки, clock account/key и exit удалены/остановлены. Новых OOM
нет. Mac не перенастраивался. Часы физических машин не менялись, reboot не было.
Сетевые политики совпали после исключения счётчиков, времён жизни, случайных
owner IDs и одного нового link-local IPv6 адреса пересозданного tun0.

До самостоятельной native-автозагрузки остаётся конкретный переход:

1. Упаковать постоянного владельца Radxa DNS/маршрутов/TUN вместо trial owner;
   сохранить единоличное владение, crash recovery и независимый guard.
2. Журналируемо переключать legacy/native activation и SNAT dependency;
   восстанавливать исходные unit/drop-in состояния, не менять USB rescue.
3. Проверить этот переход и его аварии в VM, затем временно на плате.
4. Только затем проверять boot новой установки на Radxa. Reboot и реальное
   отключение питания учитывать раздельно; текущие результаты их не заменяют.

Работающая временная native-служба не означает, что эти четыре пункта закрыты.
