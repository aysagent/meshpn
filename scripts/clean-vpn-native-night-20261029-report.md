# Самостоятельный native client/exit: результат ночной работы 29 октября

Реализован самостоятельный lifecycle для проверенной Radxa и существующего VPS,
без зависимости от старого Node VPN. Выполнены временные физические проверки,
загрузки VM, аварии и ограниченные soak. Постоянный native autostart на узлах
не включён. Node остаётся в админке/control plane; payload/TLS/DNS — C++.

## Что закрыто

| Область | Результат и доказательство |
| --- | --- |
| Radxa client owner | TUN identity, routes, tunnel DNS, USB SNAT/MSS, same-boot journal, независимый ExecStopPost; 21 kernel check |
| Client lifecycle | 14 systemd сценариев: engine/owner SIGKILL, stop/restart, exit outage, late uplink, link down/up, смена gateway; [отчёт](../fixtures/clean-vpn-native-host-systemd-report.json) |
| Свежая админка | Явная привязка `--native-name`, start/stop через owner, обе службы в диагностике; 23 unit + 9 real-systemd checks; [отчёт](../fixtures/clean-vpn-native-host-admin-report.json) |
| Existing-host exit | Только собственный TUN/FORWARD/NAT, сохранение foreign rules/routes/forwarding; 23 kernel + 11 real-systemd checks и 32 installer/unit regressions; [отчёт](../fixtures/clean-vpn-native-exit-host-report.json) |
| Boot/update/recovery | 30 проверок на трёх настоящих загрузках QEMU: оба установленных owner, autostart, client binary update/rollback, SIGKILL client/exit owner, guard failure; [отчёт](../fixtures/clean-vpn-native-host-boot-report.json) |
| Owner soak | 900 с, 87 замеров, 4 SIGKILL, живые DNS UDP/TCP и HTTPS; [отчёт](../fixtures/clean-vpn-native-host-soak-report.json) |
| Runtime/container soak | 3612 с, 317 замеров, 12 restart, 27 проверок, LAN ingress, DNS/HTTPS/TCP/UDP, independent capture, cleanup; [отчёт](../fixtures/clean-vpn-native-runtime-soak-20261029.json) |
| Физический Radxa↔VPS | Временный host client, затем пара с новым scoped exit; DNS/NSS/HTTPS, SIGKILL обоих owner в отдельных прогонах, проверенный cleanup; [отчёт](../fixtures/clean-vpn-native-host-physical-report.json) |

Часовой runtime выполнен на Podman ARM64 с ранее проверенным engine image;
новой C++ компиляции эта работа не требовала. Docker имеет предыдущую приёмку,
в эту ночь заново не запускался. Новый host-profile и container runtime имеют
разные владельцы сети: контейнер не перенастраивает маршруты/DNS Mac или Linux host.

## Что нашли и исправили

- Системный `network-online.target` ждал неиспользуемые интерфейсы Radxa:
  owner теперь проверяет свой uplink и повторяет запуск при его отсутствии.
- NVM Node на физических узлах: сохраняется настоящий абсолютный путь runtime.
- Stop во время синхронного audit command мог пометить owner failed:
  `KillMode=mixed` позволяет закончить аудит, сохраняя принудительную уборку детей.
- Завершённый журнал прежнего именованного instance мешал новой установке:
  stage `released` допускает свежий instance; незавершённое чужое владение запрещено.
- Binary updater учитывает вложенные manifest paths и hashes собственных unit/drop-in.
- У существующей старой USB SNAT службы нет автоматического удаления правил
  при stop: её три правила убраны штатным scoped helper. Чужой uplink MASQUERADE сохранён.

Ошибки ранних стендовых прогонов не скрыты в reports: tmpfs `/run` с неправильным
mode, stale тест из image и недостаточный 90-секундный TCG recovery deadline.
Production ownership/permission проверки ради успеха не отключались.

## Измерения и мимикрия

В последнем физическом запуске client готов за 13.954 с, exit — за 1.063 с.
После SIGKILL exit owner listener восстановился за 11.143 с, затем прошли
повторные клиентские DNS/HTTPS. В предыдущем physical run client owner восстановился
за 37.886 с. Эти величины включают systemd retry и не являются benchmark пропускной способности.

В часовом container soak client RSS 6212–6440 KiB, FD=7/socket=3; exit
5736–6360 KiB, FD=6/socket=2. Zombie-процессов нет. В отдельном owner soak
engine RSS 6588–6656 KiB, FD=8; Node owner 66520–67144 KiB, обычно 27 FD,
два кратких замера 35, затем возврат к 27. Это выборочные parent-process
измерения и малая нагрузка; они не доказывают отсутствие любых долгосрочных утечек.

Независимый physical tcpdump увидел два ClientHello, matched
`chromium-156-bounded-cold-v1`. JA3 различался из-за допустимой перестановки
extensions, JA4 совпадал: `t13d0915h2_f91f431d341e_54d72502093d`.
Container capture ограничен 20000 пакетами: девять записанных ClientHello matched,
kernel drops=0. Это сверка заданных cold ClientHello полей, не доказательство
полной неотличимости браузера. В последнем smoke нового exit дополнительного
pcap не было; раннее physical и container evidence не выдаётся за его capture.

## Состояние после проверок

- На Radxa все новые native instances остановлены; guard и USB rescue активны.
  Старые VPN/SNAT службы остановлены, их прежний enable-state не менялся:
  после reboot они могут стартовать. Перед постоянной native активацией их
  достаточно отключить — проект не требует бесшовной миграции/возврата legacy.
- На VPS новые native службы остановлены. Содержимое foreign firewall rules
  совпало с baseline (счётчики исключены), IPv4 routes совпали; forwarding=1.
  x-ui и Docker активны с прежними MainPID.
- Собственные installed/prepared/window unit-файлы испытаний удалены после
  сверки hashes; четыре client bundle и один exit bundle архивированы в
  приватных root-каталогах испытаний. Ключи не публиковались.
- Временная блокировка транзита ноутбука через Radxa удалена. Сеть, Wi-Fi,
  DNS, маршруты и часы Mac не менялись. Лабораторные прогоны остановлены,
  Podman VM и кэш сохранены для следующих запусков.
- Существующая физическая админка не перепривязана к новым instances.
  `device/**` и другие параллельные пользовательские изменения не включены в наши коммиты.

## Следующая отсечка

1. Совместная VM-приёмка нового host-profile и условного clock recovery с
   действительно неверной датой и независимыми часами exit. Ранее этот clock
   механизм прошёл свою two-VM матрицу; в новой 30-case матрице часы исправны,
   clock-profile присутствует, SSH bootstrap не требуется. Эти результаты не складываются
   автоматически в доказательство новой совместной связки.
2. Подготовить выбранную постоянную пару: выключить старые конкурирующие units,
   привязать физическую админку к native, проверить профиль/settings rollback.
   Новая постоянная активация остаётся отложена по указанию пользователя.
3. После выбора постоянной установки — физический reboot и отдельный cold/power-loss
   сценарий Radxa с USB rescue. VM reboot не заменяет эту приёмку.

Расширения после boring-tls: настраиваемый адрес client host-profile для нескольких
Radxa, combo/transparent host lifecycle, более полная browser fidelity, OpenWrt/LuCI
и public-proxy ingress. До этого не требуется добавлять новые DNS backends или
возвращаться к совместимости со старым Node data plane.

Рабочие инструкции: [client host](clean-vpn-native-host-network.md),
[existing exit host](clean-vpn-native-exit-host.md),
[runtime Docker/Podman](clean-vpn-native-runtime.md), [админка](../admin/README.md).
