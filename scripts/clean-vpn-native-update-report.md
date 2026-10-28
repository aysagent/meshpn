# Binary update: лаборатория и Radxa/VPS, 2026-10-28

## Результат

Реализовано [обновление native-бинарника](clean-vpn-native-update.md) с
сохранением релизов, журналом, автоматическим rollback и boot recovery.
Приёмка текущей реализации `6b9ed94`:

| Проверка | Результат |
| --- | --- |
| Локальные transaction/boot-evidence/lab-parser tests | 21/21 |
| Transaction + fresh installer + boot-evidence на Radxa и VPS | по 18/18 |
| Существующий native CTest на Radxa и VPS | по 10/10 |
| Реальный systemd update-check в отдельном namespace на каждой машине | по 8/8 |
| NIC-less QEMU, три различных kernel boot ID | 46/46: 22 + 14 + 10 |
| Полный Radxa ↔ VPS boring-tls smoke с браузерным профилем | passed, включая USB и возврат legacy |

[Машиночитаемый отчёт](../fixtures/clean-vpn-native-update-20261028.json),
[полный boot evidence](../fixtures/clean-vpn-native-update-boot-20261028.json).

## Что проверено в обновлении

На настоящем systemd каждой машины запускалась отдельная пара native client/
exit с Chromium-derived профилем. Namespace не имел WAN/veth и не менял
маршруты основной машины. Проверены обновление обеих ролей, отказ при изменении
привязанного unit-файла, rollback неработающего кандидата, сохранение остановленного
состояния и восстановление после SIGKILL главного update-worker. Службы, namespace
и установочные bundle после проверки удалены. Host firewall сохранился.

В VM дополнительно передавались пакеты через TUN после замены binary. Затем
updater был убит после публикации нового ELF, но до commit. Следующий отдельный
запуск kernel восстановил прежний binary **до** старта native service, после
чего снова прошли передача данных и DNS. На третьей загрузке отказ guard
заблокировал engine/uplink. Ключи, config и остальные исходные файлы сохранились.

VM хранит установленные файлы на persistent ext4 и восстанавливает их в
initramfs перед PID1. Это проверка нового kernel boot, не снятие питания с Radxa
и не испытание её flash при power loss. Physical namespace check не измеряет WAN
или throughput. В качестве двух релизов использовался один доверенный ELF с
различающимся хвостом-маркером: изменения C++ версии этим не заявляются.

## WAN и независимый профиль

На VPS был запущен прежний bounded exit trial с отдельным TUN и точными
FORWARD/MASQUERADE-правилами. На Radxa native client временно заменил legacy
через существующий journalled DNS/route owner; kill switch и USB rescue работали.

Последний smoke прошёл во всех трёх состояниях — legacy / native / restored:
DNS 4/4, HTTPS 2/2, скачивание 1 MiB. Дополнительные USB-пробы с Mac также прошли
во всех трёх состояниях: DNS 4/4, HTTPS 3/3 и 1 MiB. `rollback=verified`,
`guard=verified`. Это функциональные пробы, не benchmark линии.

Независимый tcpdump на VPS eth0: 1601 пакет, **0 kernel drops**, анализ отдельным
CLI на Mac. Native ClientHello соответствует сохранённому subset-профилю:

- JA3 этого конкретного Hello: `a44bf561179108e5d415d80dceda3b32`;
- JA4: `t13d0915h2_f91f431d341e_54d72502093d`;
- legacy Hello в том же pcap: `mismatch`;
- pcap SHA-256: `aeb3481815a00600edfbcff736d94f43994f2801f33099b18225d900c90048f5`.

JA3 может меняться из-за перестановки extensions. Match подтверждает конкретный
ограниченный профиль, не весь сетевой профиль Chromium. Приватный pcap не включён
в git; итоговый отчёт содержит только fingerprints/hash. Наблюдатель завершился
по своему RuntimeMaxSec, поэтому systemd timeout у него ожидаемый.

## Отказы сохранены

- Первый WAN smoke: native прошёл, но после возврата legacy скачивание оборвалось
  по 20-секундному deadline на 302319 байтах. Служба и защита восстановились.
  Причина не установлена; повторный полный pass не стирает этот результат.
- Первый VPS crash-check: `systemctl kill --kill-whom=all` вернул EINVAL для
  auxiliary processes. Cleanup завершился; проверка изменена на SIGKILL main
  worker, с уничтожением его дочерних процессов штатным KillMode systemd.
- В VM сначала отсутствовал `systemd-run`; executable и библиотеки добавлены.
- Debug ELF и его tmpfs-копии превысили фиксированные 256 MiB worker. Автоматическое
  восстановление вернуло старый engine. Budget теперь зависит от размера ELF.
- Прежний диск VM 128 MiB не вместил retained debug releases; для этой матрицы
  выделено 512 MiB. В production updater дополнительно проверяется свободное
  место и удаляется частичный временный файл при ENOSPC; добавлены регрессии.

## Состояние машин после работы

- Исходники на обеих машинах обновлены через Git; Radxa — verified bundle по USB.
  Native C++ с последней сборки не менялся, пересборка BoringSSL не требовалась.
- На Radxa работают исходные legacy VPN, guard, USB rescue, USB SNAT и админка.
  Native updater не подключался к этим legacy-службам.
- VPS возвращён к исходному состоянию: временный exit остановлен, port 443
  освобождён, исходный `ip_forward=1` сохранён. Посторонние службы не трогались.
- Сетевые снимки совпали после исключения счётчиков/timestamps и новых lifecycle
  owner IDs DNS/IPv6 на Radxa. Это сравнение политики, не побайтовое равенство
  строк со случайными идентификаторами.
- На физических машинах новых kernel OOM нет. Временных test namespaces/units
  не осталось. Default route Mac совпадает; его сеть, часы и trust store не менялись.
- Часы Radxa после выключения отставали примерно на 12 часов. Они исправлены
  вперёд по authenticated SSH времени VPS со сверкой Mac UTC. Это ручная коррекция,
  постоянный clock bootstrap не установлен.

## Что остаётся

Закрыт **binary-update checkpoint для новой именованной boring-tls установки**.
Постоянный native VPN на Radxa/VPS не включён, физического reboot/power-cycle
не было. Следующий этап — миграция existing-host lifecycle: единственный владелец
DNS/маршрутов/guard, подключение условного clock recovery и updater, временный
пилот именно этой установки с восстановлением. После этого — физическая boot
приёмка и решение об оставлении native в автозагрузке. Настраиваемые native DNS
upstream и OpenWrt остаются отдельными пунктами, этим отчётом не закрываются.
