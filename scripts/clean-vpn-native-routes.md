# Native service: DHCP/uplink и владение маршрутами

Лабораторный этап 2026-10-07. C++ остаётся прямым systemd MainPID client/exit.
`clean-vpn-native-routes.mjs` — отдельный control plane: читает сетевые метаданные,
управляет собственными маршрутами и lifecycle клиента через systemd. Не принимает
пакеты, не пересылает DNS/HTTP/TLS и не запускает legacy client/exit. Unit допускает
только AF_UNIX/AF_NETLINK; DHCP-клиент остаётся отдельным владельцем lease/default.

## Поддержанный контракт

- Один заранее выбранный uplink, один global IPv4 и один main-table default.
  Смена адреса/gateway на том же интерфейсе допустима. Замена ifindex/MAC,
  дополнительные policy rules, несколько defaults/IP требуют ручного разбора.
- TUN и его адрес/MTU уже подготовлены. Отдельный guard unit активен и отвечает
  за firewall/DNS/forwarding policy. Проверка active/BindsTo не заменяет аудит
  содержимого site firewall; эта служба его не генерирует и не снимает.
- Собственные маршруты: endpoint `/32` через uplink и два split default через
  TUN. Адреса интерфейсов, DHCP default, sysctl, NAT и IPv6 не изменяются.
- Перед созданием/починкой/сменой маршрутов клиент останавливается через systemd;
  MainPID=0 и inactive/failed проверяются явно. После повторного снимка lease,
  записи и проверки маршрутов запускается непосредственно C++ service.
  **Это restart клиента, не бесшовное переключение; старые соединения могут оборваться.**
- Исчезновение uplink/default, чужой маршрут или неготовый guard оставляют
  клиента остановленным. Guard и журнал сохраняются. Ошибка quiesce завершает
  управляющую службу; `BindsTo` должен остановить зависимый engine.
- При остановке/падении управляющей службы маршруты и защита не удаляются.
  Повторный запуск использует тот же same-boot журнал и восстанавливает только
  точно принадлежащие ему отсутствующие маршруты, с проверкой прежних интерфейсов.

Слежение — netlink metadata с debounce и контрольным аудитом раз в 10 секунд;
при отказе event monitor — polling раз в секунду. Это не гарантированное время
восстановления. `ready` в логе означает проверенные маршруты/запрошенный запуск,
не доказанный egress: готовность транспорта отдельно сообщает C++ engine.

## Конфигурация и units

Пример схемы (не инструкция развёртывания на существующей Radxa):

```json
{
  "version": 1,
  "tun": "tun0",
  "uplink": "wlan0",
  "exit_ip": "154.62.226.216",
  "engine_unit": "native-client.service",
  "guard_unit": "site-guard.service",
  "route_unit": "native-routes.service"
}
```

Файл root-owned, owner-only, без symlink, максимум 4096 bytes. CLI принимает
только `--config=/absolute/file.json` и проверяет, что MainPID указанного
`route_unit` — он сам. Запуск вручную не выдаёт себя за service с защитой BindsTo.
`lib/native-route-unit.mjs` рендерит control-plane unit с зависимостью от
подготовки сети и guard. Native engine unit должен использовать этот route unit
как свою `networkUnit` и тот же guard. Ключи/сертификаты этой службе не нужны.
Renderer пока не является упаковщиком/установщиком всех site network units.
В этом профиле запуском клиента владеет coordinator: его запускают первым,
а клиент не включают независимо в boot target. Ручной параллельный start клиента
обходит этот порядок и не входит в контракт. Проверка собственного ActiveState
и `--job-mode=fail` не позволяют coordinator заменять уже поставленный stop job.

## Журнал смены gateway

Используется отдельный `/run/clean-vpn-native-routes-NETNS_ID`: приватный каталог,
пожизненная блокировка, boot/net/user namespace и идентичности интерфейсов.
В существующую библиотеку host routes добавлена отдельная операция rebind:

1. Аудит default, TUN, прежних маршрутов; endpoint должен быть собственным.
2. Durable intent `{dev, from, to}` до первого изменения.
3. Удаление точного старого маршрута и add точного нового, с аудитом после
   каждой операции. Нет `replace`, принятия чужого маршрута или общего flush.
4. После полного read-back — фиксация нового gateway и закрытие intent.

Прерывание до/после delete/add/commit покрыто тестами повторного выполнения и
точного rollback. Третий gateway при незавершённом переходе не принимается
автоматически. Посторонние изменения сохраняются и блокируют дальнейшую запись.
Concurrent firewall/route administrators не поддерживаются.

Для native journal явно разрешён только `linkdown` на прежнем собственном TUN:
это нормальный carrier state при отсутствии attached engine. Иные flags,
новый ifindex или linkdown на uplink не обходят проверку. Старые callers сохраняют
прежний строгий режим. Журнал с незавершённым переходом нельзя отдавать старой
версии recovery-кода, не понимающей новое поле.

## Лаборатория

```bash
node scripts/clean-vpn-native-lab.mjs HOST_BOOT_BASE QEMU_TOOLS_ROOT --native-routes
```

Изолированная NIC-less VM, настоящий systemd, два C++ клиента/общий C++ exit,
real TUN. BusyBox udhcpd/udhcpc действительно обмениваются DHCP сообщениями.
Отдельный fixture hook владеет только тестовыми lease/default; он не предназначен
для production. Application TCP/UDP/fragmentation и DNS проверяет C++ socket-test.

Сценарий проверяет исходный lease, новый адрес, новый gateway, исчезновение/
возврат default, удаление собственного маршрута, отказ при чужом маршруте,
восстановление после его явного удаления, SIGKILL route coordinator,
прямой fallback при сохранённом guard, restart и stop guard.
Ограничения: не Wi-Fi/hardware/ARM, не все DHCP-менеджеры, не packet capture всех
утечек, не IPv6 или USB/WG forwarding acceptance, не полный boot/provisioning
installer и не benchmark.

Продолжение: добавлен [native-only site profile](clean-vpn-native-network.md)
TUN/guard/DNS interception/SNAT/MSS и эти lifecycle units с fresh installer,
журналом установки и VM reboot/crash сценарием. Затем — C++ transparent/combo.

## Результат 2026-10-07

Окончательный прогон: **13/13 gates**, `status=passed`,
`/var/tmp/meshpn-native-lab-uPqrI5/report.json`.
Подтверждены настоящие DHCP leases `192.0.2.2 → 192.0.2.99 → 192.0.2.100`
и смена gateway `192.0.2.1 → 192.0.2.254`.
Предыдущие успешные прогоны: `B4DUEx`, `zr0X3E`.
Первые попытки выявили TUN linkdown при quiesce и ошибку fixture с PID фоновой
shell-функции вместо DHCP-процесса; исправлены и не засчитаны в успешные прогоны.

Регрессии **419/419**, CTest **3/3**; ASAN/UBSAN integration **18/18** и CTest
**3/3**. C++ binary не менялся относительно предыдущего installer checkpoint.
Хеши компонентов, все gates и ограничения:
[clean-vpn-native-routes-report.json](fixtures/clean-vpn-native-routes-report.json).
Radxa/VPS/Mac не изменялись, внешняя сеть и benchmark не использовались.
