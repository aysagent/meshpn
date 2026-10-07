# Полный native-переход: рабочий статус

2026-10-07. Цель — C++ data plane на client **и** exit, затем native
transparent/combo. Node остаётся control plane; совместимость с прежним Node
packet path не является обязательной. Production-развёртывания нет.
Измерение скорости отложено до полностью native схемы. Старые сравнительные
скрипты сохранены, но не являются приёмочным барьером.

## Реализовано в текущем шаге

Native boring-tls exit теперь использует один неблокирующий обработчик событий
для listener, TLS/H2-сессий и общего TUN вместо последовательного обслуживания.
Клиентский packet path также остаётся в C++; транспортные/DNS payload не
передаются через управляющий Node-процесс.

- До 32 настроенных клиентов с разными 32-байтными ключами и IPv4.
- Ключ аутентифицируется с TLS exporter; он определяет разрешённый source IP.
  Адрес из пакета не может выбрать или сменить identity.
- Ответы из TUN направляются только владельцу destination IP. Неизвестные
  адреса и неподдержанные пакеты отбрасываются. Client-to-client forwarding
  между настроенными peers по умолчанию запрещён до записи в TUN.
- Повторное соединение с занятым ключом/адресом отклоняется **до** ответа 200;
  действующий клиент не вытесняется. Потерянная сессия освобождается по EOF,
  ошибке или health deadline. Автоматической миграции сессии нет.
- До 16 незавершённых авторизаций, до 32 admissions/секунду, 5 секунд на
  TLS + H2 auth с момента accept. Это bounded admission, не обещание защиты
  от распределённого DoS или гарантированного входа нового клиента при атаке.
- Отдельные bounded очереди сессий; заполненный получатель не блокирует
  обслуживание остальных получателей общего TUN. Пакеты для заполненной
  outgoing-очереди отбрасываются и учитываются в packet counters.
- События ошибок соединений ограничены по частоте, metadata не содержит
  ключей, bearer, TLS error stack или payload. Режим `status` сохраняет
  прежний bounded control contract; состояние exit агрегированное.
- `--check-config /absolute/file.json`: проверка схемы, файлов ключей и
  TLS context без открытия TUN/listener и изменения сетевых настроек.

Реестр exit (пример формы; это не команда установки):

```json
{
  "version": 1,
  "role": "exit",
  "address": "0.0.0.0",
  "port": 443,
  "tun": "tun0",
  "cert": "/etc/clean-vpn/cert.pem",
  "key": "/etc/clean-vpn/key.pem",
  "peers": [
    { "ipv4": "10.99.0.2", "secret_path": "/etc/clean-vpn/peer-a.key" },
    { "ipv4": "10.99.0.3", "secret_path": "/etc/clean-vpn/peer-b.key" }
  ]
}
```

Client указывает свой `peer_ipv4` и `secret_path`, CA и проверяемое серверное
имя. Допустимые адреса этого этапа — `10.99.0.2..254`; dynamic IP allocation,
CIDR delegation и IPv6 data plane пока не реализованы. Повторные IP/ключи и
смешение `peers` с одиночным `secret_path` на exit отклоняются. Одиночный
`secret_path` остаётся краткой конфигурацией одной native-пары, не Node fallback.
Native DNS stub/source следует `peer_ipv4`. Фиксированный USB control profile
по-прежнему разрешает только `.2`; маршруты и DNS для остальных peers должен
подготовить внешний control plane. Регистрация/ротация peers пока требует restart.

## Лабораторные проверки

`test-native-multi-peer.mjs` подготавливает PKI/config; генерация и проверка
всех IP-пакетов выполняется **C++** fixture:

- два независимых клиента, 400 двунаправленных адресованных пакетов;
- незавершённые/частичные TLS handshakes не задерживают их вход;
- duplicate identity, неверный source и client-to-client destination не
  инжектируются в TUN и не ломают остальные сессии;
- поток новых TCP-подключений, admission/FD bound и истечение auth deadline;
- пять reconnect одного клиента при продолжающейся работе другого;
- остановленный через SIGSTOP авторизованный получатель и переполнение его
  очереди не блокируют второго клиента; после SIGCONT/reconnect обмен возвращается;
- все 32 клиента одновременно, ещё 256 адресованных пакетов;
- ограничения RSS/FD и завершение процессов;
- отрицательные конфигурации с повторными ключами/IP, лишними полями и лимитами.

Основные проверки:

```bash
cmake --build native/clean_vpn/build -j2
ctest --test-dir native/clean_vpn/build --output-on-failure
node --test scripts/test-native-multi-peer.mjs scripts/test-native-data-plane.mjs scripts/test-native-dns.mjs
CVPN_NATIVE_ONLY=1 CVPN_SOAK_SECONDS=180 node --test scripts/test-native-soak.mjs
```

`clean-vpn-native-lab.mjs HOST_BOOT_BASE QEMU_TOOLS_ROOT --native-only` использует
NIC-less VM и реальные kernel TUN, firewall/DNS/SNAT и USB-подобный peer.
В этом режиме нет Node client/exit, mixed-version проверок или benchmark.
Node запускается только как native control coordinator. Проверяются DNS,
TCP/UDP/fragmentation, uplink recovery, native exit restart, graceful stop,
engine crash, сохранение guard и SSH, уборка процессов. Этот VM-сценарий пока
проверяет одну native-пару, не multi-peer routing в настоящем kernel TUN.
Он также **не** проверяет native systemd installer/boot; это следующий этап.

### Зафиксированный результат 2026-10-07

- Общий regression-набор: 381/381, без пропусков; включает сохранённые
  control-plane/rollback тесты. Это не означает запуск legacy в native-only VM.
- CTest: 2/2; ASAN/UBSAN: 18/18, включая multi-peer и DNS второго клиента.
  Инструментирован собственный C++ код, не сторонние зависимости.
- DNS для `.3` проверен в отдельном network namespace без адреса `.2`, включая
  исходный адрес UDP/TCP запросов к upstream.
- Native-only endurance, 180 секунд: 936 256 пакетов с проверкой содержимого,
  0 dropped packets, 0 unexpected reconnects; 36 отсчётов ресурсов,
  peak RSS 6232 KiB, максимальный рост RSS 1188 KiB. Это тест устойчивости
  на fixture, **не** измерение скорости интернета.
- Native-only VM: 10/10 gates, `status=passed`, без внешней сети и shared FS.
  Локальный отчёт: `/var/tmp/meshpn-native-lab-CUAJqt/report.json`.
  SHA-256 проверенного production engine:
  `2464763cee6b7ca821a9dcdb301c683cea2764ddc3dbe0b8d4b19e21b2676e92`.
  Отрицательные probes намеренно возвращают ошибки — итог оценивается по
  gates, включая positive control, crash guard и cleanup.

Radxa/VPS/Mac не изменялись; развёртывание и WAN benchmark не запускались.

## Что ещё не закончено

Продолжение 2026-10-07: добавлены [прямой C++ service и systemd-лаборатория](clean-vpn-native-service.md).
Этот шаг отделяет lifecycle engine от сетевого provisioning. Старый результат
VM выше относится к предыдущей сборке и сохранён как отдельный checkpoint.

1. Эксплуатационная интеграция native-only network provisioning client и exit.
   [Route ownership/DHCP recovery для direct service](clean-vpn-native-routes.md)
   реализованы отдельным coordinator без packet IO. Добавлен [единый site profile](clean-vpn-native-network.md)
   TUN/guard/DNS/SNAT/MSS с fresh-only установкой, activation target и VM
   crash/reboot сценарием. Network manager/address/default пока — внешний владелец;
   нельзя применять профиль к существующему firewall или уже поднятому uplink.
   [Fresh installer и cold boot/reboot в VM](clean-vpn-native-install.md)
   добавлены отдельным checkpoint на fixture-сети. Direct C++ systemd
   start/stop, crash-restart обеих сторон и два peer через реальные TUN уже
   проверены отдельной лабораторией; это ещё не полный production provisioning.
   Нужны также расширенные ресурсные прогоны разных нагрузок. Не расширять
   текущий USB профиль молча.
2. Перенос transparent relay/обработки потоков в C++, защищённая судьба
   non-HTTPS трафика, негативные handshake/relay тесты.
   [Первый C++ codec/HRR checkpoint](clean-vpn-native-transparent.md) проверен
   на full/resumed TLS 1.2/1.3 (включая HRR) внутри memory BIO. Добавлены native
   enc-SNI/auth, durable replay и scoped TCP relay с backpressure/half-close.
   Scoped engine client/exit и SO_ORIGINAL_DST/REDIRECT проверяются в отдельном
   namespace с SIGKILL/restart. Public-HTTPS destination policy добавлен и
   проверяется через veth/отдельный origin namespace без внешнего Интернета.
   Добавлен standalone LAN HTTPS network guard с default-DROP остальных типов
   трафика и общей моделью владения firewall. Пять namespace проверяют оба C++
   engine, PREROUTING REDIRECT, SIGKILL client/exit, restart и отсутствие
   выбранного прямого обхода. Fresh site installer теперь связывает engine и
   firewall, создаёт replay state до публикации unit и выделяет ему единственный
   writable каталог. [Transparent systemd/cold boot](clean-vpn-native-transparent-boot.md)
   прошёл 19/19 gates на двух загрузках: сохранность байтов/прав replay,
   автозапуск обеих ролей, crash/restart, отказ при missing/corrupt state и
   восстановление только явно сохранённых fixture-байтов. Это не power-loss,
   live-token replay через reboot или physical-host приёмка.
3. [Native combo engine checkpoint](clean-vpn-native-combo.md): общий exit listener,
   выбор ветки по ClientHello и владение потоками внутри C++ реализованы.
   Проверены одновременный packet/TLS fixture и replay после exit crash.
   Единый network profile и реальные TUN/DNS/LAN проверены в NIC-less VM:
   HTTPS через transparent, TCP/UDP/DNS через boring, crash/restart обеих ролей,
   отказ прямого fallback даже после удаления split routes. Нельзя склеивать
   standalone guards вручную. [Installer/systemd приёмка](clean-vpn-native-combo-boot.md)
   дополнительно прошла 23/23 gates на двух загрузках: nested PKI/PSK, replay,
   direct C++ client/exit, установленный route coordinator, crash/autorestart и
   отказ при missing/corrupt replay без автоматического reset. Общая регрессия
   416/416; CTest normal/ASAN 6/6 и ASAN integration 16/16. Это fresh dedicated-host
   контракт, не distro migration, physical acceptance или live upgrade.
4. [Native-only смешанная нагрузка](clean-vpn-native-combo-soak.md) прошла 180 секунд:
   2 437 092 проверенных пакета, 1 907 TLS-сеансов, без packet drops/reconnect;
   FD/threads вернулись к baseline. Отдельно пройден 30-секундный ASAN/UBSAN
   прогон. Регрессия 418/418, CTest normal/ASAN 6/6, ASAN integration 10/10.
   Границы: loopback/fixture packet FD, один peer, не real-TUN или WAN benchmark.
   Далее real-TUN длительная нагрузка и воспроизводимые измерения
   полностью native схемы (не Internet speed из TCG) и следующие продуктовые
   этапы roadmap. Браузерные профили/UI не объявляются реализованными этим шагом.

Это промежуточный этап полного переноса, **не** заявление «весь native готов».
