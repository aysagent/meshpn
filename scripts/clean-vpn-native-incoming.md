# Входящие подключения через native VPN

Для сервиса, к которому VPS должен сам открывать новые соединения, у native
boring-tls client есть опция engine config:

```json
"connection_mode": "persistent"
```

В combo-tls она располагается внутри `boring`. По умолчанию действует
`on-demand`: после штатного закрытия HTTP/2 клиент ждёт исходящего IP-пакета
или DNS-demand. В `persistent` клиент после такого закрытия использует обычный
bounded reconnect, не ожидая пользовательского трафика. Проверки CA, имени,
срока сертификата и PSK сохраняются. Существующий H2 PING обнаруживает потерю
связи; синтетические HTTP/DNS-запросы для пробуждения не добавлены.
При постоянно закрывающем соединение exit этот режим создаёт повторные
handshake с обычной задержкой retry 250 мс; он явно выбирается для входящих
сервисов. Уже оборванные TCP/WS/SSE сессии приложение переподключает само.

## Узкое разрешение в Radxa host-profile

`persistent` управляет доступностью соединения. Входящие права задаются отдельно:
опциональный `incoming_tcp` в JSON, передаваемом installer как `--host-profile`:

```json
{
  "version": 1,
  "guard_unit": "clean-vpn-killswitch.service",
  "guard_script": "/usr/local/bin/clean-vpn-killswitch.sh",
  "incoming_tcp": {"source_ipv4": "10.99.0.1", "port": 9443}
}
```

Этот первый профиль разрешает один TCP-порт 1024–65535 от tunnel IP exit
`10.99.0.1` к выбранному `peer_ipv4` клиента. 1053 занят native DNS; нельзя
также выбрать порт combo relay. Нужны engine с capability `connection_modes`
и `persistent` в его config. Старый бинарник или on-demand отклоняются установщиком.

Network owner журналирует INPUT-правила: новые соединения с TUN разрешаются
только на этот endpoint; ответы существующих соединений продолжают работать.
Этот же endpoint закрыт при поступлении через другой интерфейс. USB/локальные
DNS-запросы к listener 1053 не перекрываются. Политика других портов WAN/USB
остаётся у существующего firewall. При stop сначала останавливается engine,
затем удаляются только собственные правила; независимый guard остаётся.
Каждый промежуточный шаг записи правил имеет recovery-проверку.

Сервис должен слушать конкретный VPN IP, например `10.99.0.2:9443`, и проверять
собственные mTLS credentials. VPN PSK не заменяет mTLS. Native engine проверяет
peer destination до выдачи пакета в TUN, поэтому этот grant не экспортирует LAN
и не добавляет маршрутизацию между клиентами. На exit требуется разрешённый
OUTPUT и маршрут к peer; host-profile не переписывает чужой OUTPUT firewall.

## Лаборатория и граница совместимости

В одноразовом NIC-less systemd-стенде `native-host-multi-lab.mjs` режим
`CVPN_HOST_MULTI_INCOMING=1` проверяет новый mTLS-запрос с exit после 20 секунд
без исходящих application/DNS probes, отказ другого source/порта/сертификата,
недоступность LAN через TUN, outage exit и пересоздание клиентского TUN.
`CVPN_HOST_MULTI_COMBO=1` повторяет это для packet-ветки combo с работающим relay.
Проверка C++ отдельно заставляет peer закрывать H2 через END_STREAM/GOAWAY:
три входящих пакета принимаются после переподключений при `tx_packets=0`.

[Отчёт 29 октября](../fixtures/clean-vpn-native-incoming-20261029.json):
13 systemd сценариев boring и 15 combo, 37 kernel checks, 31 regression test,
10 CTest и 18 TLS-profile тестов на новой ARM64 сборке. Последние выполнены
двумя прогонами: 15 сразу, ещё три ML-DSA после сборки отсутствовавшего test-only
credential helper. Дополнительно проверены installer/preflight и изоляция peers.
Snapshot hashes и ограничения каждого прогона сохранены в отчёте.

Это prerequisites для самостоятельного public-proxy. Проверяется fixture
mTLS service, а не приложение public-proxy, Caddy, его авторизация или поведение
agent при исчезновении адреса. Caddy namespace, HTTP/WS/SSE, долгий простой,
физический smoke и совместный recipe остаются отдельной приёмкой. Transparent-tls
сам по себе не является двунаправленным IP-туннелем. Постоянная установка на
Radxa/VPS этими проверками не выполняется.
