# Native combo: изолированный контейнерный runtime

Checkpoint 2026-10-29. Экспериментальный `combo-tls` теперь поддерживается общим
Docker/Podman launcher: packet/TUN/DNS обслуживает native boring-ветка, HTTPS
из явно указанной LAN — native transparent relay. Повседневная Radxa↔VPS пара
не менялась. Это расширение [runtime-контракта](clean-vpn-native-runtime.md),
а не установщик на физический шлюз.

## Конфигурация и границы

- Linux rootful Docker/Podman, отдельные namespace, uplink и LAN bridge.
  Host network запрещён. Standalone `transparent-tls` этот launcher пока
  не принимает; в combo поддерживается только `public-https` destination policy.
- Формат engine: `{version:1, transport:"combo-tls", role, boring:{...},
  transparent:{...}}`. Вложенный `boring` — обычный native packet config,
  `tun:"cvpn0"`; у клиента `dns:true`. Полная схема проверяется native engine
  до изменения сети. Примеры создаёт [исполняемый стенд](clean-vpn-native-combo-runtime-lab.mjs).
  Offline `clean-vpn-native-runtime-config.mjs` теперь поддерживает
  [combo bundles с несколькими клиентами](clean-vpn-native-combo-provisioning.md).
- Клиентские `boring.address/port` и `transparent.exit.ipv4/port` должны совпадать.
  На exit совпадают `boring.address/port` и `transparent.listen.ipv4/port`:
  обе ветки принимаются одним listener, например `3443`.
- `boring.sni` клиента равен `transparent.public_name`. Проверяемое TLS-имя
  сертификата `boring.server_name` и CA задаются отдельно: маскировочное имя
  не отменяет проверку сертификата. Сохранённый `tls_profile_path` применяется
  к boring-ветке; relay сохраняет параметры ClientHello приложения.
- Packet и relay используют отдельные файлы PSK, по 32 сырых байта, 0600/root.
  Общий relay PSK нужен обеим сторонам relay, но не должен совпадать с packet PSK.
- Клиент требует `--lan-network`, `--lan-ip`, `--lan-subnet` и relay listener
  `0.0.0.0:<порт>`, например `10443`. Порт `1053` занят native DNS. Relay INPUT
  разрешён только для перенаправленных соединений из указанной LAN.
  В этом bounded runtime LAN — подсеть внутри `192.168.0.0/16` с префиксом
  `/16..30`, не пересекающая uplink/exit; порт `2222` также зарезервирован.
  HTTPS самого контейнера автоматически в relay не перенаправляется.
- Перехват относится к **назначению TCP/443** в LAN; `3443` — независимый порт
  client↔exit. DNS/53 из LAN сначала перенаправляется в native DNS. Private,
  special, local, exit IP и пользовательский deny list исключены из relay;
  LAN TCP/443 после исключения блокируется, в packet/TUN ветку не переходит.
  Другой разрешённый IPv4-трафик идёт через packet/TUN. IPv6 вне loopback закрыт.
- Исходящий relay на exit разрешён только к допустимым public IPv4 TCP/443;
  ответы общего listener разрешаются отдельно. Это не общий direct OUTPUT.

## Replay volume и запуск

У combo exit обязателен `--replay-volume=NAME`: существующий named volume,
отличный от config volume. Конфиг должен указывать
`transparent.replay_directory:"/replay/state"`. Config mount остаётся read-only,
replay mount — read-write. Обычный start **не инициализирует и не сбрасывает**
replay state. Пустой, повреждённый, read-only state или второй владелец приводят
к отказу. Удалять replay volume при пересоздании exit нельзя.

Один раз для **нового** trial создайте volume и инициализируйте состояние.
Ниже `IMAGE` — свежий runtime image, `CONFIG_VOLUME` — приватный комплект exit,
`REPLAY_VOLUME` — новый выделенный volume; `exit.json` уже содержит `/replay/state`:

```bash
podman volume create "$REPLAY_VOLUME"
podman run --rm --network=none --cap-drop=ALL \
  -v "$CONFIG_VOLUME:/config:ro" -v "$REPLAY_VOLUME:/replay" \
  --entrypoint=sh "$IMAGE" -ec \
  'mkdir -m 700 /replay/state; exec clean-vpn-engine --init-transparent-replay /config/exit.json'
```

Команда намеренно откажет при существующем каталоге; не добавляйте `rm` или
автоматический reset. Для Docker заменить `podman` на `docker`. На Mac используйте
только connection выделенной Linux VM для всех команд, включая volume и build.

Exit запускается обычным `clean-vpn-native-container.mjs start --role=exit`
с `--replay-volume`, отдельными `--name`, `--network`, `--ip`, config и image.
Client — тем же launcher с `--role=client` и тремя LAN-опциями выше.
`--publish=3443` публикует только exit listener; при внутреннем listener `4443`
launcher сам строит mapping `3443:4443/tcp` из конфигурации. Значение CLI — число.
В локальной приёмке публикации на Mac нет: всё замкнуто на внутренних bridges.

При статическом `--ip` или LAN launcher включает `CVPN_ANNOUNCE_IPV4=1`.
После установки guard runtime посылает ARP announcements только для реально
назначенных IPv4 своих uplink/LAN интерфейсов. Это обновляет соседей при смене
MAC после recreate. Чужие neighbor tables не очищаются. Требуется новый image
с `iputils-arping`; зависимость проверяется до изменения сети.

## Health и аварии

Client health проверяет реальные UDP/TCP DNS через authenticated packet path
и наличие локального relay listener. **Это не проверка end-to-end HTTPS relay**:
для неё нужен запрос из LAN к проверяемому HTTPS origin. Exit health означает
только listener. Стенд отдельно выполняет настоящие packet и relay запросы.

Теперь есть opt-in [active relay HTTPS health](clean-vpn-native-combo-provisioning.md):
`--relay-health=relay-health.json`. Он проверяет relay до заданного origin,
но LAN interception по-прежнему требует отдельной LAN-пробы.

SIGKILL оставляет guard в живом namespace; при его удержании другим контейнером
LAN не получает прямой выход. Для нового namespace launcher создаёт правила
заново, exit повторно использует прежний replay volume. Partial setup не
продолжается автоматически. Повторная подготовка готового namespace проверяет
правила и сохраняет чужие chains. SIGTERM обрабатывает native PID 1.

## Воспроизводимая проверка

```bash
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
CVPN_RUNTIME_IMAGE=localhost/clean-vpn-native-runtime:local \
CVPN_OBSERVER_IMAGE=localhost/clean-vpn-native-observer:local \
CVPN_COMBO_LOAD_SECONDS=60 \
node scripts/clean-vpn-native-combo-runtime-lab.mjs /tmp/combo-report.json
```

Только выделенный Linux container engine; сети `10.77.0.0/24` и
`192.168.88.0/24` не должны пересекаться с другой лабораторией. Отчёт должен быть
новым файлом. Для Docker задайте `CVPN_CONTAINER_COMMAND='["docker"]'`.
Cleanup проверяет собственные имена и labels; ownership-файл остаётся для
независимого восстановления уборки. Без observer image fingerprint-gate
не выполняется — такой запуск нельзя выдавать за pcap-приёмку.

Проверяются одновременно packet DNS/HTTPS/TCP/UDP и четыре relay запроса за
итерацию, отдельный burst из 64 запросов, освобождение FD/threads и bounded RSS,
replay ownership, отказ relay без fallback, SIGKILL/recreate обеих сторон и
SIGTERM. Нагрузка ограничена 30–1800 сек; default 60, это не benchmark.
Для длительного прогона и опциональной матрицы сетевых помех см.
[combo resilience](clean-vpn-native-combo-resilience.md).
Production limits (16 relay slots, 32 новых admissions/sec) не повышались;
отказы при перегрузке ожидаемы и проверяются отдельно от штатной нагрузки.

Независимый pcap сравнивает boring ClientHello с сохранённым Chromium subset,
а JA3/JA4 relay — с оригинальным ClientHello приложения. Совпадение не доказывает
полную неотличимость от браузера. Replay после полного recreate дополнительно
проверяется отдельным `clean-vpn-native-runtime-replay-lab.mjs`, с повтором
захваченного токена и свежим положительным контролем.

Результаты: `fixtures/clean-vpn-native-combo-runtime-20261029.json`.
Фрагментация/таймауты: `fixtures/clean-vpn-native-relay-faults-20261029.json`.

| Проверка 2026-10-29 | Результат |
| --- | --- |
| Native CTest / отдельный ASan+UBSan fault test | 11/11; sanitizer run прошёл |
| Runtime unit/regression | 19/19 |
| Podman 6.1.4 combo lifecycle | 15/15, 60 сек: 464 relay + 116 packet batches |
| NIC-less Docker 28.5.2 combo lifecycle | 15/15, 60 сек: 460 relay + 115 packet batches |
| Boring runtime regression, порт 3443 | 24/24 |
| Durable replay, transparent + combo | 26/26, production engine, отдельная packaging fixture |

Native RSS в mixed-load пиках был меньше 6.7 MiB на процесс; FD и threads
после нагрузки вернулись к исходным значениям. Это не память всего контейнера.
В каждом combo capture совпали один packet profile и два relay JA3/JA4;
потерь capture kernel не зафиксировано. Все временные lab resources убраны.
Ранние отказы из-за порядка iptables options, перегрузки непейсированной
нагрузкой и устаревшего ARP сохранены в отчёте вместе с исправлениями.

Продолжение — [длительный mixed soak и netem loss/delay/reordering](clean-vpn-native-combo-resilience.md)
в этой же изолированной лаборатории. Физическая приёмка — отдельно,
без остановки повседневной пары.
