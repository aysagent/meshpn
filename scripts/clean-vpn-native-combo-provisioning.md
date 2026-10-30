# Native combo: комплекты клиентов, active relay health и общий exit

Локальный этап 2026-10-29, после [soak/netem](clean-vpn-native-combo-resilience.md).
Физические Radxa/VPS и сеть Mac не меняются. Первый этап менял provisioning/control layer; последующее native-исправление —
[отдельные ключи, квоты и подбор ёмкости](clean-vpn-native-relay-quotas.md).

## Offline-комплект

```bash
node scripts/clean-vpn-native-runtime-config.mjs create \
  --directory=/absolute/new/combo-bundle --mode=container \
  --transport=combo-tls --endpoint=192.0.2.10 --exit-address=172.30.77.2 \
  --port=3443 --server-name=vpn.example.net --public-name=relay.example \
  --relay-port=10443 --clients=3
```

Адреса в примере заменить. Команда не меняет сеть, не запускает службы и не
перезаписывает существующий каталог. По умолчанию транспорт остаётся boring-tls;
combo требует явных `--transport=combo-tls` и `--public-name`.
Порты `1053` и `2222` для relay listener зарезервированы. `--exit-port` позволяет
отделить внутренний exit listener от внешнего `--port`; launcher принимает
`--publish=3443` и сам получает внутренний порт из конфигурации.

Создаются private CA в `authority/`, `exit/` и `client-N/`. Каждому клиенту
назначаются свой packet PSK и `10.99.0.N`; exit получает peer list. TLS-профиль
копируется в каждый client directory, CA/hostname verification сохраняются.
Для relay теперь генерируется **отдельный ключ каждого клиента**, а exit получает
relay peer list. По умолчанию общий предел — 128 сессий, на один ключ — 64.
Подробности конфигурации и replay — в [описании квот](clean-vpn-native-relay-quotas.md).

Раздавать только каталог нужной роли; `authority/` хранить offline. Не монтировать
весь bundle в client. Config/credentials — 0600, каталоги — 0700; на Linux
нужен владелец root. `--mode=standalone` записывает абсолютные пути в новом bundle.
Native `--check-config` на целевой Linux-системе обязателен.

Replay не создаётся автоматически: container config указывает `/replay/state`,
standalone — `exit/replay` внутри bundle. Для первого запуска exit явно создать
каталог 0700 и инициализировать replay через native engine; далее сохранять его.
Команды и LAN-контракт — в [combo runtime](clean-vpn-native-combo-runtime.md).

## Active HTTPS relay health

По умолчанию health остаётся packet DNS + локальный relay listener. Для проверки
реального HTTPS через relay оператор задаёт небольшой стабильный endpoint:
числовой public IPv4, TLS hostname, path и SHA-256 **байтов HTTP response body**.
Нет OS DNS lookup, HTTP redirect, отключения TLS verification или прямого fallback.
Response должен иметь status 200 и размер ≤16 KiB; deadline — 4 сек.

В приватном client-каталоге создать `relay-health.json`, например:

```json
{
  "version": 1,
  "ipv4": "11.22.33.44",
  "server_name": "health.example.net",
  "path": "/health",
  "ca": null,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Это только схема: IP/name/hash заменить данными **своего** endpoint; приведённый
hash не является ожидаемым ответом реального сервера. `ca:null` использует системные
корни image; для private CA скопировать PEM в клиентский комплект и указать
`"ca":"/config/health-ca.pem"`. Не использовать private key в качестве CA.
Поля файла проверяются до сетевых изменений; private/special/deny-list/exit IP
не допускаются. При запуске client добавить `--relay-health=relay-health.json`.
Это opt-in для combo container client; exit/boring такой параметр не принимают.

Runtime сохраняет параметры пробы в своём журнале и fingerprint. Проба bind'ится
на VPN-адрес клиента и через узкий OUTPUT REDIRECT попадает в native relay,
далее идёт через общий exit listener к HTTPS origin. Отдельное DROP-правило
запрещает соединение с этим source/target TCP/443 через packet/TUN или напрямую,
если REDIRECT отсутствует. Правило также затрагивает обычные локальные запросы
контейнера с тем же source к **этому конкретному endpoint**. LAN interception
проверяется отдельно — active health не доказывает правильность LAN PREROUTING.

Успешный вывод: `NATIVE_HEALTH=authenticated-packet-dns-and-relay-https`.
Недоступность origin, неверные CA/name/body или отказ relay делают health
неуспешным, даже если packet DNS работает. Общий container health запускает
пробы каждые 30 сек; это дополнительный реальный TLS/HTTP трафик с Node.js
ClientHello. Он не использует сохранённый браузерный профиль и не доказывает
мимикрию. Если такой трафик нежелателен, не включать опцию.
Это readiness, не команда автоматического перезапуска engine: недоступность
origin или исчерпание общих relay slots сами по себе не доказывают смерть процесса.

Обновлять через свежий container namespace: изменение health-конфига меняет
network fingerprint. Старые журналы/правила не переписываются в обход аудита.
Смену CA/body/endpoint нужно согласовывать с состоянием probe server.

## Три клиента и перегрузка

```bash
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
CVPN_RUNTIME_IMAGE=localhost/clean-vpn-native-runtime:provision-20261029 \
node scripts/clean-vpn-native-multi-client-lab.mjs /tmp/combo-multi.json
```

Только выделенный rootful Linux engine. Стенд создаёт три независимых client
namespace, три LAN и отдельные role config volumes; общий exit использует
реально сгенерированный peer list. Проверяются минутная нагрузка каждого
клиента, active health, сохранение PID и освобождение ресурсов.

В первоначальном прогоне (до исправления квот) отдельный клиент удерживал
16 relay-соединений, остальные продолжали packet
запросы и пытаются открыть relay. Стенд **измеряет** отказ/прогресс, а не выдаёт
общий лимит за справедливую квоту: в том engine relay cap был глобальный,
а relay PSK общий. После освобождения слотов все клиенты обязаны восстановиться
без перезапуска. Даже успешный обычный multi-client smoke не доказывает защиту
от вытеснения одним активным клиентом.

В фактическом прогоне каждый из трёх клиентов прошёл 116/116 обычных итераций.
При занятых слотах каждый из остальных сохранил 8/8 packet-наборов, но получил
0/8 успешных relay запросов. Fairness **не пройдена**; тест воспроизводит предел
архитектуры. После снятия нагрузки все клиенты восстановились, PID сохранены.

Проверки: 26/26 unit, 17/17 combo lifecycle + active health, 5/5 multi-client;
boring regression — 23/23 на предыдущем image до последней combo-only правки.
Независимый pcap подтвердил packet ClientHello и четыре relay JA3/JA4 совпадения.
Это не доказательство полного сходства с браузером.

[Отчёт](../fixtures/clean-vpn-native-combo-provisioning-20261029.json) содержит
image/engine/source hashes, замеры, известное ограничение fairness и границы проверок.
Это исторический отчёт до исправления. Текущий стенд требует успешного доступа
остальных клиентов при полной личной квоте первого; новый этап и результаты —
[relay quotas](clean-vpn-native-relay-quotas.md).

Standalone systemd installer также переносит `transparent.peers` с отдельным
ключом для каждого ID. Ключи сохраняются как приватные `relay-peer-N.psk`,
публикуемый config ссылается только на bundle, а replay инициализируется отдельно
в `replay/<id>/state`. То же поддерживается standalone transparent exit.
Повторная установка/инициализация существующего replay по-прежнему запрещена.
