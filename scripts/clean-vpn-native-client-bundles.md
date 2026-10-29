# Несколько native-клиентов на одном exit

Один `clean-vpn-engine` принимает до **32 клиентов** с отдельными IPv4 и
32-байтными packet PSK. Это относится к native `boring-tls` и packet-части
native `combo-tls`. Старый `scripts/clean-vpn.js` не получает эту возможность.

`clean-vpn-native-clients.mjs` готовит приватные комплекты конфигураций и ключей
для новой установки. Он не меняет сеть, DNS или службы и не подключается к VPS.
Нативный multi-peer обработчик уже существовал; здесь добавлены генератор
согласованных конфигураций и проверка его результата реальными соединениями.

## Подготовка двух клиентов

Пример для Radxa и VPS 2 через `boring-tls`; все пути абсолютные, значения
endpoint/имени/интерфейсов нужно заменить на свои. `198.51.100.2` — пример,
не рабочий exit. Endpoint в этом профиле должен быть IPv4, доступным клиентам
и пригодным для bind на exit.

```json
{
  "version": 1,
  "transport": "boring-tls",
  "endpoint": "198.51.100.2",
  "port": 443,
  "server_name": "vpn.example.com",
  "cert": "/root/vpn-pki/cert.pem",
  "key": "/root/vpn-pki/key.pem",
  "ca": "/root/vpn-pki/ca.pem",
  "deploy_root": "/etc/clean-vpn-clients",
  "exit": { "uplink": "eth0", "link_unit": "links.service" },
  "clients": [
    {
      "name": "radxa", "ipv4": "10.99.0.2",
      "uplink": "wlan0", "link_unit": "links.service",
      "lan": { "interface": "usb0", "subnet": "192.168.7.0/24" }
    },
    {
      "name": "vps2", "ipv4": "10.99.0.3",
      "uplink": "eth0", "link_unit": "links.service", "lan": null
    }
  ]
}
```

`links.service` — пример имени **существующего внешнего владельца сети**,
соответствующего [site-контракту](clean-vpn-native-network.md). Генератор не
создаёт его и не превращает произвольную работающую сеть в dedicated site.
Выбор systemd-networkd вместо этого имени сам по себе контракт не выполняет.

Сохранить как `/root/clients.json`. Сертификат должен соответствовать
`server_name`, ключ — сертификату; CA должен доверять цепочке exit. Для файлов
использовать обычные пути без symlink, для private key — права `0600` и своего
владельца. Генератор проверяет leaf/key/hostname и формат CA; проверка цепочки
доверия происходит при TLS handshake.

```bash
node scripts/clean-vpn-native-clients.mjs \
  --manifest=/root/clients.json \
  --directory=/root/native-clients-bundle
```

Выходной каталог должен отсутствовать. Повторный запуск не перезаписывает ключи.
Результат (каталоги `0700`, файлы `0600`):

```text
native-clients-bundle/
  manifest.json
  exit/          config.json, site.json, cert.pem, key.pem, peers/*.psk
  clients/radxa/ config.json, site.json, ca.pem, packet.psk
  clients/vps2/  config.json, site.json, ca.pem, packet.psk
```

На каждую машину переносится **только содержимое её комплекта**, с сохранением
закрытых прав, в `/etc/clean-vpn-clients`. Клиентам не передаются private key
exit и packet PSK других клиентов. `manifest.json` не содержит секретов.
Пример проверки уже перенесённого комплекта на каждой машине:

```bash
native/clean_vpn/build/clean-vpn-engine \
  --check-config /etc/clean-vpn-clients/config.json
```

Далее — dry-run существующего установщика на новом выделенном site:

```bash
node scripts/clean-vpn-native-install.mjs \
  --name=multi \
  --binary=/absolute/clean-vpn-engine \
  --config=/etc/clean-vpn-clients/config.json \
  --site-profile=/etc/clean-vpn-clients/site.json
```

Без `--apply` эта команда проверяет конфигурацию и формирует план. Установка и
активация описаны в [native-install](clean-vpn-native-install.md). Не запускать
её как автоматическую миграцию существующего Radxa/VPS: текущие legacy guards,
DNS и USB rescue требуют отдельного согласования. Старый bounded direct trial
пока намеренно проверяет одну пару с адресом клиента `.2`; этот генератор его
ограничения не меняет.

## Combo и изоляция

Для `combo-tls` выбрать `"transport": "combo-tls"`, добавить
`"public_name": "relay.example.com"` и при необходимости `"deny_ipv4": []`.
Текущий combo site-профиль требует LAN у каждого клиента: HTTPS REDIRECT
применяется к входящему LAN-трафику. Пример VPS 2 с `lan: null` подходит для
`boring-tls`; генератор отвергнет его для combo. Имена server_name и public_name
имеют разные назначения: проверка сертификата exit и SNI разделения транспорта.

Combo-комплекты дополнительно содержат **общий relay.psk**. У каждого клиента
свой packet PSK, но независимого отзыва HTTPS relay-доступа пока нет: для него
нужна ротация группового ключа у всех клиентов. Replay-state общий на exit,
создаётся установщиком один раз при fresh install; генератор его не создаёт.
Удалять или заново инициализировать существующий replay-state нельзя.

Остальные свойства:

- Exit: `10.99.0.1/24`; клиенты: разные адреса `10.99.0.2…254/32`, максимум 32.
- Source IP привязан к аутентифицированному ключу; ответы идут только владельцу
  destination IP. Прямая пересылка между настроенными клиентами запрещена.
- Одна активная сессия на identity; повторный вход не вытесняет действующую.
- LAN-клиенты SNAT-ятся в адрес своего VPN-клиента. Одинаковые LAN-подсети на
  разных шлюзах допустимы; маршрутизация LAN-to-LAN этим не добавляется.
- Добавление/отзыв клиента пока выполняется через изменение конфигурации exit
  и перезапуск; hot reload, API пользователей и обновление существующей
  установки этим генератором не реализованы. Повторная генерация в новый каталог
  выпускает новые ключи **всех** клиентов, это не операция добавления одного.
- Лимит 32 — число настроенных packet identities, не гарантия пропускной
  способности. Relay очереди/лимиты остаются общими для всех клиентов.

## Проверка в лаборатории

```bash
# Только генератор и согласованность профилей
npm run test:native-clients

# Linux с собранными engine и fixtures
npm run test:native-clients-real

# macOS: кэшированная Linux-сборка, CTest и multi-client проверки
npm run lab:native:mac -- --multi-clients
```

Новый тест использует сгенерированные комплекты: 32 настоящих combo TLS/H2
соединения к одному exit, 256 адресованных пакетов в обе стороны, проверка
изоляции получателей и ограничений FD/RSS. Отдельный существующий multi-peer
тест проверяет подмену source IP, duplicate identity, stalled TLS и reconnect.
В этом быстром прогоне вместо TUN используется fixture FD; DNS выключен только
в runtime fixture, HTTPS relay payload не генерируется. Он не заменяет
реальную проверку двух клиентов с TUN/NAT/DNS на Radxa ↔ VPS.

Проверено 2026-10-25 в macOS/Podman Linux amd64: CTest 7/7, multi-client suite
6/6 без пропусков. Локальные проверки генератора, lab CLI, network profile и
service unit — 67/67. Физический multi-client прогон пока не выполнен.
