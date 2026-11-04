# Установка native clean-vpn

Все команды — root, из корня репозитория на **новых Linux-узлах**.
Exit: Debian/Ubuntu с systemd. Клиент: Radxa Zero 3W/Armbian,
`wlan0` для Wi-Fi и USB device controller для `usb0`.
Нужен Node.js 22+ (рекомендуется 24); `npm install` и Python не нужны.
Системный Wi-Fi должен быть подготовлен ОС (wpa_supplicant/networkd);
installer не заменяет сетевой менеджер и сохраняет существующие сети.

## Зависимости

На обеих машинах (Node.js должен быть уже установлен):

```bash
apt-get update
apt-get install -y build-essential cmake git patch pkg-config perl \
  openssl ca-certificates iproute2 iptables util-linux openssh-client
```

На exit дополнительно `apt-get install -y openssh-server`.
На клиенте с админкой:

```bash
apt-get install -y dnsmasq wpasupplicant conntrack avahi-daemon libavahi-client-dev
```

## Exit — одна команда

Подставить публичный IPv4 своего VPS:

```bash
bash install.sh --role=exit --endpoint=203.0.113.10
```

Installer сам собирает отсутствующий engine, создаёт CA/сертификат и отдельные
packet/relay-ключи, включает forwarding, устанавливает scoped firewall/NAT,
инициализирует replay state и включает systemd-автозапуск.
По умолчанию: **combo-tls, TCP 443**, `personal-cert.internal`,
`www.trustpilot.com`, Chromium 156, три клиента `.2/.3/.4` в `10.99.0.0/24`,
relay 128 всего / 64 на клиента. Браузерный профиль воспроизводится в пределах
[поддержанного набора параметров](clean-vpn-native-tls-profiles.md).

Если VPS за NAT: `--endpoint` — внешний IP, `--listen=10.0.0.2` — адрес его
интерфейса. При нескольких uplink можно явно добавить `--uplink=eth0`.
TCP 443 должен быть разрешён также в панели провайдера; installer управляет
только локальным firewall. Занятый порт и чужая установка не перезаписываются.

## Клиент — один файл и одна команда

На клиенте забрать **только его** bundle с нового exit:

```bash
scp root@203.0.113.10:/var/lib/clean-vpn/setup/exit/exports/client-1.bundle.json /root/client.bundle.json
bash install.sh --role=client --bundle=/root/client.bundle.json --admin-ui
```

В bundle уже находятся CA, профиль, packet/relay-ключи и ограниченный SSH-ключ
проверки времени. Серверные приватные TLS/CA-ключи туда не входят. Для второй
платы взять `client-2.bundle.json`, для третьей — `client-3.bundle.json`.
**Не устанавливать один клиентский bundle одновременно на несколько плат.**

Installer настраивает USB Ethernet/DHCP и порядок загрузки, guard, TUN,
маршруты, DNS и VPN. `--admin-ui` дополнительно устанавливает web/API,
`mpn.local`, captive portal и автозапуск админки. Без флага админка не ставится.
Вход по USB: **http://mpn.local/** или **http://192.168.7.1/**,
первый пароль **admin**; поменять в разделе «Устройство».
Существующий неизвестный USB gadget не заменяется автоматически.

Восстановление часов запускается только после определённой ошибки времени
TLS/авторизации, через закреплённый SSH-ключ exit, максимум раз за загрузку.
Нужен работающий SSH exit и синхронизированные часы exit. Отключение: `--no-clock`
на этапе установки; проверка TLS-сертификатов при этом остаётся включённой.

## Проверка и удаление

```bash
bash install.sh --check --role=exit    # на VPS: listening
bash install.sh --check --role=client  # на плате: ready после подключения Wi-Fi
bash uninstall.sh --role=client       # удалить службы клиента и его админки
bash uninstall.sh --role=exit         # удалить службы exit
```

Повтор той же install-команды сохраняет ключи и настройки. Uninstall убирает
собственные службы/правила и возвращает исходный forwarding. Ключи, настройки,
replay state и служебные учётные записи сохраняются для повторной установки;
чужие правила не очищаются. USB-адрес не сбрасывается посреди удаления, чтобы
не оборвать доступ; созданный gadget после удаления службы не включится при reboot.
После прерванной установки выполнить соответствующий `uninstall.sh`, затем
повторить install. Изменённые посторонним процессом файлы требуют разбирательства.

Опции: `--type=boring-tls`, `--port=443`, `--clients=1..32`, `--jobs=1..8`,
`--binary=/absolute/engine`, `--name=NAME`, `--plan`; полный список —
`bash install.sh --help`. Другая версия/конфигурация — отдельное обновление,
повторный install не подменяет действующий engine.
[Проверки для агента и порядок загрузки](clean-vpn-native-install-checklist.md).
Для проверки именно трафика USB-клиента с Mac есть
[один ограниченный smoke-скрипт](clean-vpn-usb-smoke.md); он не меняет сеть Mac.
