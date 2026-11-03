# Новая native combo-пара с параметрами действующей Radxa/VPS

Сверено 2026-11-03 с работающими конфигурациями обеих машин. Это установка
**новой пары**, а не обновление существующего instance. Новые IP endpoint,
CA, сертификат и ключи обязательны; секреты действующей пары не копируются.

| Параметр | Значение |
| --- | --- |
| Транспорт / внешний порт | combo-tls / TCP 443 |
| Проверяемая TLS identity | personal-cert.internal |
| Packet SNI / transparent public_name | www.trustpilot.com |
| Браузерный профиль | chromium-156-bounded-cold-v1 |
| IP клиентов | 10.99.0.2, 10.99.0.3, 10.99.0.4 |
| TUN exit / client | cvexit0 / tun0, MTU 1400 |
| Локальный relay клиента | 0.0.0.0:10443; доступ ограничивает network owner |
| Transparent limits | 128 всего / 64 на identity |
| Политика transparent | public-https, пустой deny_ipv4 |
| Сеть платы | wlan0 uplink; usb0 192.168.7.1/24 |
| Guard | cvks4, both/block, USB DNS + strict USB |

HTTPS TCP/443 от USB идёт через transparent; остальной IPv4, включая QUIC и
собственный HTTPS платы, — через boring packet. Native DNS включён; IPv6
прямо наружу блокируется. Private .mpn DNS и address discovery здесь не включены.
ALPS на exit оставлен выключенным, как в действующем config.

## Граница этой инструкции

Exit подходит для Ubuntu/Debian с systemd. Client-команды ниже — для **уже
подготовленной Radxa Zero 3W/Armbian с тем же USB gadget, DHCP и wlan0**.
Installer VPN не создаёт USB gadget/DHCP/Wi-Fi и USB-админку с нуля. Для другой
платы или чистого образа сначала нужна подготовка этих компонентов. Не обходить
USB preflight через staging root: он намеренно отклоняет неизвестный gadget.

Админка, её пароль, сохранённые Wi-Fi сети, mDNS и networkd boot gate не
клонируются этими командами. VPN/ключи/условное восстановление часов описаны ниже;
это не полный образ ОС нашей Radxa. Все команды выполняются **на новых узлах**,
root в Bash, последовательно; после ошибки не переходить к следующему шагу.

## 1. Код и сборка — на каждом новом Linux-узле

Нужен установленный Node.js 24 и доступ к приватному репозиторию. Стабильный
абсолютный путь Node будет записан в systemd unit; затем эту версию не удалять.

```bash
set -e
apt-get update
apt-get install -y build-essential cmake git patch pkg-config perl python3 \
  openssl ca-certificates iproute2 iptables util-linux openssh-client dnsutils curl
node --version

mkdir -p /root/dev
git clone --branch feat/clean-vpn-native-data-plane \
  git@github.com:aysagent/meshpn.git /root/dev/meshpn
cd /root/dev/meshpn
git rev-parse HEAD
bash scripts/build-clean-vpn-native.sh --low-memory --jobs=1
```

Это свежий clone; если checkout уже есть, проверить его изменения и выполнить
`git pull --ff-only` на указанной ветке вместо clone. Оба узла должны получить
одинаковую ревизию, не старый main. Нужны все 14 CTest без ошибок.
На VPS с 1 GiB RAM можно перед сборкой выполнить
`bash scripts/clean-vpn-native-swap.sh on`, после — `off` при достаточной RAM.
На более мощной плате допустим `--jobs=2`, если хватает памяти.

## 2. Все TLS/PSK credentials — один раз на НОВОМ VPS

Заменить значения ниже. `CVPN_BIND_IP` — адрес интерфейса VPS, который виден в
`ip -4 address`: за NAT он отличается от публичного `CVPN_EXIT_IP`.
Не указывать здесь IP нашей действующей пары.

```bash
cd /root/dev/meshpn
export CVPN_EXIT_IP='PUBLIC_IPV4_NEW_VPS'
export CVPN_BIND_IP='LOCAL_IPV4_NEW_VPS'
export CVPN_UPLINK='eth0'
umask 077

node scripts/clean-vpn-native-runtime-config.mjs create \
  --directory=/root/clean-vpn-new \
  --mode=standalone \
  --endpoint="$CVPN_EXIT_IP" --exit-address="$CVPN_BIND_IP" \
  --port=443 --exit-port=443 \
  --server-name=personal-cert.internal \
  --transport=combo-tls --public-name=www.trustpilot.com \
  --relay-port=10443 --relay-sessions=128 --relay-per-client=64 \
  --clients=3 --days=365 \
  --profile="$PWD/fixtures/native-tls-profiles/chromium-156-bounded-cold.json"

python3 - <<'PY'
import json, os
from pathlib import Path
base = Path('/root/clean-vpn-new')
for role in ['exit', 'client-1', 'client-2', 'client-3']:
    p = base / role / 'engine.json'
    c = json.loads(p.read_text())
    c['boring']['tun'] = 'cvexit0' if role == 'exit' else 'tun0'
    if role == 'exit':
        c['boring'].pop('alps', None)
        for i, peer in enumerate(c['transparent']['peers'], 2):
            peer['id'] = f'peer-10-99-0-{i}'
    p.write_text(json.dumps(c, indent=2) + '\n')
def write_new(name, obj):
    with (base / name).open('x') as f:
        json.dump(obj, f, indent=2)
        f.write('\n')
write_new('exit/host.json', {'version': 1, 'uplink': os.environ['CVPN_UPLINK']})
for i in range(1, 4):
    write_new(f'client-{i}/host.json', {
        'version': 1, 'guard_unit': 'clean-vpn-killswitch.service',
        'guard_script': '/usr/local/bin/clean-vpn-killswitch.sh'})
PY

openssl verify -purpose sslserver -verify_hostname personal-cert.internal \
  -CAfile /root/clean-vpn-new/authority/ca.pem \
  /root/clean-vpn-new/exit/cert.pem
native/clean_vpn/build/clean-vpn-engine --check-config /root/clean-vpn-new/exit/engine.json
native/clean_vpn/build/clean-vpn-engine --check-config /root/clean-vpn-new/client-1/engine.json
```

Генератор откажет, если `/root/clean-vpn-new` уже существует. Не удалять этот
каталог ради повторного запуска: это уже выпущенные credentials. `engine.json`
содержит абсолютные пути, поэтому при переносе сохранять путь каталога.

| Файл | Куда нужен |
| --- | --- |
| authority/ca.key | Приватный CA; резервная копия отдельно, клиенту не передавать |
| exit/cert.pem + exit/key.pem | Сертификат и приватный TLS-ключ только exit |
| exit/peer-N.psk ↔ client-N/psk | Одинаковый packet PSK соответствующего клиента |
| exit/relay-N.psk ↔ client-N/relay.psk | Другой, отдельный transparent PSK того же клиента |
| client-N/ca.pem | Публичный CA для проверки exit, не приватный ключ |
| client-N/profile.json | Браузерный TLS-профиль, уже включён в комплект |

PSK — **32 сырых байта**, не hex-текст. JSON использует `secret_path`, поэтому
конвертировать ничего не нужно. Имена peer-файлов после installer могут измениться,
но config переписывается вместе с ними. Если отдельно нужен hex для ручного
ввода: `od -An -v -tx1 /root/clean-vpn-new/client-1/psk | tr -d ' \n'; echo`.
Это вывод секрета; не отправлять его в диагностику или git.

`personal-cert.internal` не требует записи в публичном DNS: подключение по IP,
имя проверяется по SAN и нашей CA. CA не надо устанавливать в браузер/телефон
или глобальное хранилище ОС. `www.trustpilot.com` — отдельный параметр SNI;
сертификат этого сайта мы не выпускаем и его ключами не владеем.

## 3. Exit: публикация и запуск

Нужен свободный TCP/443 и разрешение этого входа в firewall VPS/провайдера.
Не менять SSH и не выполнять firewall flush. При занятом 443 сначала выбрать,
какой сервис должен владеть этим адресом/портом.

```bash
ss -lntp '( sport = :443 )'
ip -4 address
ip -4 route
sysctl -n net.ipv4.ip_forward
```

На новом VPS, где forwarding ещё выключен, явно включить его для роли шлюза:

```bash
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-clean-vpn-forward.conf
sysctl -p /etc/sysctl.d/90-clean-vpn-forward.conf
```

Подсеть `10.99.0.0/24` должна быть свободна. После успешного dry-run повторить
с `--apply`:

```bash
cd /root/dev/meshpn
node scripts/clean-vpn-native-install.mjs \
  --name=combo-daily-exit --binary="$PWD/native/clean_vpn/build/clean-vpn-engine" \
  --config=/root/clean-vpn-new/exit/engine.json \
  --exit-profile=/root/clean-vpn-new/exit/host.json

node scripts/clean-vpn-native-install.mjs \
  --name=combo-daily-exit --binary="$PWD/native/clean_vpn/build/clean-vpn-engine" \
  --config=/root/clean-vpn-new/exit/engine.json \
  --exit-profile=/root/clean-vpn-new/exit/host.json --apply

systemctl daemon-reload
node /opt/clean-vpn-native/combo-daily-exit/control/clean-vpn-native-exit-host.mjs \
  preflight --config=/opt/clean-vpn-native/combo-daily-exit/network.json
systemctl enable --now native-combo-daily-exit-network.service
systemctl show native-combo-daily-exit-network.service native-combo-daily-exit.service \
  -p Id -p ActiveState -p StatusText -p Result
```

Installer сам копирует нужные материалы в `/opt/clean-vpn-native/combo-daily-exit/`,
переписывает пути и **один раз** создаёт replay state. Не запускать вручную
`--init-transparent-replay` перед installer и не удалять replay при рестарте.
Client-комплекты и CA private key в installed exit bundle не попадают.

## 3a. Ключ восстановления часов — на НОВОМ VPS

Этот шаг воспроизводит clock recovery действующей Radxa. Выполнить **до
копирования client-1**. Для Ubuntu/Debian с OpenSSH и `UsePAM yes`; существующий
`cvpn-clock` не перезаписывать. Серверные часы должны быть синхронизированы.
Создаётся account без пароля с единственным ключом только для запроса времени.
Глобальные параметры sshd и root-доступ не меняются.

```bash
set -e
cd /root/dev/meshpn
test "$(timedatectl show -p NTPSynchronized --value)" = yes
/usr/sbin/sshd -T | grep -qx 'usepam yes'
/usr/sbin/sshd -T | grep -qx 'hostkey /etc/ssh/ssh_host_ed25519_key'
test -f /etc/ssh/ssh_host_ed25519_key.pub
if getent passwd cvpn-clock >/dev/null; then
  echo 'cvpn-clock уже существует: сначала проверить его конфигурацию' >&2
  exit 1
fi
test ! -e /var/lib/clean-vpn-clock
test ! -e /opt/clean-vpn-clock
test ! -e /root/clean-vpn-new/client-1/clock-identity

ssh-keygen -q -t ed25519 -N '' -C cvpn-clock-client-1 \
  -f /root/clean-vpn-new/client-1/clock-identity
useradd --system --user-group --home-dir /var/lib/clean-vpn-clock \
  --shell /bin/sh cvpn-clock
install -d -o root -g root -m 0755 /opt/clean-vpn-clock \
  /var/lib/clean-vpn-clock /var/lib/clean-vpn-clock/.ssh
install -o root -g root -m 0644 scripts/clean-vpn-native-clock.py \
  /opt/clean-vpn-clock/clean-vpn-native-clock.py
python3 - <<'PY'
import json
from pathlib import Path
base = Path('/root/clean-vpn-new/client-1')
pub = (base / 'clock-identity.pub').read_text().strip()
forced = 'restrict,command="/usr/bin/timeout 5s /usr/bin/python3 -I /opt/clean-vpn-clock/clean-vpn-native-clock.py serve" '
authorized = Path('/var/lib/clean-vpn-clock/.ssh/authorized_keys')
with authorized.open('x') as f:
    f.write(forced + pub + '\n')
authorized.chmod(0o644)
host = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
assert host[0] == 'ssh-ed25519'
with (base / 'clock-known-hosts').open('x') as f:
    f.write('clean-vpn-clock ' + ' '.join(host[:2]) + '\n')
endpoint = json.loads((base / 'engine.json').read_text())['boring']['address']
with (base / 'clock.json').open('x') as f:
    json.dump({'version': 1, 'host': endpoint, 'port': 22, 'user': 'cvpn-clock',
               'identity': str(base / 'clock-identity'),
               'known_hosts': str(base / 'clock-known-hosts')}, f, indent=2)
for name in ['clock-identity', 'clock-known-hosts', 'clock.json']:
    (base / name).chmod(0o600)
PY
```

Не ставить `/usr/sbin/nologin` этому account: он может заблокировать forced
command. Домашний каталог/authorized_keys/helper принадлежат root, account не
может расширить свои права. Если sshd использует другой AuthorizedKeysFile,
AllowUsers/DenyUsers или Match-политику, сначала согласовать account с ней;
probe на плате должна пройти до установки VPN.
Для client-2/3 выпускать свои SSH identities и добавлять публичные ключи с теми
же ограничениями; ключ клиента 1 всем платам не раздавать.

## 4. Передать только комплект нужного клиента

На ноутбуке с SSH-доступом к обоим новым узлам. `scp -3` передаёт файлы через
ноутбук, VPS не обязан видеть USB-адрес платы. Ни маршруты, ни Wi-Fi ноутбука
эти команды не меняют. Проверить SSH host keys обычным доверенным способом.

```bash
CVPN_NEW_VPS='PUBLIC_IPV4_NEW_VPS'
CVPN_NEW_BOARD='192.168.7.1'
ssh root@"$CVPN_NEW_BOARD" 'test ! -e /root/clean-vpn-new && mkdir -m 700 /root/clean-vpn-new'
scp -3 -pr root@"$CVPN_NEW_VPS":/root/clean-vpn-new/client-1 \
  root@"$CVPN_NEW_BOARD":/root/clean-vpn-new/
```

Первой плате — только `client-1` (`10.99.0.2`); следующей — `client-2` (`.3`),
третьей — `client-3` (`.4`). Не копировать один комплект на одновременно
работающие клиенты. Не копировать всю `/root/clean-vpn-new` на каждую плату.

## 5. Client на подготовленной плате

Сначала read-only проверки. На чистом Armbian этот шаг ещё не пройдёт:
нужны USB gadget/DHCP/rescue и подключение wlan0.

```bash
cd /root/dev/meshpn
node scripts/clean-vpn-native-usb-preflight.mjs
ip -4 address show usb0
ip -4 route show default
sysctl -n net.ipv4.ip_forward
date -u
```

Ожидается `status=passed`, `usb0=192.168.7.1/24`, default через `wlan0`,
forwarding=1, правильная дата. Исправление порядка DHCP известной Radxa описано
в [clean-vpn-usb-boot-ready.md](clean-vpn-usb-boot-ready.md); оно не создаёт gadget.

Нужен отдельный `clean-vpn-killswitch.service`, как в действующей установке.
Если его ещё нет, на подготовленной плате установить следующий guard. Сначала
собрать бинарник, скопировать credentials и настроить Wi-Fi: после включения
guard прямой интернет платы будет закрыт до запуска VPN. USB SSH остаётся.
Не перезаписывать существующий guard или другой service этим примером.

```bash
export CVPN_EXIT_IP='PUBLIC_IPV4_NEW_VPS'
cd /root/dev/meshpn
test ! -e /etc/systemd/system/clean-vpn-killswitch.service
test ! -e /usr/local/bin/clean-vpn-killswitch.sh
install -m 0755 scripts/autostart/killswitch.sh /usr/local/bin/clean-vpn-killswitch.sh
/usr/local/bin/clean-vpn-killswitch.sh plan --scope=both --ipv6=block \
  --tun=tun0 --ssh-port=22 --server="$CVPN_EXIT_IP" --usb-dns=1 --usb-strict=1
cat > /etc/systemd/system/clean-vpn-killswitch.service <<EOF
[Unit]
Description=clean-vpn persistent guard
DefaultDependencies=no
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --ssh-port=22 --server=$CVPN_EXIT_IP --usb-dns=1 --usb-strict=1
ExecStop=/bin/true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/clean-vpn-killswitch.service
systemctl daemon-reload
systemctl enable --now clean-vpn-killswitch.service
/usr/local/bin/clean-vpn-killswitch.sh status
```

`ExecStop=/bin/true` сохраняет защиту при остановке guard unit. Это самостоятельный
guard, не установка старого Node VPN. Полный ранний boot gate networkd нашей
платы — отдельная конфигурация ОС, этим минимальным unit не воспроизводится.

Установка клиента (для второй платы заменить в командах `client-1` на `client-2`):

```bash
cd /root/dev/meshpn
node scripts/clean-vpn-native-install.mjs \
  --name=combo-daily --binary="$PWD/native/clean_vpn/build/clean-vpn-engine" \
  --config=/root/clean-vpn-new/client-1/engine.json \
  --host-profile=/root/clean-vpn-new/client-1/host.json \
  --clock-profile=/root/clean-vpn-new/client-1/clock.json

node scripts/clean-vpn-native-install.mjs \
  --name=combo-daily --binary="$PWD/native/clean_vpn/build/clean-vpn-engine" \
  --config=/root/clean-vpn-new/client-1/engine.json \
  --host-profile=/root/clean-vpn-new/client-1/host.json \
  --clock-profile=/root/clean-vpn-new/client-1/clock.json --apply

systemctl daemon-reload
python3 /opt/clean-vpn-native/combo-daily/clock.py probe \
  --config=/opt/clean-vpn-native/combo-daily/clock.json
node /opt/clean-vpn-native/combo-daily/control/clean-vpn-native-host-network.mjs \
  preflight --config=/opt/clean-vpn-native/combo-daily/network.json
systemctl enable --now native-combo-daily-network.service
systemctl show native-combo-daily-network.service native-combo-daily.service \
  -p Id -p ActiveState -p StatusText -p Result
```

Клиентские CA/PSK/profile будут скопированы в `/opt/clean-vpn-native/combo-daily/`.
Engine unit не включать отдельно: запускается именно network owner.
Успешная публикация installer сама по себе не запускает VPN.

## 6. Часы и админка

Шаг 3a создаёт **SSH** identity и pin, отличные от TLS cert/PSK. Installer шага 5
копирует их и подключает условный clock recovery. `probe` только запрашивает время,
не меняет часы. При ошибке остановиться и проверить account/pin/синхронизацию VPS.
Автоматика запрашивает время после конкретной ошибки времени TLS/HMAC, а не при
каждом включении. Одна попытка на boot, предельный RTT 5 секунд; недоступный или
медленный SSH не обходит TLS-проверку. Детали — [clock recovery](clean-vpn-native-clock.md).

Если осознанно использовать только исправный RTC/системную синхронизацию,
можно пропустить 3a и убрать `--clock-profile` и `clock.py probe` в шаге 5.
Тогда это уже отличие от действующей платы. Не копировать root SSH-ключ ноутбука
и не использовать слепой `ssh-keyscan` как доказательство подлинности VPS.

USB-админка также устанавливается отдельно и должна указывать на
`native-combo-daily-network.service` и `/opt/clean-vpn-native/combo-daily/config.json`.
Генератор не переносит пароль админки и Wi-Fi credentials. Для полностью чистой
платы остаются OS/admin шаги; не считать данную инструкцию универсальным
готовым образом Radxa.

## 7. Проверка после запуска

На плате:

```bash
journalctl -u native-combo-daily.service -u native-combo-daily-network.service \
  -n 100 --no-pager
dig @10.99.0.2 -p 1053 example.org A +time=3 +tries=1
dig @10.99.0.2 -p 1053 example.org AAAA +tcp +time=3 +tries=1
curl --connect-timeout 10 --max-time 20 -I https://example.org
```

Для клиента `.3`/`.4` использовать его DNS address вместо `.2`.
Проверка самой платы испытывает packet-ветку. Отдельно подключить телефон по USB:
проверить выдачу `192.168.7.x`, открыть HTTPS и проверить download **и upload**.
Затем проверить reboot и холодную загрузку с повторной выдачей DHCP. `active`
без `ready` и один успешный curl не доказывают работу USB/transparent/DNS целиком.

Секреты в вывод диагностики не включать. Резервные копии provisioning bundle
и installed state хранить приватно; не коммитить в git. Выходные bundle-каталоги
созданы с 0700, ключи/config — 0600.

## Проверка инструкции

2026-11-03: синтаксис всех Bash-блоков и встроенного Python проверен. В отдельном
Linux-контейнере без сети прошли выпуск CA/leaf, native config validation, проверка
шести независимых PSK и совпадения пар, staging install exit/client с clock-profile
и создание replay. SSH identities для staging выпущены локальным ssh-keygen;
создание account/sshd-policy на новом VPS и живой запуск новой пары этим не проверены.

На действующей Radxa read-only USB preflight прошёл все проверки; engine был
`ready`. Активный браузерный профиль совпал с repository fixture по SHA-256:
`e2cf0e9e2fb68ce5a2af43d56c0be989cd525217ac73e6037ad65098d5e0be79`.
Существующие службы, ключи и настройки обеих машин не менялись.
