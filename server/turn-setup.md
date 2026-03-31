# TURN Relay Server Setup (coturn)

Данное руководство описывает настройку TURN relay сервера для mesh VPN.

## Зачем нужен TURN

TURN (Traversal Using Relays around NAT) — это протокол для обхода NAT, когда прямое P2P соединение невозможно. WebRTC использует TURN как fallback когда STUN не работает.

## Установка coturn

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install coturn
```

### CentOS/RHEL

```bash
sudo yum install epel-release
sudo yum install coturn
```

### Из исходников

```bash
git clone https://github.com/coturn/coturn.git
cd coturn
./configure
make
sudo make install
```

## Конфигурация

### Основной конфиг `/etc/turnserver.conf`

```ini
# Сетевые настройки
listening-port=3478
tls-listening-port=5349
alt-listening-port=3479
alt-tls-listening-port=5350

# Внешний IP (замените на реальный IP вашего VPS)
external-ip=YOUR_PUBLIC_IP

# Realm (замените на ваш домен)
realm=mesh-vpn.example.com

# Аутентификация
lt-cred-mech
user=meshuser:meshpassword

# Или используйте статический ключ
# static-auth-secret=YOUR_SECRET_KEY
# use-auth-secret

# Логирование
log-file=/var/log/turnserver/turnserver.log
verbose

# Безопасность
no-multicast-peers
no-cli
secure-stun

# Лимиты
total-quota=100
bps-capacity=0
stale-nonce=600

# Fingerprinting (для совместимости)
fingerprint

# TLS сертификаты (для production)
# cert=/etc/letsencrypt/live/turn.example.com/fullchain.pem
# pkey=/etc/letsencrypt/live/turn.example.com/privkey.pem
```

### VPS: публичный IP и приватный интерфейс (`external-ip`)

У многих провайдеров VPS **публичный** адрес (тот, по которому к вам ходят из интернета) **не совпадает** с адресом на `eth0`: на интерфейсе может быть только **приватная** подсеть (например `10.x`, `172.16–31`, `192.168.x`). Coturn в логах тогда пишет строки вроде `IPv4. Local relay addr: 10.x.x.x:...` — это **локальная привязка сокета**, а не обязательно то, что попадёт в ICE как relay.

1. Если публичный IP один и он **должен** использоваться для relay, обычно достаточно:
   - `external-ip=ВАШ_ПУБЛИЧНЫЙ_IP`
2. Если после этого в **клиенте** (лог mesh: `[WebRTC] ICE local … typ=relay`) по-прежнему виден **приватный** IPv4 на relay-кандидате, а второй peer **не** в этой LAN, задайте **явное сопоставление** «какой публичный адрес соответствует какому локальному»:
   - `external-ip=62.84.120.30/10.129.0.18`
   - формат: `ПУБЛИЧНЫЙ_IP/ЛОКАЛЬНЫЙ_IP_ИНТЕРФЕЙСА` (см. документацию coturn к вашей версии).

После правки: `sudo systemctl restart coturn` и проверьте, что подхватывается нужный файл (`grep -E '^external-ip|^#' /etc/turnserver.conf`, нет второго конфликтующего include).

В приложении mesh-vpn при стандартных настройках в лог печатаются строки **`[WebRTC] ICE local` / `ICE remote`** с `typ=relay` и адресом — по ним видно, совпадает ли relay с ожидаемым публичным IP.

### TLS с самоподписанным сертификатом (без домена)

Если у вас нет домена и вы хотите использовать TLS только с IP-адресом, можно создать самоподписанный сертификат.

#### 1. Генерация сертификата для IP-адреса

```bash
# Замените YOUR_PUBLIC_IP на реальный IP вашего сервера
export TURN_IP="YOUR_PUBLIC_IP"

# Создаем директорию для сертификатов
sudo mkdir -p /etc/coturn/certs
cd /etc/coturn/certs

# Генерируем приватный ключ и самоподписанный сертификат
sudo openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
  -keyout turn-key.pem -out turn-cert.pem \
  -subj "/CN=TURN Server/O=MeshVPN" \
  -addext "subjectAltName=IP:${TURN_IP}" \
  -nodes

# Устанавливаем права доступа
sudo chmod 600 turn-key.pem
sudo chmod 644 turn-cert.pem
sudo chown turnserver:turnserver turn-*.pem
```

#### 2. Настройка coturn с self-signed сертификатом

Добавьте в `/etc/turnserver.conf`:

```ini
# TLS с самоподписанным сертификатом
cert=/etc/coturn/certs/turn-cert.pem
pkey=/etc/coturn/certs/turn-key.pem

# Отключаем устаревшие версии TLS
no-tlsv1
no-tlsv1_1

# Разрешаем TLS без проверки сертификата (для self-signed)
no-tls-cert-verify
```

#### 3. Использование в клиентах

**Важно:** Браузеры и WebRTC клиенты по умолчанию отклоняют самоподписанные сертификаты для `turns://` соединений.

**Варианты решения:**

**Вариант A: Использовать `turn:` без TLS (для тестирования/внутренних сетей)**

```json
{
  "turnServers": [
    {
      "urls": "turn:YOUR_IP:3478",
      "username": "meshuser",
      "credential": "meshpassword"
    }
  ]
}
```

**Вариант B: Добавить CA в доверенные (для Node.js приложений)**

```bash
# Экспортируем переменную окружения
export NODE_EXTRA_CA_CERTS=/etc/coturn/certs/turn-cert.pem

# Или в коде Node.js
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';  # Только для тестирования!
```

**Вариант C: Скопировать сертификат на клиентские машины**

```bash
# На сервере: скопировать сертификат
scp /etc/coturn/certs/turn-cert.pem user@client:/tmp/

# На клиенте (Linux): добавить в системные CA
sudo cp /tmp/turn-cert.pem /usr/local/share/ca-certificates/turn-server.crt
sudo update-ca-certificates

# На клиенте (macOS): добавить в Keychain
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/turn-cert.pem
```

#### 4. Проверка TLS соединения

```bash
# Проверка сертификата
openssl s_client -connect YOUR_IP:5349 -showcerts

# Должен показать ваш самоподписанный сертификат
```

### Включение автозапуска

#### Ubuntu/Debian

```bash
# Редактируем /etc/default/coturn
sudo sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn

# Запускаем
sudo systemctl enable coturn
sudo systemctl start coturn
```

#### CentOS/RHEL

```bash
sudo systemctl enable coturn
sudo systemctl start coturn
```

## Firewall

### UFW (Ubuntu)

```bash
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
sudo ufw allow 5349/udp
sudo ufw allow 49152:65535/udp
```

### firewalld (CentOS)

```bash
sudo firewall-cmd --permanent --add-port=3478/tcp
sudo firewall-cmd --permanent --add-port=3478/udp
sudo firewall-cmd --permanent --add-port=5349/tcp
sudo firewall-cmd --permanent --add-port=5349/udp
sudo firewall-cmd --permanent --add-port=49152-65535/udp
sudo firewall-cmd --reload
```

### iptables

```bash
iptables -A INPUT -p tcp --dport 3478 -j ACCEPT
iptables -A INPUT -p udp --dport 3478 -j ACCEPT
iptables -A INPUT -p tcp --dport 5349 -j ACCEPT
iptables -A INPUT -p udp --dport 5349 -j ACCEPT
iptables -A INPUT -p udp --dport 49152:65535 -j ACCEPT
```

## Проверка работы

### Проверка статуса

```bash
sudo systemctl status coturn
```

### Проверка портов

```bash
netstat -tulpn | grep turnserver
```

### Тестирование TURN

Используйте [Trickle ICE](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/) для тестирования:

1. Добавьте TURN сервер:
   - URL: `turn:YOUR_IP:3478`
   - Username: `meshuser`
   - Credential: `meshpassword`
   
2. Нажмите "Gather candidates"
3. Должны появиться `relay` кандидаты

## Настройка в mesh VPN

### config/default.json

```json
{
  "turnServers": [
    {
      "urls": "turn:YOUR_TURN_SERVER:3478",
      "username": "meshuser",
      "credential": "meshpassword"
    },
    {
      "urls": "turns:YOUR_TURN_SERVER:5349",
      "username": "meshuser",
      "credential": "meshpassword"
    }
  ]
}
```

## Несколько TURN серверов

Для отказоустойчивости рекомендуется использовать несколько TURN серверов в разных регионах:

```json
{
  "turnServers": [
    {
      "urls": "turn:turn1.example.com:3478",
      "username": "user",
      "credential": "pass"
    },
    {
      "urls": "turn:turn2.example.com:3478",
      "username": "user",
      "credential": "pass"
    }
  ]
}
```

## Мониторинг

### Логи

```bash
tail -f /var/log/turnserver/turnserver.log
```

### Метрики

coturn предоставляет REST API для мониторинга:

```bash
curl http://localhost:8080/
```

## Безопасность

1. **Используйте TLS** — всегда настраивайте сертификаты для production
2. **Ротируйте credentials** — регулярно меняйте пароли
3. **Ограничьте доступ** — используйте whitelist IP если возможно
4. **Мониторьте** — следите за аномальным трафиком

## Troubleshooting

### TURN не работает

1. Проверьте firewall (UDP к порту coturn, обычно 3478, и диапазон relay-портов если задан `min-port`/`max-port`).
2. Убедитесь, что `external-ip` соответствует **публичному** адресу, с которого клиенты достигают сервера; при NAT/VPS с приватным интерфейсом см. раздел **«VPS: публичный IP и приватный интерфейс»** выше и форму `ПУБЛИЧНЫЙ/ПРИВАТНЫЙ`.
3. Проверьте логи: `/var/log/turnserver/turnserver.log`
4. Сравните с логами приложения: для relay-кандидата адрес в `[WebRTC] ICE local … typ=relay` должен быть **достижим** для удалённого peer (часто это ваш публичный IP, а не только `10.x` с другой стороны сети).

### WebRTC Peers: 0 при работающем сигналинге

1. Убедитесь, что TURN в конфиге клиента совпадает с coturn (realm/user/password/порт).
2. По логам mesh проверьте `typ=relay` и IP: при приватном relay для внешнего peer настройте `external-ip` как выше.
3. Исключите блокировку UDP relay на хосте/облачном security group.

### Высокая нагрузка

1. Увеличьте лимиты в конфиге
2. Добавьте больше TURN серверов
3. Оптимизируйте сеть (MTU, буферы)

### Проблемы с TLS

1. Проверьте пути к сертификатам
2. Убедитесь что сертификаты не истекли
3. Проверьте права доступа к файлам
