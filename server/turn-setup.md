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

1. Проверьте firewall
2. Убедитесь что external-ip правильный
3. Проверьте логи: `/var/log/turnserver/turnserver.log`

### Высокая нагрузка

1. Увеличьте лимиты в конфиге
2. Добавьте больше TURN серверов
3. Оптимизируйте сеть (MTU, буферы)

### Проблемы с TLS

1. Проверьте пути к сертификатам
2. Убедитесь что сертификаты не истекли
3. Проверьте права доступа к файлам
