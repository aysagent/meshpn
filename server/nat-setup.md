# Настройка NAT для Exit Node

Exit node требует настройки системного NAT для пересылки трафика от клиентов в интернет.

## Быстрая настройка (рекомендуется)

Используйте npm-скрипты для автоматической настройки NAT с сохранением исходных параметров:

```bash
# Включить NAT (автоматически сохранит бэкап настроек)
npm run nat:enable

# Включить NAT с указанием интерфейса
npm run nat:enable -- eth0

# Выключить NAT и восстановить исходные настройки
npm run nat:disable
```

Скрипты автоматически:
- Определяют ОС (Linux/macOS)
- Определяют сетевой интерфейс
- Сохраняют текущие настройки в `~/.mesh-vpn-backup/`
- Добавляют/удаляют только правила mesh-vpn
- Восстанавливают исходные значения при отключении

---

## Ручная настройка

Если нужна более тонкая настройка, используйте инструкции ниже.

## Сохранение исходных настроек (важно!)

Перед изменением системных настроек сохраните текущие значения для возможности отката.

### Linux

```bash
# Сохранить текущее состояние IP forwarding
cat /proc/sys/net/ipv4/ip_forward > ~/.mesh-vpn-backup-ip-forward

# Сохранить текущие правила iptables
sudo iptables-save > ~/.mesh-vpn-backup-iptables

# Сохранить sysctl.conf
sudo cp /etc/sysctl.conf ~/.mesh-vpn-backup-sysctl.conf
```

### macOS

```bash
# Сохранить текущее состояние IP forwarding
sysctl -n net.inet.ip.forwarding > ~/.mesh-vpn-backup-ip-forward

# Сохранить текущее состояние pf
sudo pfctl -s nat > ~/.mesh-vpn-backup-pf-nat 2>/dev/null || echo "# no rules" > ~/.mesh-vpn-backup-pf-nat
sudo pfctl -s rules > ~/.mesh-vpn-backup-pf-rules 2>/dev/null || echo "# no rules" > ~/.mesh-vpn-backup-pf-rules

# Запомнить был ли pf включен
sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled" && echo "enabled" > ~/.mesh-vpn-backup-pf-status || echo "disabled" > ~/.mesh-vpn-backup-pf-status

# Сохранить pf.conf
sudo cp /etc/pf.conf ~/.mesh-vpn-backup-pf.conf
```

## Linux (iptables/nftables)

### Включение IP forwarding

```bash
# Временно (до перезагрузки)
sudo sysctl -w net.ipv4.ip_forward=1

# Постоянно (добавить в /etc/sysctl.conf, если ещё нет)
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### iptables (MASQUERADE)

```bash
# Замените eth0 на ваш сетевой интерфейс с выходом в интернет
sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -o eth0 -j MASQUERADE

# Разрешить forward для VPN трафика
sudo iptables -A FORWARD -i tun+ -j ACCEPT
sudo iptables -A FORWARD -o tun+ -j ACCEPT

# Сохранить правила (Debian/Ubuntu)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### nftables (альтернатива iptables)

```bash
sudo nft add table nat
sudo nft add chain nat postrouting { type nat hook postrouting priority 100 \; }
sudo nft add rule nat postrouting ip saddr 10.200.0.0/16 oif eth0 masquerade
```

## macOS (pf)

### Включение IP forwarding

```bash
# Временно
sudo sysctl -w net.inet.ip.forwarding=1

# Постоянно (добавить в /etc/sysctl.conf)
echo "net.inet.ip.forwarding=1" | sudo tee -a /etc/sysctl.conf
```

### Настройка pf (Packet Filter)

Создайте файл `/etc/pf.anchors/mesh-vpn`:

```
# NAT для mesh VPN
nat on en0 from 10.200.0.0/16 to any -> (en0)
```

Добавьте в `/etc/pf.conf`:

```
# После строки "nat-anchor com.apple/*"
nat-anchor "mesh-vpn"
load anchor "mesh-vpn" from "/etc/pf.anchors/mesh-vpn"
```

Примените правила:

```bash
# Проверить синтаксис
sudo pfctl -n -f /etc/pf.conf

# Применить
sudo pfctl -f /etc/pf.conf

# Включить pf если выключен
sudo pfctl -e
```

### Быстрый вариант (без файлов)

```bash
# Включить IP forwarding
sudo sysctl -w net.inet.ip.forwarding=1

# Создать временное правило NAT
echo "nat on en0 from 10.200.0.0/16 to any -> (en0)" | sudo pfctl -ef -
```

## Проверка

После настройки NAT, проверьте работу:

```bash
# На клиенте
curl --interface utun5 http://ifconfig.me

# Должен вернуть публичный IP exit-ноды
```

## Откат изменений

Используйте бэкапы, созданные перед настройкой, для восстановления исходного состояния системы.

### Linux: восстановление из бэкапа

```bash
# Удалить только правила mesh-vpn (не трогая остальные)
sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/16 -o eth0 -j MASQUERADE 2>/dev/null
sudo iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null
sudo iptables -D FORWARD -o tun+ -j ACCEPT 2>/dev/null

# Восстановить исходное значение IP forwarding
if [ -f ~/.mesh-vpn-backup-ip-forward ]; then
  ORIGINAL_VALUE=$(cat ~/.mesh-vpn-backup-ip-forward)
  sudo sysctl -w net.ipv4.ip_forward=$ORIGINAL_VALUE
  echo "IP forwarding restored to: $ORIGINAL_VALUE"
fi

# Восстановить sysctl.conf (если меняли постоянные настройки)
if [ -f ~/.mesh-vpn-backup-sysctl.conf ]; then
  sudo cp ~/.mesh-vpn-backup-sysctl.conf /etc/sysctl.conf
  sudo sysctl -p
fi

# Или полное восстановление iptables из бэкапа (осторожно!)
# sudo iptables-restore < ~/.mesh-vpn-backup-iptables

# Если использовали iptables-persistent
sudo netfilter-persistent save
```

### Linux: удаление правил nftables

```bash
# Удалить только правило для mesh-vpn (если таблица nat существовала до этого)
sudo nft delete rule nat postrouting ip saddr 10.200.0.0/16 oif eth0 masquerade 2>/dev/null

# Или удалить таблицу nat целиком (только если создавали её для mesh-vpn)
# sudo nft delete table nat
```

### macOS: восстановление из бэкапа

```bash
# Восстановить исходное значение IP forwarding
if [ -f ~/.mesh-vpn-backup-ip-forward ]; then
  ORIGINAL_VALUE=$(cat ~/.mesh-vpn-backup-ip-forward)
  sudo sysctl -w net.inet.ip.forwarding=$ORIGINAL_VALUE
  echo "IP forwarding restored to: $ORIGINAL_VALUE"
fi

# Восстановить pf.conf
if [ -f ~/.mesh-vpn-backup-pf.conf ]; then
  sudo cp ~/.mesh-vpn-backup-pf.conf /etc/pf.conf
  sudo pfctl -f /etc/pf.conf
fi

# Удалить файл anchor если создавали
sudo rm -f /etc/pf.anchors/mesh-vpn

# Восстановить исходное состояние pf (включен/выключен)
if [ -f ~/.mesh-vpn-backup-pf-status ]; then
  if [ "$(cat ~/.mesh-vpn-backup-pf-status)" = "disabled" ]; then
    sudo pfctl -d 2>/dev/null
    echo "pf disabled (was disabled before)"
  else
    sudo pfctl -e 2>/dev/null
    echo "pf enabled (was enabled before)"
  fi
fi
```

### Быстрый откат (без бэкапов)

Если бэкапы не были созданы, удалите только добавленные правила:

```bash
# Linux
sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/16 -o eth0 -j MASQUERADE
sudo iptables -D FORWARD -i tun+ -j ACCEPT
sudo iptables -D FORWARD -o tun+ -j ACCEPT
# НЕ трогайте ip_forward если не уверены в исходном значении!

# macOS
sudo sed -i '' '/mesh-vpn/d' /etc/pf.conf
sudo rm -f /etc/pf.anchors/mesh-vpn
sudo pfctl -f /etc/pf.conf
# НЕ трогайте ip.forwarding если не уверены в исходном значении!
```

### Удаление файлов бэкапа

После успешного отката можно удалить бэкапы:

```bash
rm -f ~/.mesh-vpn-backup-*
```

### Проверка после отката

```bash
# Linux
sudo iptables -t nat -L -n | grep 10.200  # должно быть пусто
cat /proc/sys/net/ipv4/ip_forward  # проверить значение

# macOS
sudo pfctl -s nat 2>/dev/null | grep 10.200  # должно быть пусто
sysctl net.inet.ip.forwarding  # проверить значение
```

## Troubleshooting

### Linux: проверка правил iptables

```bash
sudo iptables -t nat -L -n -v
```

### macOS: проверка правил pf

```bash
sudo pfctl -s nat
sudo pfctl -s rules
```

### Проверка IP forwarding

```bash
# Linux
cat /proc/sys/net/ipv4/ip_forward

# macOS
sysctl net.inet.ip.forwarding
```

### tcpdump для отладки

```bash
# На exit node - смотреть трафик на TUN интерфейсе
sudo tcpdump -i utun5 -n

# Смотреть NAT трафик на внешнем интерфейсе
sudo tcpdump -i eth0 -n host ifconfig.me
```
