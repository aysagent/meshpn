# Настройка NAT для Exit Node

Exit node требует настройки системного NAT для пересылки трафика от клиентов в интернет.

## Linux (iptables/nftables)

### Включение IP forwarding

```bash
# Временно (до перезагрузки)
sudo sysctl -w net.ipv4.ip_forward=1

# Постоянно (добавить в /etc/sysctl.conf)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
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
