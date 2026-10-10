# Изолированный physical sandbox

Первый WAN/hardware прогон combo не должен заменять текущий VPN, default route,
DNS или firewall policy хоста. Проектируем отдельные network namespace для
client и exit с собственными veth/TUN и отдельным непривилегированным TCP-портом.

Это особенно важно для выбранной пары:

- client: Radxa;
- exit endpoint: `154.62.226.216`;
- primary `443` и rescue `2222` не используются sandbox-транспортом;
- первый предложенный trial port: `18443`;
- текущие `clean-vpn.service`, USB rescue и SSH должны продолжать работать.

Сервер `154.62.226.216` ранее дал признаки посторонней IPFS-установки. Read-only
инвентаризация допустима, но успешный benchmark или transport test на нём не
доказывает доверенность хоста. До rebuild либо принятого incident-verdict этот
факт остаётся отдельным блокером реальной активации.

## Read-only preflight

На Radxa:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-native-sandbox-preflight.mjs \
  --role=client --name=radxa \
  --endpoint=154.62.226.216 --port=18443 \
  --sandbox-cidr=10.203.0.0/30
```

На exit:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-native-sandbox-preflight.mjs \
  --role=exit --name=exit \
  --endpoint=154.62.226.216 --port=18443 \
  --sandbox-cidr=10.203.0.4/30
```

Скрипт не отправляет пакеты и не создаёт namespace/veth/TUN. Он не вызывает
`systemctl start/stop`, не меняет sysctl/firewall и не останавливает VPN.
Собираются только:

- существующие links, IPv4 routes и route к exit;
- занятость trial port на exit;
- конфликты будущих namespace/veth/transient units;
- текущий forwarding;
- backend/version и SHA-256 текущих iptables/ip6tables/nft firewall snapshots;
- наличие активного firewalld/ufw/nftables/netfilter-persistent и динамических
  владельцев вроде Docker/Podman/libvirt/fail2ban/kubelet;
- наличие `/dev/net/tun`, systemd PID 1 и необходимых утилит.

В отчёте нет process argv, environment, конфигураций, PSK/private keys,
journal или payload. `ready-for-sandbox-design-review` не разрешает применение;
`mutationAllowed` всегда `false`.

## Планируемая граница будущего runner

Runner ещё не реализован. Его обязательный контракт:

1. Existing VPN/SSH/USB units не останавливаются и не перезапускаются.
2. Все имена namespace/veth/chains/unit уникальны и проверяются до первой записи.
3. Правила только additive и scoped к sandbox veth, `/30` и `18443`; никаких
   flush, default-policy или широких ACCEPT/DROP.
4. Отдельный transient rollback unit создаётся раньше основной мутации, имеет
   bounded runtime и удаляет только ресурсы с совпавшими identity/fingerprint.
5. Исходный `ip_forward=1` никогда не сбрасывается; временно включённый `0→1`
   возвращается только после полного read-back cleanup.
6. После cleanup hashes/структура чужого firewall и состояние штатных services
   должны совпасть с baseline. Drift означает stop/manual review, не flush.
7. Provider firewall, host integrity и независимый доступ не выводятся из
   локального preflight и остаются явными operator gates.

До реализации и VM fault-tests этого контракта никаких `--apply` у sandbox нет.
