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
- на client — только allowlist-форма argv работающего legacy service: role/type,
  совпадение endpoint, port, split-default, IPv6/DNS flags; неизвестные параметры
  считаются, но их имена/значения не выводятся;
- состояния `clean-vpn.service`, kill switch и USB rescue, а также только
  clean-vpn-owned firewall rules/marker;
- наличие `/dev/net/tun`, systemd PID 1 и необходимых утилит.

В отчёте нет raw process argv, environment, конфигураций, PSK/private keys,
journal или payload. `ready-for-sandbox-design-review` не разрешает применение;
`mutationAllowed` всегда `false`.

Для Radxa ожидаемый неизменяемый baseline — активный `--type=tls`, endpoint
`154.62.226.216:443`, `--split-default`, профиль kill switch
`cvks4:both:block:tun0:154.62.226.216:22` и активный USB rescue socket. Sandbox
не является заменой этого baseline. Он должен работать параллельно и после
cleanup оставить те же PID/units/routes/firewall ownership.

Отсутствующий standalone `nft` CLI при `iptables ... (nf_tables)` теперь
фиксируется предупреждением: обязательны рабочие `iptables-save/restore`, а
`nft`-snapshot собирается только когда CLI уже установлен. Устанавливать пакет
ради read-only preflight не требуется. Широкие existing routes `/0`, `/1` или
policy bypass `/8` не считаются конфликтом с будущим более специфичным connected
`/30`; конфликтом остаются link/kernel и specific routes.

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

Отдельная важная граница Radxa: внешний TCP из client namespace станет
forwarded-трафиком через host veth, а текущий `CLEANVPN_KS_FWD` по замыслу
закрывает неизвестный public egress. Простое добавление ACCEPT после cvks4 не
сработает, а вставка произвольного правила перед первым hook будет отвергнута
аудитом kill switch. Поэтому runner не должен «обходить» защиту. Нужен отдельный
точно ограниченный sandbox-prefix contract, распознаваемый существующим audit,
с endpoint `154.62.226.216`, port `18443`, source `/30` и конкретным veth;
он устанавливается до подъёма veth и удаляется по identity/read-back. Этот
контракт сначала проверяется model/VM fault-tests вместе с crash cleanup.

До реализации и VM fault-tests этого контракта никаких `--apply` у sandbox нет.
