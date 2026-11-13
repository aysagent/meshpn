# Tailscale вместе с native clean-vpn

Host profile / установленный `network.json` поддерживает явный `"tailscale": true`.
По умолчанию сохраняется прежний отказ любых сторонних IPv4 policy rules.
Нужны обновлённые network owner и `scripts/autostart/killswitch.sh`.

Поддерживается Tailscale как участник tailnet для доступа к самой плате.
Интернет и публичный внешний транспорт Tailscale идут через clean-vpn (прямой
обмен с LAN peers сохраняет существующие LAN-исключения guard), поэтому удалённый
доступ Tailscale не является независимым rescue при отказе clean-vpn.
USB rescue остаётся независимым. Tailscale exit node, subnet routing,
advertised routes и AppConnector в этом режиме не поддерживаются.

Перед включением режима сохранить прежние настройки Tailscale и выполнить:

```sh
tailscale set --accept-dns=false --accept-routes=false --netfilter-mode=off
```

Команда сохраняет регистрацию и ключи Tailscale. Не требуется `tailscale down`
или повторный `up`. DNS остаётся у clean-vpn; системный MagicDNS этим режимом
не настраивается, tailnet проверяется по IP. Обработка ACL внутри Tailscale
сохраняется. Отключается только автоматическое управление Linux firewall:
[netfilter modes](https://tailscale.com/docs/reference/netfilter-modes),
[DNS preferences](https://tailscale.com/docs/features/client/manage-preferences).

Owner принимает только точную группу правил 5210/5230/5250/5270 и IPv4
маршруты table 52 в пределах `100.64.0.0/10` через `tailscale0` без gateway.
При старте и каждые 5 секунд проверяются policy, таблица и preferences.
Default route / сторонний subnet / смена DNS или netfilter отклоняются.
Неизвестные правила не удаляются. Изменения Tailscale не входят в журнал
clean-vpn и не стираются при остановке VPN.

Журнал clean-vpn добавляет только OUTPUT grant для host→tailnet, INPUT
антиспуфинг IPv4 и DROP в обоих направлениях FORWARD для `tailscale0`.
USB не получает обход kill switch через tailnet. Восстановление удаляет только
свои правила. IPv6 public egress остаётся закрыт существующим guard;
этот режим не добавляет IPv6 exit/subnet routing.

Старые сокеты Tailscale могут сохранить Wi-Fi source IP после появления
VPN-маршрутов. OUTPUT отклоняет только marked `0x80000/0xff0000` пакеты,
идущие в `tun0` с source, отличным от назначенного peer IPv4. Приложение
получает локальный отказ и может повторить подключение; неверный source не
попадает на exit и не обрывает туннель остальных приложений. Новые сокеты
выбирают адрес `tun0`. Kernel regression отправляет такой пакет через
настоящий `SO_MARK` socket и проверяет счётчик REJECT.

Для существующей установки менять network config только при остановленном
owner и завершённом recovery. Обновить hashes именно изменённых файлов
в install/setup manifest и, если установлен binary updater, его проверенные
static bindings. Не принимать неизвестные изменения и pending transaction.

Проверки: `scripts/test-native-tailscale.mjs`, `scripts/test-killswitch-plan.mjs`,
а также Linux namespace regression `scripts/test-native-host-network-linux.mjs`
с `CVPN_TAILSCALE_PROFILE=1` (добавляются к обычным параметрам изолированного
стенда). В последней Tailscale preferences эмулируются, но policy routing,
TUN, DNS, firewall, journal/recovery исполняются настоящим ядром Linux.
