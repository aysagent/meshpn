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

## A7Z: применено 13 ноября 2026

На Cubie `192.168.8.1` с exit `84.201.14.124:443` включён режим выше.
Tailscale сохранил регистрацию, адрес `100.99.181.79` и автозапуск.
Native network owner тоже enabled; guard не отключался, Wi-Fi/USB и сеть Mac
не перенастраивались. Изменены установленный owner, guard, network.json и
только проверка нового параметра в старой копии валидатора админки. Broker
перезапущен. Связанные hashes в installed/setup manifests сверены и обновлены.
Отдельного binary-updater на этой установке нет. У network.json исходное
отличие от manifest оказалось только pretty-print: hash компактного JSON
совпал с сохранённым; значения до изменения были проверены.

Резервная копия: `/root/cvpn-tailscale-20261113/` и `followup/`. Три исходные
настройки Tailscale сохранены отдельно; ключи/регистрация не заменялись.
Начальный коммит доставлен через git bundle по USB, поскольку GitHub DNS
без работающего VPN не разрешался; следующий получен обычным git pull.

На первом запуске выявлены старые TCP sockets tailscaled с fwmark 0x80000
и source `192.168.1.9`. Exit отвергал эти пакеты и закрывал packet session.
Добавленная OUTPUT-защита покрывает этот переход. После её установки owner
и engine запущены заново; штатный restart tailscaled сохранил PID engine,
`ready_events=1`, `session_ends=0`. Tailscale: Running, health пустой, повторная
авторизация не требовалась. Его prefs после restart сохраняются.

Проверено на плате:

- Tailscale ping до NanoPi по LAN и второго узла через DERP(hel); обычный ICMP
  до NanoPi: 2/2 ответа без потерь. После restart tailscaled ping снова прошёл.
- Два USB smoke, включая повтор после финальной установки: каждый 8/8 HTTP(S)
  запросов, DNS A/AAAA UDP/TCP, 1 MiB download, 256 KiB upload; внешний IP exit
  проверен отдельно по HTTP и HTTPS. Админка USB HTTP 200, её валидатор принял
  новую конфигурацию.
- Часы сами синхронизировались через NTP после возврата туннеля; ручной установки
  времени и отключения TLS/auth проверки не было.
- Лабораторный финальный kernel regression: 39 проверок, включая настоящий
  marked socket с неверным source. Ранее дополнительно прошли 37 проверок
  обычного профиля без Tailscale и 72 теста установки/валидации/guard.

Полной перезагрузки A7Z и браузерного Speedtest на телефоне в этом прогоне
не было. Для этой установки Tailscale используется как host endpoint, не
как альтернативный exit или роутер для USB-клиентов.

После следующего переподключения питания пользователем проверена новая загрузка
A7Z (uptime около 1 минуты): native engine ready, network owner active,
Tailscale Connected, OpenSSH слушает IPv4/IPv6 port 22. Имя
`cubie-a7z.tail5b1c58.ts.net` разрешилось в `100.99.181.79`. Полный password
SSH-вход root с Mac по этому имени прошёл, сервер подтвердил соединение
между двумя tailnet IP. Host key предварительно сверен через USB; для теста
использован временный known_hosts, настройки Mac не менялись. В момент
проверки исходный сообщённый пользователем отказ SSH не воспроизвёлся;
его конкретная ошибка ещё не предоставлена. Не считать отсутствие ключа
нового имени в неинтерактивном тестовом SSH доказанной причиной его отказа.
