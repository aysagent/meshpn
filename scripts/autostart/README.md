# clean-vpn: автозапуск через systemd

> Этот установщик пока **не прошёл приёмку** для новой связки host-client + DNS +
> `--ipv6=auto`. Kill-switch v2 убирает общее исключение `ESTABLISHED` и
> предварительный `down` при повторном `up`; systemd lifecycle ещё не принят.
> Не считать его полноценной защитой при авариях и не устанавливать на Radxa
> до завершения [лабораторной приёмки](../clean-vpn-host-acceptance.md).

Простой автозапуск без hot-reload и без бота. Установщик генерирует
`/usr/local/bin/<SERVICE_NAME>-run.sh` с зашитыми аргументами и ставит systemd-юнит,
который запускает `scripts/clean-vpn.js` **из этого репозитория** (удобно на этапе
разработки/тестирования).

## Установка / обновление

Всё, что идёт после `install.sh`, — это аргументы `clean-vpn.js` как есть:

```bash
sudo env "PATH=$PATH" scripts/autostart/install.sh \
  --role=exit --server=0.0.0.0:443 --type=combo-tls --keep-alive=5 \
  --tls-probe-target=www.trustpilot.com:443 --tls-public-name=www.trustpilot.com
```

Пример для client:

```bash
sudo env "PATH=$PATH" scripts/autostart/install.sh \
  --role=client --server=62.84.120.30:443 --type=combo-tls --keep-alive=5 \
  --split-default --tls-client-sni=www.trustpilot.com --tls-public-name=www.trustpilot.com \
  --boring-tls-clienthello-profile=/root/dev/meshpn/browser-profile.json \
  --client-lan-subnet=192.168.7.0/24
```

Повторный запуск с новыми аргументами полностью перезаписывает `run.sh` и юнит
и делает `restart` — это и есть «обновить актуальным».

`sudo env "PATH=$PATH" ...` нужен, чтобы установщик нашёл ваш `node` (важно при nvm).

Юнит **намеренно не зависит от `network-online.target`**: на нестабильном uplink
(например, wifi к телефону) `wait-online` блокирует запуск — `systemctl start/restart`
и загрузка зависают. Вместо этого сервис стартует сразу; `clean-vpn` сам переподключается,
а если сети ещё нет (нет default route) — падает и рестартится по `Restart=always`, пока
uplink не появится. Установщик дополнительно делает `systemctl restart --no-block` и
не ждёт завершения job'а. Логи: `journalctl -u clean-vpn -f`.

## Kill-switch (анти-leak)

Для `--role=client` установщик автоматически ставит **kill-switch**: пока туннель
не поднят (или если он упал), guard блокирует публичный egress с перечисленными
ниже исключениями. Это не заявление о полной защите от утечек во всём lifecycle.

Разрешено всегда (чтобы не потерять управление и дать поднять туннель):

- loopback; ответы на входящий TCP SSH (`--sport=KS_SSH_PORT`, conntrack
  `ESTABLISHED` + `REPLY`), по умолчанию порт 22; не произвольные открытые соединения;
- вся локальная сеть RFC1918 (`10/8`, `172.16/12`, `192.168/16`) — SSH/управление;
- IP VPN-сервера (bypass, извлекается из `--server`);
- исходящее в `tun0`; DHCP/broadcast.

Блокируется (когда туннеля нет): весь остальной egress платы (`OUTPUT`) и форвардинг
LAN-клиентов (`FORWARD`) в интернет, плюс прямой публичный IPv6-egress.
IPv6 через TUN, link-local, ULA и link-local multicast `ff02::/16` разрешены.
Разрешающие правила используют `RETURN`, а не `ACCEPT`: последующие правила
основного firewall по-прежнему могут запретить этот трафик.

Правила живут в отдельных цепочках `CLEANVPN_KS_OUT` / `CLEANVPN_KS_FWD`
(изолированно от intercept/NAT самого clean-vpn). Kill-switch **привязан к сервису**
(`tied`): поднимается ДО `clean-vpn` и снимается при остановке сервиса.

Повторный `up` перестраивает собственные цепочки через `iptables-restore --noflush`
без предварительного снятия защиты. Commit атомарен **внутри одной семьи IP**,
не одновременно для IPv4 и IPv6. Сначала проверяются оба плана. Ошибка применения
не вызывает автоматического `down`; повторный `up` может завершить частичное обновление.
Операции сериализованы `flock`. Нужны согласованные `iptables`/`iptables-restore`
и `ip6tables`/`ip6tables-restore`, bash, stat и flock.

Guard проверяет собственные правила и hooks перед изменением. Старые немаркированные
цепочки, чужие правила, лишний/отсутствующий hook или правило перед hook приводят
к отказу без очистки firewall. Автоматической миграции старой защиты нет.
Менять `scope`/`ipv6` при действующем guard запрещено; явный `down` снимает защиту.
DNS/IPv6 runtime может поставить свой hook первым: обновлять/снимать guard следует
после штатной остановки VPN. Не использовать глобальный flush для обхода отказа.
Имена цепочек и lock общие: несколько независимых kill-switch instances не поддержаны.

```bash
# посмотреть активные правила / снять-поднять вручную:
/usr/local/bin/clean-vpn-killswitch.sh status
sudo /usr/local/bin/clean-vpn-killswitch.sh down
sudo /usr/local/bin/clean-vpn-killswitch.sh up --server=154.62.226.216 --scope=both --ipv6=block
```

Env-переключатели установщика:

- `KILLSWITCH=1|0` — ставить kill-switch (default `1` для client, `0` для exit;
  на exit он вреден — там плата и есть выход в интернет).
- `KS_SCOPE=both|fwd` — резать `OUTPUT`+`FORWARD` (default `both`) или только `FORWARD`.
- `KS_IPV6=block|leave` — резать IPv6-egress (default `block`).
- `KS_SSH_PORT=22` — порт входящего SSH, ответы которого разрешены (`0` отключает
  исключение). При нестандартном порте задать его до установки; другие публичные
  входящие сервисы этим исключением не защищены от потери связи.
  Это исключение firewall, **не настройка обратного маршрута SSH**: включение
  `--split-default` по удалённому публичному SSH требует отдельного bypass
  маршрута управления или доступа через консоль/локальную сеть.
- `KS_SERVER_IPS=IP[,IP...]` — bypass к серверу, если IP не извлёкся из `--server`
  (напр. когда `--server` задан хостнеймом с меняющимся IP).
- `KILLSWITCH_PERSIST=1` — kill-switch **не** привязан к сервису: активен с раннего
  boot (`network-pre.target`) и держится, даже если сервис остановлен/упал; снимается
  при явном снятии защиты. Ранний boot и update/uninstall ещё не прошли совместную
  проверку: нельзя обещать отсутствие окна до установки правил.

> ВНИМАНИЕ: kill-switch с `KS_SCOPE=both` блокирует и DNS к публичным резолверам
> (напр. `8.8.8.8`), пока туннель не поднят. DNS к локальному резолверу (RFC1918)
> и через `tun0` работает. Если `--server` — хостнейм, его IP резолвится на момент
> установки; при смене IP переустановите или задайте `KS_SERVER_IPS`.

## Опции установщика (через env)

- `SERVICE_NAME` — имя сервиса, default `clean-vpn`. Влияет и на имя run.sh
  (`/usr/local/bin/<SERVICE_NAME>-run.sh`). Это не изоляция сетевых правил:
  несколько client kill-switch одновременно не поддержаны.
- `NODE_BIN` — путь к `node`, если автодетект не подходит:

```bash
sudo NODE_BIN=/root/.nvm/versions/node/v24.13.0/bin/node \
  scripts/autostart/install.sh --role=exit --type=combo-tls ...
```

Два сервиса на одной машине:

```bash
sudo env "PATH=$PATH" SERVICE_NAME=clean-vpn-exit scripts/autostart/install.sh --role=exit ...
sudo env "PATH=$PATH" SERVICE_NAME=clean-vpn-cli  scripts/autostart/install.sh --role=client ...
```

## Управление

```bash
systemctl status clean-vpn
journalctl -u clean-vpn -f          # логи
sudo systemctl restart clean-vpn
sudo systemctl stop clean-vpn       # SIGTERM → откат маршрутов/NAT
```

## Удаление

```bash
sudo scripts/autostart/uninstall.sh
sudo SERVICE_NAME=clean-vpn-exit scripts/autostart/uninstall.sh
```

## Что создаётся

- `/usr/local/bin/<SERVICE_NAME>-run.sh` — обёртка: выставляет `PATH`
  (с `/usr/sbin`,`/sbin` для `iptables`/`ip`/`sysctl`), делает `cd` в корень репозитория
  и `exec node scripts/clean-vpn.js <аргументы>`.
- `/etc/systemd/system/<SERVICE_NAME>.service` — юнит: `Type=simple`, `Restart=always`,
  `After=network.target` (без ожидания `network-online.target`),
  `StartLimitIntervalSec=0`, `TimeoutStopSec=420`, `KillMode=mixed`.
  Начальный SIGTERM направляется только основному процессу, чтобы не прервать
  его cleanup-команды. Лимит учитывает отдельные 120-секундные бюджеты DNS, IPv6 и IPv4-маршрутов;
  это верхняя граница, не обязательная задержка остановки. Изменение применяется
  только при переустановке юнита; сейчас не переустанавливать ради этой правки —
  приёмка всей связки ещё не завершена.
- (client) `/usr/local/bin/<SERVICE_NAME>-killswitch.sh` и
  `/etc/systemd/system/<SERVICE_NAME>-killswitch.service` — kill-switch (см. выше).

## Заметки

- `StartLimitIntervalSec=0` отключает лимит рестартов: иначе после нескольких быстрых
  падений подряд (например, сеть/сервер недоступны на старте) systemd увёл бы сервис в
  `failed` и перестал бы его поднимать — а это и есть «не запустилось автоматом + leak».
- Сервис исполняется от root (нужно для TUN/iptables) — это дефолт system-юнита.
- Пути к сертификатам/`--config` в аргументах лучше указывать **абсолютными**
  (юнит делает `cd` в корень репо, но абсолютные надёжнее).
- Сервис ссылается на `clean-vpn.js` в текущем репозитории; при переносе репозитория
  перезапустите установщик, чтобы обновить пути в `run.sh`.
