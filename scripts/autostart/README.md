# clean-vpn: автозапуск через systemd

> Приёмка на Radxa ещё не выполнена. Первый кандидат ограничен host-client,
> TLS/H2 поверх IPv4, DNS tunnel, `--split-default --ipv6=auto`, persist guard
> both/block и systemd-networkd. Начинать с read-only preflight ниже;
> не устанавливать и не перезагружать удалённую плату без плана и локальной консоли.

В лаборатории воспроизведён блокер persist-mode: при ошибке guard **до установки
правил** VPN не стартует, но одного `Before=network-pre.target` недостаточно,
чтобы запретить запуск других сетевых потребителей. В отдельной транзакции
systemd такой потребитель выполнил прямые IPv4/IPv6/DNS-запросы. Это не проверка
реального reboot. Для этого дефекта добавлена отдельная opt-in интеграция
`NETWORKD_GUARD=1`: networkd и его socket требуют успешно запущенный guard. Она не включается
по умолчанию; прежний persist-mode без этой опции не получает новых гарантий.

## Первый шаг на Radxa: только проверка

Из обновлённого репозитория выполнить одну команду и сохранить/передать весь отчёт:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-host-preflight.mjs --exit-ip=154.62.226.216
```

Команда не посылает сетевых проб, не меняет DNS, firewall или маршруты, не ставит
сервисы и не останавливает VPN. Если ручной client работает, отчёт это отметит;
для этого первого сбора останавливать его не нужно. `review-required` (код 1)
означает необходимость разбора, а не команду автоматически исправить настройки.
Даже `inventory-ready-for-review` — не разрешение установки: нужны проверка
Wi-Fi/раннего boot, SSH-порта и доступной локальной консоли.

## Кандидат networkd (только после разбора preflight)

Опция установщика `NETWORKD_GUARD=1` требует `KILLSWITCH=1`,
`KILLSWITCH_PERSIST=1`, `KS_SCOPE=both`, `KS_IPV6=block`, а также host client
`--type=tls --split-default --ipv6=auto` с числовым IPv4 адресом exit.
LAN, config-файлы, нестандартные DNS state-dir и другие транспорты в первый
кандидат не входят. На exit внешний IPv6 необязателен: при его отсутствии
client блокирует прямой внешний IPv6, а не объявляет IPv6 доступным.

Установщик проверяет активный networkd, отсутствие другого менеджера и TUN,
публикует собственные drop-in `90-clean-vpn-SERVICE_NAME.conf` для
`systemd-networkd.service` и `systemd-networkd.socket`, оба с
`Requires/After=SERVICE_NAME-killswitch.service`. Сетевые конфиги не переписывает
и networkd не перезапускает. При отказе guard на boot networkd не стартует:
**сеть и SSH могут быть недоступны; восстановление требует консоли**.
Адреса, настроенные ещё в initramfs, и параллельные администраторы не покрываются.
Пара drop-in не является одной атомарной операцией. Прерванная установка может
оставить частичную конфигурацию и зависимость от отсутствующего guard; повторный
installer намеренно откажет. Это требует разбора через консоль, а не удаления
файлов вслепую. Матрица штатных reboot не является power-cut тестом установщика.

Обычный stop/restart выполняется для основного VPN-сервиса. Не останавливайте
guard вручную через SSH: зависимость остановит также networkd и его socket. При этом правила
защиты **останутся**, потому что `ExecStop` guard в этом режиме их не снимает.
Audited uninstall сначала проверяет три released-журнала, удаляет только свой
drop-in обоих юнитов, делает daemon-reload и проверяет отсоединение зависимостей; только затем
останавливает guard и явно снимает его правила. Networkd остаётся запущенным.
Updater сохраняет оба drop-in и guard; новая версия остаётся остановленной до явного
старта. Подробности и ограничения матриц — в [отчёте лаборатории](../clean-vpn-host-acceptance.md).

Простой автозапуск без hot-reload и без бота. Установщик генерирует
`/usr/local/bin/<SERVICE_NAME>-run.sh` с зашитыми аргументами и ставит systemd-юнит,
который запускает `scripts/clean-vpn.js` **из этого репозитория** (удобно на этапе
разработки/тестирования).

## Новая установка (повторный installer запрещён)

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

Повторный запуск теперь **отклоняется до изменений**, даже для остановленного
сервиса и даже с `KILLSWITCH=0`. Проверяются четыре установленных файла, два networkd drop-in и состояние
обоих юнитов в systemd; partial installation, ссылки, masked/loaded/failed units
и ошибка чтения также означают отказ. Старые wrapper, unit и guard не заменяются.
Для ограниченного переключения версии добавлен отдельный updater ниже. Не удаляйте файлы вручную
и не используйте uninstall как способ обойти этот запрет: он снимает защиту.
Проверка не является блокировкой против параллельных установщиков/администраторов.

`sudo env "PATH=$PATH" ...` нужен, чтобы установщик нашёл ваш `node` (важно при nvm).

Юнит **намеренно не зависит от `network-online.target`**: на нестабильном uplink
(например, wifi к телефону) `wait-online` блокирует запуск — `systemctl start/restart`
и загрузка зависают. Вместо этого сервис стартует сразу; `clean-vpn` сам переподключается,
а если сети ещё нет (нет default route) — падает и рестартится по `Restart=always`, пока
uplink не появится. Установщик дополнительно делает `systemctl restart --no-block` и
не ждёт завершения job'а. Логи: `journalctl -u clean-vpn -f`.

## Переключение версии: лабораторный updater

Пока не применять на Radxa/VPS: общая приёмка autostart не завершена.
`scripts/clean-vpn-update.mjs --release=/absolute/separate/release` предназначен
только для установленного **host client + split-default + persist guard both/block**.
`SERVICE_NAME` выбирает сервис. Это не повторный installer и не `git pull`.

Каталог новой версии готовится заранее, отдельно от работающей копии; нужны
зависимости, `package.json` и собранный TUN addon. Вся копия и её родители должны
принадлежать root, без записи для остальных, symlink/hardlink и специальных файлов.
Допустимы простые пути/имена; максимум 10000 записей и 256 MiB файлов. Updater
сверяет состав/хеши до и после stop, но не компилирует, не скачивает и не запускает
новый код для проверки совместимости. Не менять обе копии во время операции.

Порядок: проверить известные templates/guard → stop старого клиента → удержать
блокировки трёх `released`/отсутствующих журналов → проверить реальные правила
IPv4/IPv6 guard → атомарно заменить один wrapper. Аргументы, Node, units и
guard сохраняются; меняются только `cd` и путь к `scripts/clean-vpn.js`.
Сложные shell-аргументы, custom DNS state-dir, config-файл, LAN/from-tun scope,
нестандартные units/overrides, tied/неактивный guard требуют ручного разбора.

Успех возвращает `updated-stopped`, хеши и `backupDirectory`. Сервис **остаётся
остановленным**, guard продолжает блокировать публичный egress. После проверки
результата запуск выполняется отдельно через `systemctl start SERVICE_NAME`.
Это не подтверждение работоспособности новой версии: её надо проверить после запуска.

Резервная копия wrapper сохраняется как приватный `previous-wrapper` в каталоге
`.clean-vpn-update-*` рядом с установленным wrapper; там могут быть чувствительные
аргументы. Updater не удаляет старую версию, backup или журналы. После ошибки/обрыва
не выполняет автоматический старт либо rollback: проверяйте выбранный wrapper и
журналы. Незавершённые сетевые журналы требуют отдельного явного recovery.
Параллельное управление другим администратором, питание/reboot, смена параметров
guard, публикация нового unit и автоматический старт этой процедурой не покрываются.

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
sudo env "PATH=$PATH" scripts/autostart/uninstall.sh
sudo env "PATH=$PATH" SERVICE_NAME=clean-vpn-exit scripts/autostart/uninstall.sh
```

Удаление теперь требует доступного Node (`NODE_BIN` можно задать явно).
Успешный `systemctl stop` **не считается доказательством восстановления сети**:
до снятия guard проверяются журналы host IPv4, DNS tunnel и IPv6. Разрешены только
`released` либо отсутствие журнала; блокировки удерживаются до завершения удаления.
Активный/незавершённый/повреждённый журнал или занятая блокировка вызывают отказ,
guard и файлы не снимаются. Автоматического `--apply` нет; журналы не удаляются.

Пока поддержано аудированное удаление **persist-mode** (либо сервиса без guard).
Tied-mode (`PartOf`/`BindsTo`, в том числе текущий default установщика) отклоняется
**до stop**, поскольку systemd может снять такой guard до проверки rollback.
Это намеренный отказ вместо небезопасного удаления; не обходить его ручным flush
или удалением unit-файлов. Также требуют отдельного разбора нестандартный
`--dns-state-dir`, частичная установка, приватные namespace/root/bind mounts.
Проверка должна выполняться в том же network namespace, что и сервис.
Конкурентные изменения unit/firewall другим администратором не покрываются.

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
- Сервис ссылается на `clean-vpn.js` в текущем репозитории. Перенос или обновление
  самого репозитория тоже меняет доступный сервису код и не защищается проверкой
  повторной установки. Не выполнять это как live-update; процедура обновления
  через отдельный updater ограничена описанным выше лабораторным сценарием.
