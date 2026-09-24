# DNS: конфиденциальность, bootstrap и публичные имена

План по обсуждению 2026-09-23. Первый explicit-loopback DoH стенд **реализован**:
[запуск и границы](../scripts/transparent-dns-lab.md), разделы 32–33 context.
Дополнительно реализованы независимый namespace pcap и bounded DNS soak.
DNS клиента/системы и firewall не менялись. Production DNS интеграции пока нет.
Upstream/bootstrap JSON contract и offline CLI реализованы отдельно:
[конфигурация](../scripts/dns-upstream-config.md), раздел 34 context.
Есть opt-in pinned route exit и [явный клиентский adapter](../scripts/dns-exit-adapter.md)
через числовой exit endpoint, а также его собственные
[pcap/soak](../scripts/dns-adapter-soak.md), отдельно от прежнего lab TLS пути.
Динамическое клонирование BoringSSL-профиля не возвращаем.

## Что есть сейчас

- `clean-vpn.js` split-default оставляет private/LAN-сети на uplink, поэтому
  запросы системному DNS на роутере могут обходить VPN. IPv6 требует отдельной
  проверки. Факт наличия TUN не доказывает отсутствие DNS leak.
- Transparent перехватывает IPv4 TCP/443. Произвольный DNS UDP/TCP 53 не
  становится enc-SNI relay; у standalone transparent общий IPv4 stream сырой.
  Даже если DNS отправлен по нему через exit, payload не становится секретным.
- В combo общий IPv4 идёт через TLS-mux/BoringSSL. Это подходящая основа для
  защищённой доставки DNS, но не доказательство, что конкретный DNS туда попал.
- Exit самостоятельно разрешает исходный hostname. Новая destination policy
  проверяет IP и предотвращает повторное разрешение при connect, но использует
  OS resolver, не добавляет DoH/DoT или DNSSEC.
- `--tls-public-name=a,b` — публичные SNI-имена для dispatch; в enc-SNI берётся
  primary public name. Это не список разрешённых DNS-назначений и не механизм
  случайного выбора доменов. `transperent-sni-dictionary.md` — ещё план alias-cache,
  не реализованный allowlist/cover DNS сервис.

## Приоритет: настоящий DNS через защищённый путь

Предлагаемое направление: отдельный DNS transport adapter/stub с явным upstream,
проверкой его TLS-сертификата/имени и отсутствием fallback в открытый LAN/ISP DNS.
Первую проверку можно сделать на одном VPS: loopback DNS client → explicit stub →
TLS/HTTPS test resolver через стенд, без TUN, port 53 системы или `/etc/resolv.conf`.
Это ещё не прозрачное включение для всех приложений.

Для protected upstream использовать стандартный
[DoH, RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) или
[DoT, RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html), либо DNS внутри уже
аутентифицированного шифрованного mux. Для текущего TCP/443 relay DoH естественнее
вписывается в существующий путь; это проектное предпочтение, не обещание мимикрии.
Нужно определить, кто доверенный resolver и где заканчивается шифрование.

Bootstrap решать отдельно: exit/resolver endpoints должны быть доступны до
обычного DNS через tunnel — явные IP/проверяемая конфигурация либо узкое разрешение
на разрешение **только** имени exit. Нельзя решать цикл «для tunnel нужен DNS,
для DNS нужен tunnel» разрешением любого прямого DNS при ошибке.

Проверки стенда и последующей интеграции:

1. UDP и TCP запросы explicit stub, A/AAAA, TC/truncation, NXDOMAIN, timeout,
   malformed responses, ограничения размера, очереди, in-flight, TTL и cleanup.
2. Настоящий TLS upstream: доверенный сертификат проходит; wrong CA/hostname,
   downtime, reset/restart приводят к контролируемому отказу без plaintext fallback.
3. Наблюдаемый путь: real QNAME не появляется на имитированном внешнем plaintext
   DNS listener/pcap. Одна только успешная резолюция — недостаточный критерий.
4. Отдельные capture точки client↔exit и exit↔resolver: от какого наблюдателя
   скрываются запросы, а кому они всё ещё доступны. DNS resolver видит QNAME;
   exit тоже может видеть его при завершении защищённого канала на exit.
5. Уже после этого отдельное согласованное внедрение для OS/LAN/IPv6/bootstrap
   и crash/restart. До него нельзя объявлять все системные DNS-запросы защищёнными.

Закрытый DNS не скрывает автоматически адрес exit, тайминги/размеры трафика,
plaintext TLS SNI на других путях или все посещаемые домены от любого наблюдателя.
Это отдельный слой конфиденциальности, не доказательство неотличимости от браузера.

## Идея редких прямых запросов к cover-доменам

Сама по себе реализация возможна, но полезность не установлена. Отсутствие DNS
перед каждым TLS connect нормально при cache/повторном соединении/защищённом DNS.
Гипотеза: независимый случайный запрос перед каждым N-м tunnel connect может
создать новый корреляционный признак вместо улучшения правдоподобия.

Если возвращаться к эксперименту, сначала проверить согласованность:

- публичное имя принадлежит оператору или действительно обслуживает этот exit;
  полученные A/AAAA соотносятся с фактическим IP подключения;
- поведение зависит от cache/TTL и реальной необходимости разрешить endpoint,
  а не от обязательной последовательности «cover DNS → tunnel»;
- ограничены частота, timeout и число имён; ошибки cover DNS не вызывают
  plaintext fallback для реальных пользовательских QNAME;
- реальные origin не попадают в direct-query list. Длинные уникальные
  `<encrypted-labels>.publicName` тоже не запрашиваются: это вынос route token
  в DNS и новая наблюдаемая корреляция, а не полезный bootstrap;
- certificate/probe/SNI/IP согласуются, а отсутствие соответствующего HTTP
  поведения не выдаётся за полноценную мимикрию браузера.

Случайные запросы к чужим популярным доменам при последующем подключении к IP VPS
такой согласованности не дают. Предпочтение: обычное кэшируемое разрешение
собственного публичного имени exit, если оно действительно нужно для соединения,
вместо декоративного фонового DNS. Даже это не скрывает нынешний длинный enc-SNI.

Прямые cover-запросы **не включены**. После обсуждения отложены: недоказанная
польза не оправдывает добавление новых наблюдаемых признаков. Для публичного
имени exit предпочтителен собственный домен с настоящими A/AAAA-записями.
Безопасный bounded IP failover exit реализован (раздел 31 context).
Explicit-loopback DoH стенд проверяет success/failure/resource сценарии;
отдельный namespace runner добавляет независимый pcap обоих направлений,
plaintext positive control, повторные запросы/обрывы/restart и resource budgets.
Pcap покрывает короткую матрицу перед soak, а не весь длительный прогон.
Contract upstream/bootstrap реализован: TLS hostname отдельно от numeric IP,
bundled/custom CA, строгая offline validation и применение TLS/HTTP identity
на loopback-стенде. Public profiles подключаются к exit connector явно через
`--tls-dns-upstream-config=PATH` (только exit transparent-tls/combo-tls).
Configured hostname+port использует static public-IP snapshot без OS lookup;
другой port того же имени запрещён, остальные routes сохраняют старую policy.
Перебор только до успешного TCP выбора, без DNS/mux fallback; live exit не менялся.
Explicit клиентский DNS adapter через числовой exit endpoint реализован,
с TLS hostname/CA validation, без системного переключения DNS/TUN.
Расширен [DNS wire contract](../scripts/dns-wire.md): обычные IN-типы, включая
HTTPS/SVCB, TXT, SRV, PTR; бинарные labels, EDNS(0), extended RCODE, безопасный TC
и matching вопроса/ответа. RDATA передаются непрозрачно, без semantic/DNSSEC validation.
Реализованы TCP/DoH DNS65535 с отдельным UDP cap4096 и фиксированными buffers,
локальный BADVERS для новых EDNS versions и HTTP Age/TTL (включая negative SOA).
Реализован первый этап [DNS lifecycle](../scripts/dns-lifecycle.md): offline dry-run
и namespace-only glibc DNS стенд. Проверяются readiness, exit outage/recovery,
guard для UDP/TCP53 IPv4/IPv6, conflict без перезаписи и явное восстановление.
Добавлены namespace-only journal и13 реальных SIGKILL контроллера на каждую
семью IP: recovery прерванных apply/restore, flock, конфликты inode/hash,
missing/corrupt/stale journal. Backend/adapter остаются в namespace init;
это не host backend, не SIGKILL adapter и не reboot/power-loss test. До opt-in
live integration нужны диагностика DNS клиента, подтверждённое владение
настройками, полный adapter lifecycle и VM reboot tests. LAN/split DNS отдельно.
Для сбора evidence на реальном клиенте: `npm run dns:inspect`,
[контракт диагностики](../scripts/dns-inspect.md). Backend не выбирается автоматически;
отчёт рабочего окружения не заменяет диагностику клиентской машины.
Для resolved сделан [экспериментальный D-Bus backend](../scripts/dns-resolved.md)
с реальным namespace daemon/bus, apply/restore, ownership conflict и daemon
SIGKILL/restart. Добавлен отдельный `--resolved-journal`: persistent snapshots,
bus ID/owner/link/scope, per-setter intents, flock и controller-crash матрица.
Следующий этап — полный adapter lifecycle и VM reboot/power-loss tests.
Radxa с disabled resolved и оборванной ссылкой автоматически
не исправляется; восстановление штатного DNS нужно согласовать отдельно.
Кэша и активного production DNS/bootstrap пока нет.
Случайные cover DNS запросы не входят в этот план реализации.
