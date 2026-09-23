# Явный клиентский DNS adapter через exit, без TUN

Отдельный opt-in процесс: `127.0.0.1` UDP/TCP DNS → DoH TLS → enc-SNI exit →
настроенный resolver. Не запускает `clean-vpn.js`, не создаёт TUN, не меняет
маршруты, firewall, `/etc/resolv.conf`, trust store или настройки браузера.
Это ограниченный пилотный адаптер, **не системный DNS resolver общего назначения**.
Проверено на Node 24.13.0; native addon, BoringSSL, root и браузер не нужны.

## Запуск оператором

Сначала подготовить [upstream JSON](dns-upstream-config.md) с настоящими
hostname/port/path, проверенными public bootstrap IP и доверенными CA. На exit
должна быть согласованная pinned route через `--tls-dns-upstream-config=...`
в `transparent-tls` / `combo-tls`. Один и тот же 32-байтовый PSK нужен для enc-SNI.
Это не подключение к обычному `--type=tls` exit и не включение сырого TUN.

```bash
npm run dns:check-upstream -- --config=/path/to/upstream.json

# Заменить IP и имя на адрес/enc-SNI public-name вашего exit.
npm run dns:exit-adapter -- \
  --config=/path/to/upstream.json \
  --exit-ip=YOUR_PUBLIC_EXIT_IP --exit-port=443 \
  --public-name=vpn.example.com \
  --shared-hmac-key=/path/to/clean-vpn-hmac.key \
  --listen-port=1053
```

Все шесть параметров обязательны; неизвестные, повторные, пустые или malformed
аргументы отвергаются. `--help` работает отдельно и не читает конфигурацию.
Exit IP — **числовой public-unicast IPv4/IPv6**, без DNS lookup, URI, порта в IP,
zone-id, private/loopback/multicast. IPv6 задаётся без квадратных скобок.
Exit port: 1..65535. Listen port: 1024..65535; bind строго `127.0.0.1` сразу
для UDP и TCP. Listen address/LAN binding не настраиваются. Ошибка второго
bind откатывает первый; невалидная конфигурация отвергается до listeners.

PSK читается из regular non-symlink файла ровно32 байта, без прав group/other
(обычно `0600`). Нет автогенерации, hex/env-пароля или пересылки ключа в CLI.
JSON читается тем же bounded reader, что offline checker. Всё загружается
один раз, копируется; смена файлов требует управляемого перезапуска.

Готовность: `DNS_EXIT_ADAPTER {"status":"listening",...}` — это bind, **не**
проверка доступности exit/upstream. До первого DNS-запроса внешнего TCP нет.
Ошибки запуска: `DNS_EXIT_ADAPTER_INVALID`, exit1, без пути/PEM/PSK/stack.
SIGINT/SIGTERM закрывают listeners, активные запросы и relay-соединения.

Проверять явным клиентом, например при установленном `dig`:

```bash
dig @127.0.0.1 -p 1053 example.com A
dig @127.0.0.1 -p 1053 example.com AAAA +tcp
```

Только такие явно направленные запросы используют адаптер. Другие приложения
по-прежнему используют собственный/системный DNS; успешный `dig` не доказывает
защиту DNS всей системы. Не переключайте OS DNS на него до отдельной интеграции.

## Как исключён direct fallback

DoH использует `https.Agent` с собственной фабрикой TLS-соединения. TLS получает
один конец `duplexPair` в памяти, другой читает общий transparent client runtime.
Отдельного локального TCP HTTPS-proxy/listener нет. Единственный внешний dial
клиента — `net.connect` к закреплённому числовому exit IP/port; bootstrap IP
resolver **никогда не передаётся в клиентский TCP connect**. Переменные HTTP proxy
и глобальный HTTPS agent этот путь не выбирают. Клиент не перебирает exit IP.

SNI и certificate hostname check берутся из upstream hostname; HTTP Host/port/path
из того же compiled profile. TLS1.3+, `rejectUnauthorized: true`, явный bundled
или custom CA; HTTP/1.1, без session cache и connection pooling. Чужое имя, CA,
самоподписанный недоверенный сертификат не разрешаются. DoH body не доставляется
до успешной проверки сертификата. Это **сертификат resolver**, не exit: enc-SNI
relay не добавляет внешнюю TLS-сессию/сертификат VPN поверх исходного TLS.

Exit расшифровывает маршрут hostname/port из SNI и выбирает configured IP.
Клиент не может проверить, включил ли оператор на exit pinned route: без неё
exit может использовать обычный OS resolver. Установите согласованный JSON
на обе стороны; проверки TLS upstream остаются обязательными в любом случае.
Неверный PSK/недоступный exit/upstream/ошибка TLS/HTTP → SERVFAIL, не другой DNS,
не прямое HTTPS к resolver и не plaintext UDP/TCP53. Redirect не выполняется.

## Лимиты и ещё не сделанное

Используется существующий bounded stub/parser из `lab-doh-stub.mjs` и
`lab-dns-wire.mjs`, а не новый расширенный DNS stack:

- Только один IN A/AAAA вопрос, максимум4096 байт, ограниченный EDNS; прочие
  типы/некорректные запросы не обслуживаются. Это не полная поддержка DNSSEC,
  HTTPS/SVCB, SRV, TXT, PTR и прочих DNS-сценариев.
- По умолчанию16 in-flight запросов и16 локальных TCP-соединений; общий deadline
  DoH1500мс, lifetime входного TCP5000мс, bounded framing/HTTP headers/body.
  Deadline клиента может закончиться раньше exit failover — достижение каждого
  из восьми IP за этот срок не гарантируется.
- UDP-ответ больше объявленного лимита → TC; приложение может повторить через TCP.
  Проверяются ID/вопрос/структура ответа, status200, DNS content-type, отсутствие
  content encoding, размер; cache/pooling/HTTP retries отсутствуют.
- Один новый TLS/exit connection на запрос. Ограничение in-flight — не полная
  защита от локального DoS/rate limiting; пользоваться loopback listener могут
  и другие локальные процессы. Нет LAN listener, ACL по локальным пользователям.
- IPv6 может использоваться **для адреса exit и resolver**, но это не IPv6 VPN,
  IPv6 DNS listener или устранение IPv6-утечек прочих приложений.
- Штатные relay-логи содержат IP/port и коды ошибок, но не QNAME, CA или PSK.
  Числовые resource counters доступны через JS API; CLI не пишет per-query QNAME.

API `startDnsExitAdapter` принимает только настоящий public compiled profile;
`createLabDnsExitTransport` — отдельный JS test API с loopback profile, без
соответствующего CLI/JSON переключателя. Фальшивые/cloned profiles не принимаются.

## Проверки и следующий шаг

```bash
npm run test:dns-exit-adapter
npm run test:dns-exit-adapter-real
```

Первый набор включён в общий acceptance: preflight, ключи, A/AAAA UDP/TCP,
TLS name/CA rejection, PSK rejection, timeout/reset/redirect, недоступный exit,
snapshot, отсутствие системных name lookups/лишнего TCP dial, закрытие запросов,
SIGINT/SIGTERM и освобождение listeners. Wire observer проверяет отсутствие
QNAME в зашифрованном потоке, но **это не независимый pcap нового адаптера**.

Real-набор использует Linux user/net/mount/PID namespaces только с `lo` и public
IPv4/IPv6 aliases внутри него; нужен OpenSSL и `ip`. Настоящий public contract
клиента и exit, без mock resolver/private exemption; первый IP refused, второй
проходит TLS и DoH, затем wrong CA/reset/exhaustion/recovery. Проверяются обе
метки runtime transparent/combo, TCP/UDP A/AAAA, отсутствие DNS lookup и
освобождение sockets/timers/processes. Это не запуск full clean-vpn/TUN/mux.

Следующий пакет — **независимый pcap и ограниченный soak именно этого нового
client→exit пути**, включая длительные обрывы и отмену при переполнении.
Прежний DNS pcap/soak проверял lab TLS через локальный relay listener; его
результаты нельзя автоматически переносить на новую in-memory ветку.
После этого — отдельное согласование OS/LAN/IPv6-интеграции, не в этом пакете.
