# Combo Radxa↔VPS: DNS framing и personal-cert.internal

**Продолжение 31 октября:** [рабочая пара переключена на combo-tls](clean-vpn-native-combo-daily-20261031.md).
Ниже исторический snapshot; актуальные unit names, certificate и команды — по ссылке.

Повторный физический bounded trial 30 октября завершён: **combo H2 и H1 прошли**.
Использованы свежие native engine на самой Radxa и VPS, отдельные namespaces,
TUN и TCP/Unix bridges на внешнем порту 3443. Повседневный boring-tls не
перезапускался и не заменялся. [Машиночитаемый отчёт](../fixtures/clean-vpn-native-combo-neutral-wan-20261030.json).

## Восстановление доступности Radxa

Первый preflight обнаружил реальные ошибки чтения `/usr/bin` и EXT4 на
`mmcblk1p2`. При следующем подключении обнаружена новая загрузка; агент её
не инициировал. Initramfs fsck восстановил журнал и принудительно проверил
раздел. Команды снова заработали, daily engine/network owner и USB rescue
оказались активны. Сохранена и прочитана приватная резервная копия выбранных
конфигураций и установленных компонентов на Mac — 80.3 MB, 1577 entries.

После Git update, сборки и всех испытаний счётчик EXT4 errors остаётся 0.
Это позволило продолжить работу на плате без переустановки, но не установило
причину первоначального повреждения и не доказывает исправность накопителя.
[Точный fsck log и backup receipt](clean-vpn-native-trial-blocker-20261030.md).

## Сертификат и доверие

Тестовая TLS identity — `personal-cert.internal`, issuer —
`Personal Certificate Authority`. Клиенты доверяют отдельному приватному CA;
leaf имеет CA:FALSE/serverAuth и правильный DNS SAN. Проверены native discovery,
полная packet-сессия, HTTPS relay TLS1.2 и TLS1.3 с CA/hostname verification.
Ни одна проверка TLS не отключалась. Генератор новых bundles теперь использует
нейтральное имя CA; существующие сертификаты автоматически не переписываются.

Первый подготовленный self-signed leaf был ошибочным кандидатом для нашей
закреплённой BoringSSL: его keyUsage не разрешал keyCertSign, требуемый при
поиске trusted issuer для self-issued сертификата. OpenSSL принял trust,
native `--check-config` принял файл, но настоящий handshake отказал
`tls_verify_untrusted`. Оба начальных отказа сохранены в отчёте. В fixture
добавлен bounded `discovery.log` и фиксированный reason-код вместо потери stderr.
Кандидат заменён полноценной CA/leaf цепочкой; старый не устанавливать.

Правильная цепочка сохранена только на VPS в приватном проектном каталоге:
`/root/dev/meshpn/native/clean_vpn/build/personal-cert-chain-20261030`.
Для будущего применения нужны `exit/cert.pem`, `exit/key.pem` и публичный
`authority/ca.pem` клиентам. Сгенерированный test `exit/engine.json` содержит
новую тестовую PSK и **не является конфигом повседневного exit**.

Daily-пара по-прежнему использует прежнее доверие/имя. На working exit три
клиентские идентичности: перенос нового CA требует согласованного обновления
клиентских комплектов, имени/SNI и проверки админки. Изолированный trial не
выполняет такое переключение и не меняет транспорт рабочей пары.

## Что проверено в каждом WAN-прогоне

- Именованные laptop/canary с разными ключами, export/import и verified
  address discovery `.3`/`.4`; source client config не содержит фиксированный IP.
- DNS A по UDP/TCP через native TUN, synthetic TCP echo 3584 байта,
  параллельные HTTPS relay TLS1.2/TLS1.3 с проверкой тела и сертификата.
- Ротация canary: старый ключ отклонён, новый принят. Отзыв: discovery
  отклонён, DNS NXDOMAIN. Laptop и exit сохранили свои PID.
- Pending registry marker: ожидаемый SERVFAIL; после удаления DNS и данные
  восстановились. Ещё восемь явных смешанных проб после восстановления.
- Background probes: H2 — 28 успешных, H1 — 27. Ошибки DNS в фоне совпадают
  с намеренным marker (1 и 3 соответственно). В каждом прогоне ещё один TLS
  EOF появился **после сообщения systemd `Stopping`**, при остановке in-flight
  пробы; он сохранён отдельно и не объявлен ошибкой DNS.
- До/после совпали host routes/rules/addresses, firewall, DNS, forwarding,
  daily MainPID/InvocationID. Port3443 освобождён, временные ключи и trial
  directories удалены. Кандидат сертификата и build caches сохранены отдельно.

## Независимые captures и задержка DNS

Внешний wlan0 capture совпал с сохранённым Chromium subset profile для
**12/12 packet ClientHello**. JA4:
`t13d0915h2_f91f431d341e_54d72502093d`; sorted JA3:
`9fc752c58190630c49e1812906b40077`. H1 выбран exit при неизменённом предложении
ALPN клиента; наличие `h2` в JA4 не означает выбранный сервером H2.

Transparent: **158/158 доступных пар** исходного и внешнего ClientHello совпали
по JA3/JA4/ALPN — H2 80/80, H1 78/78. Три внешних потока не имеют пары в окне
исходного capture и не включены в совпадения. Kernel capture drops — 0.
Съём независим от engine, но parser отпечатков общий; полной неотличимости
от браузера результат не доказывает.

| Успешные `laptop.mpn` TCP ответы | Прежний H2 capture | Новый H2 | Новый H1 |
| --- | --- | --- | --- |
| Exit TUN: запрос → полный ответ, median | 205.025 мс | 2.070 мс | 2.058 мс |
| Client TUN: запрос → полный ответ, median | 302.263 мс | 273.831 мс | 216.606 мс |

В каждой колонке использован один offline parser и только успешные запросы.
WAN, libc/build и время прогонов различаются: это измерение исчезновения
локальной задержки exit, а не контролируемый benchmark общего ускорения.
Мосты и WAN по-прежнему влияют на клиентскую задержку. На client/exit TUN нет
неотвеченных запросов или unmatched ответов. NXDOMAIN и SERVFAIL соответствуют
явным отрицательным проверкам. Raw loopback AF_PACKET capture содержит
дубли UDP; счётчики DNS в итоговом JSON берутся из TUN captures.

Ранее необъяснённый физический combo DNS-сбой не повторился. Эти два успешных
прогона не устанавливают его причину и не заменяют длительную WAN-приёмку.

## Сборка и дополнительные проверки

Production engine пересобран на обоих физических узлах. VPS: один job,
ограниченный cgroup и собственный временный swap, затем swap удалён. Radxa:
два jobs без low-memory; host swap/часы/boot config не менялись.

Старые CMake caches сначала не содержали новых DNS-test targets; выполнен
явный configure. GCC12 Radxa выявил array-bounds warning в тестовом vector
insert: helper теперь заранее выделяет кадр, без отключения `-Werror`.
Production framing от этого не менялся.

Новые DNS/TCP framing tests и существующая DNS relay regression прошли на обоих
узлах в `PrivateNetwork=yes`: partial I/O, EINTR/EAGAIN, cancellation, 100
запросов, saturation и FD cleanup. На Radxa CTest14/14. На VPS сначала13/14,
один `Not Run` из-за отсутствующего address-offer executable; после его сборки
отдельная проверка прошла1/1 — все14 тестов выполнены, без скрытых пропусков.

Следующий этап: отдельное решение о применении нового TLS-доверия к daily
клиентам; для combo — более длительное WAN-наблюдение в том же изолированном
стенде. Тестовый успех не является автоматическим переключением эксплуатации.
