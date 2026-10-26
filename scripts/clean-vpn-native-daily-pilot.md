# Повседневный native boring-tls: ограниченный пилот

2026-10-26. Цель: Radxa client → VPS exit, native C++ packet path, сохранённый
профиль с частичной мимикрией и независимой проверкой wire. Это отдельная
приёмка; текущий файл не объявляет постоянную установку завершённой.

## Профиль

`fixtures/native-tls-profiles/chromium-156-bounded-cold.json` явно выведен из
сохранённого Chromium 156 Linux ARM64 capture. Рядом provenance с SHA-256
исходного capture и исполняемого JSON. Это не автоматическое обрезание захвата
импортёром и не точная копия браузера. Исходный capture остаётся неизменным.

Сохраняются порядок допустимых cipher suites, groups/key shares (включая
X25519MLKEM768), signature algorithms/ML-DSA, ALPN h2/H1, GREASE/ECH GREASE,
перестановка extensions, OCSP/SCT, Brotli и ALPS. Отличия перечислены явно:

- убраны шесть static-RSA/CBC suites по текущей политике;
- нет session-ticket extension 35 и trust-anchor 51764;
- только cold handshake, без resumption/0-RTT;
- H2 окна 1/1 MiB, concurrent streams 1, header list 8 KiB;
- carrier остаётся аутентифицированным POST, не браузерной навигацией;
- возможен padding 21, фактические fingerprints не нормализуются ради совпадения.

Поэтому JA3/JA4 должны соответствовать **этому сохранённому subset**, но не
исходному Chromium. GREASE и permutation не делают трафик неотличимым от браузера.
`browser_profiles:false` остаётся, experimental TLS profiles используются явно.

В transient client trial можно передать `--tls-profile=/root/private/profile.json`
через Mac USB coordinator. Путь относится к Radxa. Файл root-only, копируется
в private scratch до остановки legacy; engine проверяет профиль до wire.
Отчёт сохраняет ID и SHA-256 файла; внешняя проверка capture выполняется отдельно.
Установщик теперь копирует профиль в `/opt/clean-vpn-native/NAME/tls-profile.json`
и записывает его хеш в manifest: удаление исходного checkout не ломает профиль.

## Порядок и граница готовности

1. Проверить профиль real-TCP тестами, CA/name/PSK rejection и installer relocation.
2. Обновить код через git, проверить binary/config на обеих архитектурах.
3. Bounded ordinary boring-tls smoke с этим профилем; отдельный внешний
   ClientHello capture, host/USB DNS UDP/TCP и HTTPS, read-back rollback.
4. Отдельный crash smoke при работающем независимом guard и USB rescue.
5. Подготовить постоянные units под **существующие** network/DNS/guard owners.
   Лабораторный fresh-site installer с пустыми firewall tables не применять
   к живому VPS с Docker/x-ui или Radxa с USB gadget.
6. Проверить systemd stop/restart/crash, сохранность чужих rules, безопасный rollback;
   затем reboot в согласованном ограниченном сценарии с независимым доступом.
7. Закрыть часы: NTP через восстановленный туннель, сохранение последнего доверенного
   времени/RTC и поведение после cold boot. Node HTTP Date correction не перенесён
   в C++; никогда не обходить CA/hostname ради получения Date.

До пункта 7 это пилот, не завершённая повседневная установка. Полная мимикрия,
H2 queue tuning, tickets и trust anchors могут дорабатываться позже; контроль
утечек/восстановления/часов и проверка фактического применённого профиля обязательны.
