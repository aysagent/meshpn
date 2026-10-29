# Ночь 30 октября: выполнение плана

Пользователь разрешил продолжать все этапы самостоятельно до завершения либо
его остановки утром, включая параллельную работу. Физическая daily-пара и сеть
Mac не переключаются; новые экземпляры — только с сетевой изоляцией.

1. Управление клиентами: реализован manager/CLI, автоподбор стабильного IP,
   отдельные packet/relay keys, export/import, revoke/rotate/rename, journaled
   rollback и recovery. 17 manager checks и 8 real-native enrollment scenarios
   passed. [Инструкция](clean-vpn-native-clients.md).
2. Hot reload exit: реализован, native reload 5/5, CTest 13/13, текущая широкая
   регрессия прошла. Manager с реальным systemd/journal 9/9.
3. `.mpn`: bounded loopback UDP/TCP resolver готов и проверен; отдельный journalled resolved scope прошёл 23/23 настоящих systemd checks.
   Клиентский NSS→native TLS→exit bridge→registry прошёл 11/11, включая
   отсутствие public fallback и запрет WAN/spoofed source. Пятиминутный stress:
   633 раунда, минимум 17724 запроса, 64 рестарта resolver, без public fallback.
   Исправлена registry ABA-гонка при rollback; отдельные process-boundary тесты
   подтверждают исправление. Compose DNS/NSS тоже принят. [Документ](clean-vpn-native-peer-dns.md).
4. Админка: API/UI и role/capability controls реализованы, тесты и Chromium DOM
   прошли. Отдельный localhost installer exit прошёл 9/9 для boring и 9/9 для combo:
   web→broker→native без restart VPN. [Установка](../admin/EXIT-INSTALL.md).
5. Combo/transparent: 15-минутный mixed soak четырёх клиентов прошёл: 6948
   успешных раундов, 128 relay slots, нет роста RSS после освобождения ресурсов.
   Netem/crash/health — 21/21. Физический transparent smoke — 8/8 TLS
   и 8/8 JA3/JA4/ALPN через внешний Radxa wlan0 pcap; production не менялся.
   Один ранний timeout остаётся ограничением, это не длительная WAN-приёмка.
   Дополнительно [30 минут Alpine combo](clean-vpn-native-alpine-soak.md): 14013
   успешных смешанных раундов, четыре клиента, 319 samples, без рестарта native,
   роста RSS или потери доступа других клиентов при заполнении квоты одним.
6. Общий Compose: supervisor/broker и web прошли 7/7 базовых Alpine checks;
   с private DNS sidecar — 11/11 в Podman и 11/11 в настоящем Docker Engine
   28.5.2 / Compose 2.40.3, ARM64 Linux. [Docker evidence](clean-vpn-native-docker-compat.md).
   Исправлен перехват контейнерного DNS с uplink-маршрутом; разрешение действует
   только после DNAT и только к уже локальному адресу, до TUN выход закрыт.
   Финальный discovery + private DNS stack — по 12/12 в Podman и Docker:
   реальный адрес `.3`, неизменённый source config, повторный запуск и SIGKILL.
7. Alpine: начальная arm64 musl приёмка — CTest 13/13, native 48/48,
   nft/legacy runtime по 20/20. После DNS/discovery — CTest 14/14,
   managed Compose по 12/12. Исправленная signal-safe сборка отдельно прошла
   [Docker 12/12](../fixtures/clean-vpn-native-docker-signal-fixed-20261030.json).
   Для amd64 поднята отдельная offline QEMU VM без NIC/binfmt: Alpine/GCC
   уже работают, полная сборка из проверенных APK и pinned sources идёт.
8. Резерв: authenticated address discovery/session proof готов; native 75
   уникальных JS-сценариев, включая конкурентный reload; ASAN/UBSAN/LSan 34/34.
   Изолированный Linux owner — по 8/8 nft и legacy: TUN/NSS, повторный запуск, отказ при смене
   адреса, неверный ключ, IPv4/IPv6 bootstrap guard и новая namespace.
   Контейнерная упаковка discovery принята. Offline leaf renewal под прежним CA
   и review — 12/12 с настоящим native H1/H2; исправлена гонка изменения `--trust`.
   Admin certificate dates и allowlisted diagnostic export готовы,
   admin regression 47/47 и Chromium DOM. Продолжаются docs и долгие проверки.
   Discovery/full ClientHello сверены независимым observer с сохранённым
   частичным Chromium-профилем. Отказ по сроку сертификата/clock-skew проверен
   без изменения часов; автоматического SSH-time recovery у isolated owner нет.

Дополнительный [ThreadSanitizer](clean-vpn-native-tsan.md) обнаружил межпоточную
гонку флагов сигналов. Исправление `400e7d8` (lock-free atomic reload/stop)
прошло воспроизводимый before/after test, 14 native сценариев, quota/DNS units
и настоящий DNS churn 12/12. Финальный native snapshot включает это исправление;
предыдущие отчёты сохраняют собственные source/binary SHA.

Состояние обновляется по мере приёмки; эта запись не заменяет итоговый отчёт.
Изменения в `device/` ведёт отдельная работа пользователя — не включать в наши
коммиты и не откатывать.
