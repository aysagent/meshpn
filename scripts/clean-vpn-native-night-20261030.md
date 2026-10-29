# Ночь 30 октября: выполнение плана

Пользователь разрешил продолжать все этапы самостоятельно до завершения либо
его остановки утром, включая параллельную работу. Физическая daily-пара и сеть
Mac не переключаются; новые экземпляры — только с сетевой изоляцией.

1. Управление клиентами: реализован manager/CLI, автоподбор стабильного IP,
   отдельные packet/relay keys, export/import, revoke/rotate/rename, journaled
   rollback и recovery. 13 manager checks и 4 real-native enrollment scenarios
   passed. [Инструкция](clean-vpn-native-clients.md).
2. Hot reload exit: реализован, native reload 5/5, CTest 13/13, текущая широкая
   регрессия прошла. Manager с реальным systemd/journal 9/9.
3. `.mpn`: bounded loopback UDP/TCP resolver готов и проверен; отдельный journalled resolved scope прошёл 23/23 настоящих systemd checks.
   Клиентский NSS→native TLS→exit bridge→registry прошёл 11/11, включая
   отсутствие public fallback и запрет WAN/spoofed source. Идёт stress и Compose. [Документ](clean-vpn-native-peer-dns.md).
4. Админка: API/UI и role/capability controls реализованы, тесты и Chromium DOM
   прошли. Отдельный localhost installer exit прошёл 9/9 для boring и 9/9 для combo:
   web→broker→native без restart VPN. [Установка](../admin/EXIT-INSTALL.md).
5. Combo/transparent: 15-минутный mixed soak четырёх клиентов прошёл: 6948
   успешных раундов, 128 relay slots, нет роста RSS после освобождения ресурсов.
   Netem/crash/health — 21/21. Физический transparent smoke — 8/8 TLS
   и 8/8 JA3/JA4/ALPN через внешний Radxa wlan0 pcap; production не менялся.
   Один ранний timeout остаётся ограничением, это не длительная WAN-приёмка.
6. Общий Compose: supervisor/broker и web прошли 7/7 Alpine integration checks;
   Docker daemon отдельно пока не проверен.
7. Alpine: arm64 musl build/CTest 13/13, native 48/48, nft/legacy runtime
   по 20/20. Эти результаты до private DNS delta; новый delta прогон в работе.
   amd64 build пока блокируется отсутствием исполняемого x86 runtime в этой VM.
8. Резерв в работе: authenticated address offer codec готов, discovery/owner
   интеграция дальше. Offline leaf renewal под прежним CA — 10/10 с настоящим
   native H1/H2. Admin certificate dates и allowlisted diagnostic export готовы,
   admin regression 47/47 и Chromium DOM. Продолжаются docs и долгие проверки.

Состояние обновляется по мере приёмки; эта запись не заменяет итоговый отчёт.
Изменения в `device/` ведёт отдельная работа пользователя — не включать в наши
коммиты и не откатывать.
