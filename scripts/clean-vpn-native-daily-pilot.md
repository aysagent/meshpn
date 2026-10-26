# Повседневный native boring-tls: ограниченный пилот

Уточнение scope 2026-10-27: постоянную установку/enable на Radxa и VPS пользователь
отложил. На узлах — только временные проверки с rollback. Новый приоритет:
[standalone и Docker/Podman runtime, лабораторная приёмка](clean-vpn-native-night-plan.md).
Ниже сохранён предыдущий план; его пункты постоянной физической миграции пока
не выполнять.


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

## Физический checkpoint 2026-10-26

[Отчёт](../fixtures/clean-vpn-native-daily-pilot-report.json): два ordinary smoke
и отдельный native engine SIGKILL прошли, каждый с возвратом legacy.
В каждом native этапе: host NSS, DNS A/AAAA по UDP/TCP, HTTPS и загрузка 1 MiB;
USB peer отдельно DNS/HTTPS/1 MiB с IP exit. Это функциональные IPv4 проверки,
не benchmark или комплексная приёмка всех утечек. При SIGKILL два контрольных
HTTPS запроса блокировались; wlan0 capture: 548 encrypted exit packets,
0 direct packets к 1.1.1.1:443, 0 kernel drops. Обычный stop дал четыре aggregate
engine drops, причина в этом счётчике не разделяется и не объявляется исправленной.

Внешний VPS pcap последнего ordinary smoke: 2214 пакетов, 0 capture drops,
первый native ClientHello matched по всем полям subset-профиля. JA4:
`t13d0915h2_f91f431d341e_54d72502093d`, совпадает с тремя лабораторными образцами.
JA3 конкретного физического соединения: `7b4778109c8248c68ad4a09bd287002f`;
порядок extensions переставляется, поэтому постоянство JA3 не обещается.
Legacy после rollback в том же pcap отмечен mismatch, а 505 пакетов соединения,
начавшегося до capture, проигнорированы без попытки угадать ClientHello.

Для capture на данном VPS рабочий вариант: обычный privilege drop tcpdump,
`-w -`, приватный файл открывает systemd через `StandardOutput=file:...`,
**обязательно** `StandardError=journal`. Запись stderr в тот же файл портит pcap.
Попытки `-Z root` завершались SIGSEGV; первопричина системного tcpdump не исследована.
Ранние повреждённые/пустые captures не использованы для выводов.
Raw pcap остаётся приватным на VPS, в git только структурированный отчёт.

Лаборатория: CTest 10/10, profiles/protocols 43/43; Linux control 95/95,
installer relocation 1/1; final local baseline/USB/pcap tests 39/39.
Старые VPS fixture-бинарники не пересобирались: их провалившийся полный прогон
не выдан за регрессию production engine; профиль проверен актуальными lab fixtures
и двумя физическими production binaries. Изменений C++ engine в этом шаге нет.

После старта временного exit NTP Radxa синхронизировался. RTC действительно
показывал 2017 год; после проверки NTPSynchronized=yes записано верное время,
повторное чтение спустя 12 минут корректно. Системные часы вручную не переводились.
Это ещё не проверка RTC после reboot или потери питания.

Временный exit и capture остановлены, собственный TUN/rules удалены; forwarding=1,
Docker/x-ui остались. Radxa legacy/guard/USB/SNAT активны. Постоянный native ещё
не установлен; после остановки exit интернет через него снова недоступен,
как до теста. Mac network settings не менялись, Podman lab остановлена.

## Следующая реализация: миграция существующего хоста

Это следующий приоритет вместо H2 throughput tuning. Нужен отдельный контракт,
а не снятие ограничений fresh-site installer:

1. Сохранить контрольные fingerprints текущих project units/config и enabled-state.
   Публиковать новый комплект и units выключенными; исходный legacy не удалять.
2. Exit: отдельный journal owner только TUN и трёх scoped forwarding/NAT rules;
   никакого takeover INPUT/OUTPUT, Docker/x-ui или resolved. SSH сохраняется.
3. Client: использовать существующие cvks4 и USB rescue; один владелец TUN,
   routes и DNS. Исключить одновременный legacy/native. SNAT service должен
   ждать новый защищённый tunnel lifecycle, без циклических systemd зависимостей.
4. Независимый ExecStopPost и startup recovery с проверкой boot/netns/ifindex;
   никаких blind flush или восстановления чужого snapshot целой таблицы.
   Проверить worker SIGKILL, а не только engine SIGKILL, в изолированной VM.
5. VM с непустыми foreign rules и настоящим systemd: start/stop/restart,
   отказ DNS/exit, crash cut-points, reboot, cold clock. Затем staged physical
   activation с bounded rollback, и только после проверок — постоянный enable.

Живые transient smoke не подменяют эти требования. HTTP Date bootstrap для C++
отдельно не реализован; RTC/NTP boot acceptance остаётся открытой.
