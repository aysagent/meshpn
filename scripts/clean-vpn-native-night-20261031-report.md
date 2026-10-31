# Результат ночной очереди 31 октября

Сначала восстановлено управление интернетом на Radxa. Затем выполнены основные
семь этапов очереди в изолированной лаборатории. Новые native-бинарники этой
ночи на рабочую пару не устанавливались. Коммиты и push выполнялись на Mac,
сеть Mac не перенастраивалась.

На Radxa установлен ремонт `44f2bb5`. Последующие diagnostics/HTTP-profile/
profile-evidence UI изменения имеют лабораторную приёмку и пока туда не доставлены.

## Исправление Radxa

Причина отказа — устаревший systemd sandbox path у admin broker после перехода
на `combo-daily`. Config был read-only; неудачный rollback оставлял engine
остановленным при работающей защите выхода. Исправлены installer, доступность
broker при неудачном recovery, повторный start и управление из UI.

[Подробный отчёт и физическая приёмка](clean-vpn-native-admin-repair-20261031.md):
исправление `44f2bb5` установлено штатным updater, **9 физических gates** после
обновления. Проверены DNS/HTTPS через combo, stop/start/restart, сохранение
при остановленном VPN, guard off с настоящим прямым USB-выходом, затем
guard on + VPN start. Конечное состояние — combo и защита включены, без pending
journal. VPS не перезапускался. Приватная резервная копия осталась на Radxa.

Админка теперь показывает установленный `combo-tls`. Переключение транспорта
через dropdown ещё не реализовано: прежний неверный disabled `boring-tls`
selector удалён. TLS без SNI в transparent сейчас отклоняется; HTTPS с доменным
SNI прошёл. Автоматического прямого обхода для этого ограничения не добавляли.

Для прямого интернета: снять «Kill switch», нажать «Применить защиту» и
подтвердить прямой выход; операция останавливает VPN и очищает его маршруты/DNS.
Отдельная кнопка «Выключить VPN» сохраняет защиту. После загрузки платы штатная
защитная служба снова включается — это явно указано в UI.

## Лабораторные результаты

| Этап | Проверка и результат |
| --- | --- |
| Точный daily binary | [30 минут, четыре клиента](clean-vpn-native-daily-soak-20261031.md), 14073 mixed rounds, quota isolation, освобождение ресурсов, без restart |
| Потери и аварии | [Netem/crash](clean-vpn-native-netem-20261031.md): delay/loss/reorder/blackout, обе ветки combo, SIGKILL/recreate и cleanup |
| Диагностика | [Typed relay/packet/H2/DNS counters](clean-vpn-native-diagnostics.md), строгие readers, PID/InvocationID scope, CTest 14/14, controllers 49/49 |
| HTTP-мимикрия | [Bounded profile](clean-vpn-native-http-profile-20261031.md): UA H1/H2, H2 pseudo-header order, SETTINGS 3 opt-out, независимая wire-проверка |
| Доказательства профиля | [UI/evidence](clean-vpn-native-profile-evidence-20261031.md): SHA, import receipt, configured/saved distinction, ограничения; 15 tests и Chromium |
| Enrollment | [28 Linux-проверок](../fixtures/clean-vpn-native-enrollment-20261031.json), актуальный HTTP-профиль, 32 клиента, H1/H2, fixed/discovery, rotate/import/connect |
| Контейнеры | [Managed Compose/Alpine](clean-vpn-native-containers-20261031.md): 12 managed + 17 combo + 10 wire/enrollment; отдельный [30-минутный musl soak](clean-vpn-native-musl-http-soak-20261031.md), четыре клиента, 14106 rounds |
| amd64 | [Static build](../fixtures/clean-vpn-native-amd64-http-20261031.json), CTest 14/14 и 64 native tests в NIC-less x86 VM, затем H1/H2/auth внутри настоящего OpenWrt |

В сравнении HTTP отдельно видны совпавшие UA, pseudo-header order и порядок
SETTINGS. Полное сравнение H2 prefix остаётся рядом и показывает
различия в окнах, прочих headers, приоритете, методе и HPACK. Совпадение трёх
выбранных полей не объявляется неотличимостью от браузера.

Точное daily executable, новый diagnostic glibc runtime, новый HTTP glibc runtime,
musl/ARM64 и musl/amd64 — разные артефакты. Их SHA и source context записаны в
отдельных receipts. Успешный soak одного бинарника не переносится на другой.
Ни quota, ни memory limits ради профиля не увеличивали. Browser priority пока
не поддержан. `ServerHello` в relay не доказывает успешный HTTPS-запрос приложения.

## Резерв OpenWrt

Официальные OpenWrt 25.12.6 VM x86/64 и ARMv8 прошли boot/procd/UCI,
SIGKILL/respawn/stop. У VM нет NIC и host share, root disk disposable snapshot.
Generic static amd64 native прошёл config/capabilities и H1/H2/неверный PSK
через fixture FD, затем normal TUN и native procd supervision.

**[Engine-only SDK APK](clean-vpn-openwrt-sdk-20261031.md) обеих архитектур
готовы и прошли настоящие OpenWrt VM:** установленный SHA, normal TUN H1/H2,
ошибочный PSK с нулевыми packet counters, удаление маршрута/stop, native procd
SIGKILL/новый client PID при прежнем exit PID и восстановление пакетов.
APK-прогоны не используют FD fixture. VM удалены, test state очищен; пакеты
и manifests сохранены локально под `native/clean_vpn/build/openwrt-20261031/`.
Это ещё не WAN/DNS/network owner/reboot acceptance.

Исходный local SDK engine-only package и актуальная приёмка описываются в
[openwrt/README](../openwrt/README.md). Полная интеграция LuCI, UCI/procd,
netifd/fw4/DNS, захват профиля и независимый observer остаются следующими
этапами [OpenWrt-плана](clean-vpn-openwrt.md).

После завершения пять собственных ночных lab/build containers остановлены;
их images, volumes и compile/source caches сохранены. Два прежних peer-reload
контейнера не трогали. Все созданные OpenWrt VM удалены с проверкой cleanup.
Failed-attempt logs оставлены отдельно, как и подробные source/binary receipts.

## Что дальше

1. Отдельный этап обновления native daily на уже проверенный артефакт,
   с физическим повтором управления, DNS, guard off/on и холодной загрузки.
   Текущая ночная лабораторная приёмка не выполняет такое обновление автоматически.
2. Совместимость combo: TLS без SNI и корректная политика маршрутизации такого
   потока без прямого обхода; затем управляемое переключение готовых transport
   installations в админке с полной проверкой и восстановлением.
3. Browser fidelity: оставшиеся H2 различия по измеримому bounded contract,
   перенос стабильных UA/pseudo-header order из capture в новый candidate
   (сейчас новый HTTP-профиль подготовлен явно), resumed/HRR/ALPS сценарии,
   независимый observer для конкретного соединения.
4. OpenWrt v1: normal TUN/procd foundation уже проверен; теперь нужен сетевой
   adapter, WAN/DNS/kill switch и reboot recovery, затем backend/ACL/LuCI
   с полным capture/profile/observer набором. Engine-only APK не выдаём за это.
