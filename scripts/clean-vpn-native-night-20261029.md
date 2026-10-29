# Автономная работа 29 октября: самостоятельный native lifecycle

Пользователь отменил требование бесшовной миграции со старого Node VPN.
Старые службы не являются поддерживаемым runtime или обязательной частью rollback.
Node допускается для админки и управления; сетевые пакеты, TLS и DNS — C++.

Итог: [единый отчёт и следующий этап](clean-vpn-native-night-20261029-report.md).
Последующее разрешённое действие завершено: [постоянная boring-tls пара и reboot Radxa](clean-vpn-native-daily-20261029.md).

## Очередь и критерии

1. **Готово, eae4630:** отдельный host-profile для существующего Radxa:
   TUN, маршруты, tunnel DNS, USB SNAT/MSS, журнал и независимый ExecStopPost.
   Итог: 21 real-netns проверка и 14 real-systemd сценариев в лаборатории.
   Начальная 18-case netns-матрица также прошла на ядрах Radxa/VPS с отдельными mount/net namespace
   и tmpfs `/run`; рабочая сеть физических машин не менялась.
2. **Готово, 5ebaf47:** cold boot с установленными службами, clock-profile и binary
   updater; откат плохого бинарника, crash recovery owner, отказ guard.
   NVM Node проверен на Radxa; delayed uplink/live down-up/gateway — в systemd.
   Дополнительный совместный time-fault gate завершён: три загрузки, 19 шагов,
   реальные SSH requests 3/0/1, native DNS и cleanup owner.
3. **Физические smoke прошли:** временная физическая проверка boring-tls Radxa ↔ VPS: подготовка выключенной
   установки, bounded activation, DNS/HTTPS, сохранённый TLS профиль и независимый
   pcap. Сохранить USB SSH и чужие правила/службы; по завершении убрать свой runtime.
4. **Готово:** расширенный soak 1 час в изолированном runtime: рестарты, DNS, соединения,
   RSS/FD/socket counters; ограничить время и трафик. Физический soak — только
   после успешного короткого сценария и с независимым ограничением времени.
5. **Готово, 2506b6c:** админка: start/stop/restart через сетевой owner, диагностика обеих служб,
   установка без обязательного присутствия legacy; выбор профиля с откатом.
6. **Podman и Docker повторно проверены:** Podman — 27 сценариев с часовой нагрузкой;
   Docker — 23 сценария, LAN ingress, independent capture и cleanup.
   Host-profile systemd и namespace runtime разделены.
7. **Резерв реализован в лаборатории:** scoped exit owner, несколько клиентов,
   combo lifecycle и входящие соединения для будущего public-proxy. Для входа
   добавлены opt-in persistent reconnect и точный INPUT grant. Boring/combo
   прошли отдельные systemd-матрицы; public-proxy/Caddy приложение не тестировалось.

## Границы

- Mac: код/Git/выделенная Podman-лаборатория; сеть, DNS, Wi-Fi и время не менять.
- Git-коммиты на Mac; доставка на узлы Git fast-forward, при недоступном GitHub
  — Git bundle по USB. Чужие `device/**` изменения не включать.
- Физические проверки временные; не включать новый постоянный VPN без отдельного
  решения. Никакого firewall flush, установки runtime на VPS ради проверки или
  отключения независимого guard. USB rescue остаётся доступным.
- Отчёт различает unit/kernel/systemd/VM/physical evidence. Успех без time fault
  не считается проверкой clock bootstrap; reboot VM не является power loss Radxa.
- После каждого законченного блока переходить к следующему самостоятельно.


Физический smoke выявил оставшиеся старые USB SNAT/MSS rules и ожидание общего
network-online. Старые правила убраны scoped helper; сетевой owner теперь
ориентируется только на свой uplink. Отдельно исправлен graceful stop во время
синхронной команды, проверено 11 systemd-сценариями. Повторный физический запуск прошёл: готовность 13.979 с, owner SIGKILL recovery
37.886 с; обе службы штатно остановлены, свои units удалены и bundles архивированы.
Финальная VM-матрица пары client/exit: 30 проверок / 3 загрузки, включая Result=success после stop.
Часовой [runtime soak](../fixtures/clean-vpn-native-runtime-soak-20261029.json) прошёл:
3612 с, 317 замеров, 12 рестартов и 27 проверок; cleanup passed. Отдельный network-owner soak прошёл: 900 с,
87 замеров, четыре SIGKILL. Итоговая systemd-матрица расширена до 14 проверок:
поздний uplink, live down/up и смена gateway восстанавливаются автоматически.

В bounded capture записано 20000 пакетов и 9 ClientHello; все matched partial
profile, kernel drops=0. Достигнут лимит capture — это не запись каждого
handshake за час. Client RSS 6212–6440 KiB, FD=7/socket=3; exit 5736–6360 KiB,
FD=6/socket=2; zombies=0. Это малая лабораторная нагрузка, не capacity benchmark.

Резервный [scoped exit owner](clean-vpn-native-exit-host.md) завершён: 23 kernel,
11 systemd и 32 общих regression tests; включён в 30-case boot-матрицу.
Отдельный физический smoke прошёл, exit owner SIGKILL recovery 11.143 с.
Постоянная установка на физическом VPS не активирована. Продолжение завершило
[multi-client host-profile](clean-vpn-native-host-network.md), scoped combo и
[входящий IP/mTLS путь](clean-vpn-native-incoming.md). Машиночитаемые отчёты
связаны из этих документов. Оставшиеся физические действия — постоянная
активация/привязка админки и power-loss/boot на реальной плате — отложены,
лабораторные результаты за них не выдаются.
