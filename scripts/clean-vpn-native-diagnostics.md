# Native: packet, relay и DNS диагностика

[Приёмка и binary hashes](../fixtures/clean-vpn-native-diagnostics-20261031.json).
Новый лабораторный checkpoint 31 октября. Рабочие Radxa/VPS после ремонта
админки этой сборкой **не обновлялись**.

Engine экспортирует capability `diagnostics`: schema 1, событие `diagnostics`,
service interval 30 секунд. Обычные `state`/`status` сохраняют прежние семь полей.
В non-service control stdin доступна команда `{"op":"diagnostics"}`; это только
метаданные, не packet IPC. Service mode по-прежнему игнорирует stdin.

## Что измеряется

- Packet: число переходов в ready, окончаний сессий и последняя фиксированная
  причина. Нормальное завершение/GOAWAY тоже считается окончанием сессии,
  поэтому `session_ends` не означает число ошибок.
- Relay: accepted/completed/failed либо dispatcher selections/rejected,
  admission drops, активные/pending соединения. На клиентском listener также
  peak queue bytes и число poll-итераций с backpressure.
- Фазы отказов: redirect metadata, ClientHello, authorization, upstream connect,
  TLS prefix, encrypted stream, dispatcher, internal. Последний отказ содержит
  только фиксированный code, phase и monotonic milliseconds.
- Idle, drain и абсолютный lifetime теперь имеют разные reason codes. Их
  прежние бюджеты не изменились. `encrypted_stream` означает пересылку после
  ServerHello; relay не расшифровывает приложение и не проверяет его сертификат.
- DNS: queries, validated answers (включая отрицательные ответы), SERVFAIL после
  исчерпания upstreams, private queries, upstream attempts/errors/timeouts.
  Некорректные и policy-отклонённые запросы не обязаны входить в answers/SERVFAIL.

Все счётчики process-local и сбрасываются при restart. Снимок нескольких atomic
полей не является одной транзакцией: во время нагрузки значения могут быть
сняты в соседние моменты. Имена DNS, destinations, SNI, payload и ключи в этих
метриках отсутствуют. Это самодиагностика, **не независимый wire-observer**.

## Админка и controllers

Host broker читает ограниченный журнал только текущих `_PID` и
`_SYSTEMD_INVOCATION_ID`, кеширует на пять секунд, отклоняет старые/будущие
samples. Native sample старше 120 секунд не выдаётся как актуальный. Отсутствие
нового события у старого binary показывает `unavailable`, не нулевые «ошибки».
Container broker читает stdout своего child и сбрасывает snapshot при restart.

UI и диагностический export используют отдельную проекцию разрешённых полей.
Строгие native/trial/clock readers принимают только известную схему и фиксированные
reason codes. Snapshot не создаёт новый ready transition и не ослабляет проверку
неожиданных payload fields. Capability/профиль/pcap остаются отдельными источниками.

## Приёмка и ограничения

- ARM64 Linux source build и CTest **14/14**: реальные relay fault workers,
  hello/authorization и handshake/stream phases, отдельные timeout reasons,
  конкурентное обновление фиксированных счётчиков и отсутствие произвольного
  текста в reason.
- Реальные native H1/H2 packet/auth/reconnect и service metadata — **3 сценария**.
  В service diagnostic test два отказа распределились между ClientHello и
  authorization, `originConnects=0`, sample пришёл примерно через 30 секунд.
- Native DNS — **2/2**: оба peer IPv4, UDP/TCP/private deadlines, no public fallback,
  counters, cleanup. Один первоначальный прогон упал на мгновенном финальном
  подсчёте `/proc/self/fd`/`task`; причина того снимка не доказана. Текущая проверка
  требует тех же точных границ в окне до 500 мс и печатает различие при его наличии;
  это не заявление об исправленной утечке production engine.
- Strict controllers/trial/crash: **49/49 в Linux**, включая настоящие
  tcpdump/netns и route recovery, без skips. Первоначальные два macOS skips не
  выдаются за Linux приёмку.
- Projection/current invocation/privacy, container reset и связанные API tests
  прошли; Chromium DOM проверил combo label, guard UI и вывод счётчиков.

Пакеты данных, DNS upstream budgets, relay limits, trust, replay и криптография
не менялись. Эта диагностика объясняет наблюдённый этап отказа; она сама по себе
не устанавливает первопричину WAN потерь или upstream TLS disconnect.
