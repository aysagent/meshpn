# Native boring-tls: подготовка без физических узлов

Обновление 2026-10-27: после отдельного разрешения и подключения Radxa выполнен
[ограниченный физический пилот](clean-vpn-native-daily-pilot.md#физический-checkpoint-2026-10-27).
Smoke/crash/uplink/hold прошли, временные изменения возвращены. Ниже сохранена
граница предыдущего локального этапа; она не запрещает этот уже разрешённый
пилот. Постоянная установка остаётся невыполненной. Открыты cold-clock bootstrap,
реальный DNS/DHCP контракт и постоянный existing-host lifecycle/boot acceptance.

2026-10-27. Авторизованный следующий объём: локальные инструменты и выделенная
Podman/QEMU лаборатория. Без SSH на Radxa/VPS, без изменений Wi-Fi, маршрутов и
DNS Mac, без постоянной установки на физических машинах.

## Выполнено

[Машиночитаемый отчёт](../fixtures/clean-vpn-native-local-readiness-report.json)
содержит хеши фактически проверенных файлов, бинарника, pcap и сырых отчётов,
а также историю неудачных прогонов. Implementation checkpoint: `0b5ba17`.

- Генератор `clean-vpn-native-runtime-config.mjs`: private CA/cert, отдельный PSK
  на клиента, Chromium subset, container/standalone пути, без сетевых изменений.
- `clean-vpn-native-gateway.mjs`: явный ingress/bridge/table, preflight,
  bounded apply, status, журнал, flock и независимый recovery. Исполняется
  только в уже созданном выделенном Linux netns; physical host не разрешён.
- Настоящий dnsmasq: localhost/USB DNS UDP/TCP через exit; старые direct upstream
  блокируются; владелец fixture явно меняет upstream. Реальные DHCP OFFER/ACK
  содержат router и один DNS option 6 — gateway. Lease на интерфейс probe не
  применяется; USB/WG hardware не имитируется.
- Offline systemd unit renderer: native `Type=notify`, engine restart,
  bounded gateway `ExecStopPost` rollback. Проверены SIGKILL, setup/recovery cuts,
  отказ при foreign drift и совпавших маршрутах без случайного ownership tag.
- Новый `clean-vpn-native-runtime-preflight.mjs` выдаёт один read-only отчёт;
  [команды подготовки и запуска](clean-vpn-native-runtime.md),
  [gateway/DNS контракт](clean-vpn-native-runtime-host-wiring.md) описаны отдельно.

Проверки: **16/16 unit**, **39 + 41** checks в двух boot QEMU с persistent
credentials и отказом старого журнала; **40/40** в финальном single-boot
systemd regression после дополнительного ownership predicate. Последняя
проверка не выдана за повторный reboot финальной ревизии. **26/26** Podman
functional checks + successful cleanup. Docker в этом шаге не повторялся;
его прежняя приёмка не изменена. C++ не менялся и не пересобирался: проверен
существующий cache binary, его SHA зафиксирован.

Независимый pcap подтвердил сохранённый Chromium subset и JA4
`t13d0915h2_f91f431d341e_54d72502093d`. Это частичный cold TLS профиль,
не доказательство полной неотличимости от браузера.

Ранние сбои не скрыты: исправлены EDNS layout fixture origin, minimal systemd
guest PATH/OpenSSL config, parent anchor в тестовом recovery и гонка IPv6 DAD
при строгом сравнении маршрутов. Подмена bound upstream-сокетов dnsmasq
заменена явным выбором upstream и UID guard. Native DNS parser не ослаблялся.

## Что осталось до физического повседневного запуска

1. Сверить выбранный узел с актуальным read-only отчётом: DNS owner/UID,
   effective dnsmasq/DHCP или resolved config, адреса, свободные ports/table и
   существующие guards/legacy services. Старые логи не считать текущим состоянием.
2. Подготовить принадлежащий проекту namespace/bridge и процедуру подключения
   реального ingress с сохранением rescue. Нынешний controller предполагает,
   что такой namespace уже подготовлен; физическое подключение не автоматизировано.
3. Ограниченный физический pilot с независимым rollback, затем отдельный
   согласованный вопрос постоянного старта, раннего boot guard и RTC.

DNS для нового runtime проверен в лабораторной топологии. **Универсальная
интеграция системного DNS на реальных Linux-клиентах этим не объявляется закрытой.**
Reboot гостя не заменяет power-loss и проверку early boot на физическом шлюзе.
До нового решения пользователя выполнять только локальную работу и lab;
постоянная установка на Radxa/VPS остаётся запрещённой текущим scope.

## Исходная последовательность

Последовательность и критерии:

1. **Комплекты конфигурации.** Offline CA/cert, отдельные PSK для 1–32 клиентов,
   сохранённый Chromium subset, container `/config` или standalone абсолютные пути.
   Проверки прав, hostname/CA, запрет перезаписи, реальный engine check + handshake.
2. **Настраиваемый ingress.** Явные interface/subnet/private bridge/table/priority,
   read-only preflight, bounded apply, журнал, независимый recovery. Первый
   исполняемый контракт — выделенный Linux netns; physical host пока не разрешён.
   USB/WG подобные интерфейсы моделируются в VM. Проверить drop при потере engine
   или bridge, сохранение host/other-LAN/rescue и точный возврат чужих правил.
3. **DNS шлюза.** Настоящий dnsmasq с отдельным UID, loopback/USB listener и
   исходные upstream 1.1.1.1/8.8.8.8. Перехват ingress отдельно от DNS guard этого UID;
   явное переключение upstream владельцем dnsmasq, без подмены bound sockets.
   cache disabled в тесте, UDP/TCP, подтверждение upstream peer на exit,
   отказ без прямого fallback, восстановление. Не переписывать resolv.conf
   и не запускать resolved поверх существующего dnsmasq.
4. **Жизненный цикл.** Проверить bounded stop, SIGKILL, независимый ExecStopPost,
   конфликт владельца, прерывание setup, drift, повторный запуск и неверные часы.
   Reboot нового gateway контракта проверять отдельно; прежняя systemd/boot
   приёмка legacy/native site не считается доказательством для нового кода.
5. **Пакет будущего пилота.** Команды подготовки, preflight, run/status/stop,
   единый отчёт с границами приёмки. На физических узлах сейчас не исполнять.

Отсечка этого шага не равна законченной повседневной установке: ещё потребуется
согласовать реальных владельцев DNS/маршрутов и исполнить ограниченный пилот на
выбранном клиенте. Автоматический ремонт RTC и полная мимикрия не добавляются
в этот объём; неверное время по-прежнему должно приводить к TLS fail-closed.
