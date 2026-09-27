# Общий клиентский DNS controller

`lib/dns-client-controller.mjs` — общий исполнитель команд `start` и `disable`
для VPS2 и Radxa. Он уже вызывается обоими VM workers, вместо двух копий
координации. **Это библиотечный контроллер, не live CLI и не установщик.**
Factory доступа к ОС, фиксированные пути и process-lifetime flock обязан
проверить вызывающий entrypoint. Текущие VM factories сохраняют прежние проверки
изолированного гостя; запреты на выполнение их на обычном хосте не сняты.

## Порядок действий

1. Выбрать явно `vps2` или `radxa` и `start` либо `disable`. Неизвестный профиль,
   `stop` или неявный `recover` отклоняются до factory. Одна команда на instance.
2. Создать backend guard под общим DNS/boot lock. Профиль проверяется против
   установленной boot policy. В callback передаётся проверка наличия **любого**
   относящегося к профилю DNS journal; dangling journal symlink тоже считается
   существующим состоянием, а не разрешением новой привязки.
3. Подтвердить guard, лишь затем создать/проверить private journal directory и
   получить DNS backend. Отказ guard не вызывает DNS context factory/storage.
4. `start` без root journal вызывает `enable`, с apply journal — `recover`.
   Restoring/restored/released journal не превращается обратно в start: требуется
   явное `disable` или отдельное review новой эпохи. Child journals/snapshots
   проверяются соответствующей транзакцией и не усыновляются автоматически.
5. `disable` запускает обратную DNS-транзакцию. VPS2 освобождает guard только
   после подтверждения удаления owned DNS-link и двух released journals. Radxa
   paired coordinator сохраняет guard, а внешний controller отдельно проверяет
   три restored journals, localhost-file baseline и актуальный loaded dnsmasq;
   только потом разрешает release. Dangling baseline — отказ.

Release verifier выбирает сам общий controller (`verifyCoupledGuardRestore` или
`verifyRadxaGuardRestore`), а не произвольный `() => true` в service wrapper.
Verifier заново читает журналы и состояние ОС при каждом вызове guard lifecycle.
Успешный результат содержит профиль, команду, transaction ID и актуальное
`protectionRetained`: после успешного disable оно false. Это runtime release,
**не** снятие boot policy/dropins и не постоянный uninstall.

Остановка процесса/службы не является командой disable. Автоматического
разблокирования DNS, принятия старого boot/context или запуска фонового watcher
этот модуль не добавляет. Наличие live factory/lock нельзя подменять корректным
JSON либо самим фактом импорта этой библиотеки.

## Проверка

```bash
npm run test:dns-client-controller
node --test scripts/test-dns-client-controller.mjs scripts/test-dns-coupled.mjs scripts/test-dns-radxa.mjs scripts/test-dns-vm.mjs
```

Второй набор:218/218 PASS. Включает новые общие lifecycle tests с настоящими
file journals для двух профилей, отказ возвращаться из restore в start, реальный
выбор restore proof (включая отказ dangling Radxa), порядок guard/storage,
неизвестные команды и dangling journal. Модель ОС в unit tests не заменяет VM.
Node-регрессия1735/1735 PASS, без skips,
`/var/tmp/meshpn-acceptance-mCnlAj/report.json` (2026-09-27).
Новый VM lifecycle общего контроллера: VPS2 **19/19 PASS в двух загрузках**,
`/var/tmp/meshpn-dns-vm-NGWKRQ/report.json`; Radxa **20/20 PASS в двух загрузках**,
`/var/tmp/meshpn-dns-vm-gVjWqh/report.json`. В обоих baseline queries0 под защитой,
positive controls пройдены, host DNS unchanged. Все474 JS-копии соответствуют
срезу выделения контроллера. Старые crash-результаты до выделения модуля не
выдаются за новый прогон его snapshot. Это x64/systemd255 VM, не живые клиенты.
Срез этих двух VM — `059ff0d`. Последующее исправление одноразового первоначального
guard binding проверено отдельно:57/57 unit, Node1740/1740 (`meshpn-acceptance-Ukdj9G`),
без повторного VM-прогона. Детали и граница доказательств —
[guard journal](dns-client-guard-journal.md).

## Оставшаяся связь с установщиком

Общий [исполнитель команд ОС](dns-system-command.md) уже подключён к VM controller:
фиксированные root-pinned tools, system D-Bus и наследование общего flock
дочерними командами. Обычные host/namespace gates не ослаблены; это не live CLI.
Эта связка повторно прошла VPS2:19/19 (`meshpn-dns-vm-JvWiYh`) и Radxa:20/20
(`meshpn-dns-vm-Z8KVkG`), каждый в двух загрузках; Node1754/1754 PASS. В обоих
образах все482 JS-копии совпали. Срез включает одноразовый guard binding fix.
Первый отказ readiness Radxa и ограничения доказательств сохранены в описании
исполнителя; новые whole-guest power-cut матрицы этим не заявляются.

Следующий конкретный этап — live OS factories и entrypoint с fixed layout:
проверка root-owned кода/конфигов, текущего ownership/profile и inherited lock;
подключение проверенного command runner/system bus и readiness непривилегированного
adapter к установленной конфигурации; VPS2 cloud-name policy и резервирование
адреса owned link; Radxa include/daemon ownership и согласованный здоровый
baseline. VM-only gates нельзя просто удалить или заменить пользовательским
флагом. Затем — реальные controller units и единая транзакция
install/activate/disable/uninstall с [файловой частью](dns-deployment-files.md).

Начата [отдельная installed-authority проверка](dns-installed-authority.md):
opt-in привязывает client/guard ID к hash bundle/config, loader проверяет fixed
entrypoint, root-owned файлы, namespaces/interpreter и inherited lock.23 local
tests PASS; есть только read-only main `--inspect`, положительный installed
VM-путь ещё не проверен, mutating commands/factories пока не подключены.
Boot policy сама по себе разрешением DNS takeover не стала.
Полная Node-регрессия1803/1803 PASS (`meshpn-acceptance-nrWdSd`), без skips;
эта проверка не заменяет installed VM lifecycle.

Только после проверки этой связки в VM можно готовить согласованные live-пилоты.
Ни перенос кода, ни его unit PASS не закрывают [DNS v1](dns-v1.md).

Для Radxa добавлен [public resolver backend](dns-resolver-object.md): readable
resolver и private snapshots/journal разделены; VM больше не делает весь `/etc`
каталогом0700 и проверяет NSS от UID65534. Это файловая часть будущей OS factory,
не live authority. После сохранённых отказов startup новая VM прошла
26/26 в двух загрузках (`meshpn-dns-vm-L5itxn`, `1de98a7`): NSS/recovery/private
state, host DNS unchanged. Новая crash-матрица также прошла3/3, шесть загрузок,
по12 проверок (`meshpn-dns-vm-ZqbtFB`, `c3ccc0c`, уже с TCP noDelay).
Причина прежней нестабильности timing этим не доказана. Эти образы не включают
последующую installed-authority логику. Подробности — в resolver object выше.
Установщик должен выбрать same-mount
расположение snapshots относительно target (журнал может быть отдельно),
проверить реальные config sources dnsmasq и установленный здоровый baseline.
Публиковать resolver ссылкой внутрь0700 state по-прежнему нельзя.
