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

## Оставшаяся связь с установщиком

Следующий конкретный этап — live OS factories и entrypoint с fixed layout:
проверка root-owned кода/конфигов, текущего ownership/profile и inherited lock;
root-pinned команды ОС с наследованием lock мутирующим subprocess; system bus
и readiness непривилегированного adapter; VPS2 cloud-name policy и резервирование
адреса owned link; Radxa include/daemon ownership и согласованный здоровый
baseline. VM-only gates нельзя просто удалить или заменить пользовательским
флагом. Затем — реальные controller units и единая транзакция
install/activate/disable/uninstall с [файловой частью](dns-deployment-files.md).

Только после проверки этой связки в VM можно готовить согласованные live-пилоты.
Ни перенос кода, ни его unit PASS не закрывают [DNS v1](dns-v1.md).
