# Команды ОС для DNS controller

`lib/dns-system-command.mjs` добавляет общий исполнитель для `ip`, `busctl`,
`systemctl`, `dnsmasq`. Он подключён к controller-путям двух изолированных VM.
Это **не live entrypoint** и не разрешение менять DNS обычного хоста: VM gates
сохранены. Внутренняя factory требует отдельно проверяемую authority вызывающего
entrypoint; импорт библиотеки сам по себе её не создаёт.

- Только фиксированные абсолютные пути, root-owned executable/parents без
  group/world write. Перед/после команды проверяются identity, mode и изменение
  executable/symlink; обычные изменения соседних файлов в каталоге не ломают pin.
- Нужен уже удерживаемый собственным PID exclusive whole-file flock из
  `/run/clean-vpn-dns-guard/lock`. Дочерняя команда наследует тот же open file
  description на fd3, а не приобретает вторую независимую блокировку.
- Нет shell и унаследованного окружения. Ограничены argv, время, общий объём
  stdout/stderr; stdout проверяется как UTF-8. Ошибки subprocess возвращают код,
  не исходные аргументы, пути или stderr.
- Таймаут/отмена останавливают process group; при завершении лидера убираются
  оставшиеся процессы его группы. Это рассчитано на доверенные системные tools,
  не является sandbox для произвольной программы, которая намеренно делает setsid.
- Убийство только контроллера оставляет lock за ещё работающим helper. Это не
  даёт новому контроллеру одновременно начать изменение сети. Если убита вся
  группа/служба, восстановление опирается на durable intent и фактический readback.

`lib/dns-system-bus.mjs` использует фиксированный системный socket, запрещает
auto-start/interactive authorization и адресует setters уникальному bus owner.
Допустимы только канонические `SetLinkDNSEx`, `SetLinkDomains`,
`SetLinkDefaultRoute`. D-Bus route-only root — `['.', true]`, не строка `~.`.
Void setter может вернуть пустой stdout; результат подтверждается журналом и
повторным чтением состояния, а не содержимым stdout.

Важно: resolved/systemd **не наследуют flock клиента**. Таймаут `busctl` или
`systemctl` не доказывает отмену уже переданной daemon-операции. Неподтверждённый
intent остаётся неоднозначным состоянием, guard сохраняется; нельзя автоматически
считать setter не выполненным, откатывать или запускать противоположную команду.
Сервисы, которые сами требуют тот же lock, нельзя запускать синхронно под ним.
Radxa controller здесь управляет только dnsmasq, не запускает boot/controller unit.

## Проверки

```bash
node --test scripts/test-dns-system-command.mjs scripts/test-dns-system-bus.mjs
```

14/14 PASS: реальный flock и наследование fd, SIGKILL контроллера с продолжающим
работу helper, отказ конкурирующему flock, освобождение после завершения helper,
shared/no-lock отказы, bounded timeout/output/abort, очистка окружения, redacted
ошибки, fixed D-Bus endpoint, ограничения setters и malformed replies.
Эти проверки не меняют настройки DNS/сети хоста.

Полная Node-регрессия:1754/1754 PASS, без skips,
`/var/tmp/meshpn-acceptance-KtWLX3/report.json` (2026-09-27).
Новый VPS2 lifecycle:19/19 PASS в двух загрузках,
`/var/tmp/meshpn-dns-vm-JvWiYh/report.json`; все482 JS-копии совпали с рабочим
срезом. Baseline queries0 под защитой, positive control и explicit disable PASS,
host DNS unchanged. Этот прогон включает предыдущий one-shot guard binding fix.

Первый параллельный Radxa запуск
`/var/tmp/meshpn-dns-vm-bNmubT/report.json` остановился **до нового controller**:
adapter startup readiness получил `DNS_TIMEOUT` (1556мс при лимите1500мс).
Это сохранённый FAIL, не результат проверки командного backend. Лимит не увеличен.
Отдельный повтор того же кода:20/20 PASS в двух загрузках,
`/var/tmp/meshpn-dns-vm-Z8KVkG/report.json`, все482 JS-копии совпали. DHCP сохранён
при отказах exit/adapter, dnsmasq SIGKILL восстановлен; guard release подтверждён
после возврата localhost baseline и работающего restored daemon. Baseline queries0
под защитой, positive control PASS, host DNS unchanged.

Оба успешных прогона — x64/systemd255, NIC-less TCG. Это не native arm64 Radxa,
не живой resolved249 на VPS2 и не новый прогон whole-guest power-cut матриц.

Следующая граница: fixed-layout installed OS authority/entrypoint и соединение
с opt-in установкой/откатом. Наличие этого executor не заменяет проверку владельца
DNS, readiness adapter, политику внутренних имён VPS2 и здоровый baseline Radxa.
