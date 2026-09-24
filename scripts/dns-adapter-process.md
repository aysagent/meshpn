# DNS adapter как отдельный процесс: namespace-only lifecycle

Следующий этап после [журнала resolved](dns-resolved.md): настоящий DNS adapter
запускается отдельным Node-процессом, убивается SIGKILL и поднимается снова на
**том же** `127.0.0.1:HIGH_PORT`. Контроллер, журнал, resolved, D-Bus и DNS guard
остаются живы. Это не установка службы и не изменение DNS/firewall/TUN хоста.

```bash
npm run test:dns-adapter-process
MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved npm run test:dns-adapter-process-real

# Одна семья pinned exit/upstream; JSON в stdout:
MESHPN_SYSTEMD_RESOLVED=/path/to/systemd-resolved \
  npm run dns:lifecycle-lab -- --family=4 --resolved-adapter
```

Зависимости и namespaces те же, что у resolved-стенда; бинарник не скачивается
и не устанавливается автоматически. Без sudo, от непривилегированного пользователя.
`--resolved-adapter` нельзя совмещать с `--resolved-journal` или `--crash`.
Полный запуск ограничен120с, отдельный IPC вызов5с, очистка процесса с переходом
к SIGKILL через5с. Это конечная матрица, не автоматический restart supervisor.

## Как устроено

После базового lifecycle и in-memory resolved smoke fixture закрывает исходный
in-process adapter. `dns-adapter-process.mjs` создаёт управляемый дочерний процесс;
`dns-adapter-process-worker.mjs` запускает тот же `startDnsExitAdapter`, что
используется в остальных тестах. Настройки компилируются заново в дочернем
процессе: branded profile нельзя переносить обычным JSON-клонированием.

Config/CA/секрет передаются через унаследованный IPC, не argv/env/temp file.
Worker проверяет private net/mnt/PID, общий namespace с PID1 и родителя PID1;
самостоятельный запуск на хосте отклоняется. Launcher дополнительно проверяет
private mount propagation. IPC принимает только init/stats/close, с лимитом
16KiB сообщения и одним запросом одновременно; config до15KiB, stderr/stdout
до4KiB, до12 запусков и256 запросов за жизнь handle. Нет загрузки модулей или
команд из config. Child heap ограничен96MiB. Close завершает принадлежащий
handle процесс; перезапуск после close запрещён. Это не production API/CLI.

Порт выбирается один раз первоначальной fixture, затем только явный high port.
Bind UDP/TCP означает лишь наличие listener. Перед apply/recover нужны успешные
**UDP и TCP** protected DNS probes через exit и TLS-verified DoH. При недоступном
adapter/upstream журнал и свойства resolved не меняются, guard остаётся.
Recovery сохраняет transaction ID. Занятый UDP или TCP порт — ошибка старта,
без случайного порта, fallback resolver или перезаписи настроек.

После SIGKILL кеш статистики ребёнка инвалидируется: исчезновение процесса не
выдаётся за наблюдённые нулевые счётчики. Проверяются освобождение сетевых
соединений в родительской fixture и возможность снова занять исходный порт.
После graceful close доступны последние реальные счётчики child: нет jobs,
сокетов/таймеров; затем процесс обязательно reaped. Idle samples ограничивают
RSS192MiB/FD<64. Это ограниченный lifecycle smoke, не доказательство отсутствия
медленной утечки памяти или длительный soak.

## Матрица

Для каждой семьи IPv4/IPv6 pinned exit/upstream (локальный stub остаётся IPv4):

- adapter ещё не запущен: enable/recover отказаны, baseline DNS заблокирован;
- listener поднят, но exit остановлен: readiness отказана;
- exit вернулся: тот же journal продолжает apply, A/AAAA работают;
- три SIGKILL в простое, каждый с проверкой DNS, guard, snapshots и перезапуском;
- SIGKILL после поступления двух реальных UDP/TCP запросов в удерживаемый DoH origin;
- занятый UDP, затем TCP порт: два неудачных старта с очисткой child;
- повторный успешный старт на прежнем порту;
- graceful shutdown; recover при мёртвом adapter отказан;
- явный disable без живого adapter восстанавливает baseline и снимает guard.

Итого4 SIGKILL adapter,5 успешных стартов,2 bind failures,10 отказов операций
enable/recover,2 прерванных in-flight запроса на семью.62 glibc lookup checks
включают23 базовых,9 resolved smoke и30 process lifecycle. Перед takeover и
после explicit disable baseline подтверждён положительным DNS-ответом.
Во время защиты sentinel счётчики не растут; UDP/TCP53 guards проверяются для
IPv4 и IPv6. В конце child/zombie count0, owned sockets/jobs/timers0.

Важный нюанс: glibc TCP-запрос к живому resolved при мёртвом upstream может
ждать дольше `RES_OPTIONS timeout:1`. Только для ожидаемых отказов нового режима
стенд использует3с deadline и завершает вызывающий getent. В `checks` такие
пункты имеют суффикс `:client-deadline`; **это отменённый запрос, не SERVFAIL**.
Deadline не засчитывается как успешный ответ и не ослабляет sentinel/guard checks.
Для ожидаемого успеха timeout всегда проваливает тест.

## Чего этот этап не делает

Нет автоматических бесконечных рестартов, systemd unit, production polkit,
живого uplink, DHCP/NetworkManager races, сложного split DNS, защиты от замены
listener недоверенным локальным процессом. Нет SIGKILL родительского namespace
init, совместного падения controller/adapter, reboot или power-loss.
Текущий journal привязан к namespace/bus/owner/link и после смены context
отказывает, а не автоматически присваивает себе настройки.

Добавлены [offline boot/recovery protocol и read-only VM preflight](dns-boot.md),
но настоящие VM-тесты ещё не выполнены. Guard должен действовать
до допуска обычного DNS, старый журнал нельзя слепо применять к новому владельцу.
Существование сохранённого journal само по себе не обеспечивает защиту после
перезагрузки, когда runtime firewall rules и процессы потеряны. Live opt-in и
исправление штатного DNS Radxa по-прежнему требуют отдельного согласования.
