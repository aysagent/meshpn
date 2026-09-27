# DNS: файловый откат после штатного disable

`scripts/lib/dns-released-removal.mjs` связывает read-only доказательство
[released-состояния](dns-deployment-inactive.md) с
[журналом code/config deployment](dns-deployment.md). Это библиотечная
транзакция, **не host CLI и не проверенный живой uninstall**. Schema2 связывает
файловое удаление с callback перезагрузки unit-конфигурации и остановки guard;
fixed-layout factory выполняет эти действия через проверенные OS-команды.
Firewall и runtime-журналы не удаляются этой операцией.

## Что сохраняется до первого удаления

Отдельный private0700 каталог содержит журнал. Прежний schema1 сохраняет
две стадии `removing → removed` и требует strict inactive proof на каждом шаге.
Новый schema2 использует `detaching → detached → removing → removed`.
В нём записаны:

- identity root и собственного каталога, путь и SHA256 неизменяемых полей
  исходного deployment journal: его ID, identities, bundle и все13 descriptors;
- точные байты guard-policy (строго проверенный несекретный JSON до2048 байт),
  чей SHA256 обязан совпасть с descriptor исходной установки;
- `historySha256` реального released collector: SHA256 трёх runtime-журналов
  и проверенных inode/mode/ctime metadata. Это не подпись и не самостоятельная
  авторизация: свежий OS-check всё равно нужен перед каждым изменением.
- Для schema2 — `managersSha256`: текущие bus owner, PID, InvocationID и
  executable identity обоих менеджеров. `NeedDaemonReload` исключён из hash:
  его изменение ожидается при снятии drop-ins, смена процессов — нет.

Исходные PSK, upstream/config/opt-in contents сюда не копируются. Общий inherited
flock удерживается и при OS-проверках, и при файловых операциях. Нужны отдельные,
не пересекающиеся каталоги removal/deployment/runtime/code; parent directories
готовит внешний установщик, а не эта транзакция.

Сначала проверяются полная установленная транзакция и оба её дочерних inventory.
Затем durable intent разрешает уже существующему publisher удалить opt-in первым,
остальные принадлежащие ему файлы — в обратном порядке и перенести код в
private archive последним. При каждом OS-check обязаны совпасть policy и
runtime-history fingerprint. Изменённый removal journal также не перезаписывается.

`recover` без собственного intent не начинает удаление. После durable intent
достаточно сохранённой политики и прежней runtime-истории: удалённые публичные
config/opt-in/guard-policy не читаются заново. Нужен доверенный recovery bootstrap
вне уже перемещённого `/opt/clean-vpn`; host bootstrap пока не реализован.
Если запись оборвалась до atomic journal rename, orphan staging сохраняется
для review — не принимается и не стирается автоматически.

## Граница доверия и интеграции

Файловое ядро принимает доверенный `inspectReleased` callback, как существующий
publisher принимает `assertInactive`. Тестовый callback не выдаётся за OS-proof.
`scripts/lib/dns-installed-removal.mjs` добавляет отдельную fixed-layout связку:
root `/`, `/var/lib/clean-vpn/deployment`, `/var/lib/clean-vpn/removal`, настоящий
boot lock, root-owned parents и только branded pinned OS commands. Политика
читается с установленного пути лишь при создании нового intent; затем берётся
из журнала. Каждый callback вызывает настоящий released collector.

Связка пока **не подключена к CLI и не прошла единый VM uninstall**.
Новая boot/bus/owner epoch не усыновляется. Radxa этим VPS2-набором не
обслуживается. Прежний schema1 не повышается до schema2 при recovery.

Реализован переход в одном порядке:

1. После настоящего disable остановить adapter и доказать отсутствие workers;
   guard oneshot временно остаётся active/exited. Это отдельное
   [quiescent-наблюдение](dns-deployment-inactive.md), не strict inactive proof.
2. До удаления сохранить policy/history binding; отозвать opt-in и удалить
   принадлежащие deployment manager drop-ins в существующем обратном порядке.
   Частично удалённый набор обязан оставаться распознаваемым по журналу.
3. Проверить ownership оставшихся файлов и неизменность manager context;
   daemon-reload, остановить guard без stop hooks, получить strict released
   proof с тем же history fingerprint и без перезапуска resolved/networkd.
4. Лишь затем завершить оставшийся файловый rollback и архивирование кода.

`recover` повторяет service transition, если обрыв произошёл после reload/stop,
но до durable перехода к `removing`. Перед продолжением снова нужны прежние
runtime history и оба manager identity. `inspect` не выполняет service callbacks.
После `removing` допустим только строгий inactive proof. Schema1 по-прежнему
отвергает quiescent-отчёт.

Factory после daemon-reload проверяет отсутствие оставшихся manager/foreign
dependencies guard, stop propagation и OnSuccess/OnFailure triggers, затем
останавливает guard. Наличие adapter/controller workers до операции запрещено;
factory не вызывает их неявную остановку и не выполняет disable за пользователя.
Эти реальные OS-действия ещё требуют единого VM-прогона с файловыми журналами.

## Проверки

`node --test scripts/test-dns-released-removal.mjs` использует реальные GNU mv,
flock, файлы и SIGKILL внутри private user/mount/network/PID namespace/chroot.
Code fixture — четыре минимальных модуля; OS observation — тестовый callback.
Проверяются пять обрывов: durable removal intent, отзыв opt-in, удаление
guard-policy, переход к перемещению кода и завершённое перемещение. Исходный
source directory перед resume переименовывается; его прежний путь недоступен.
Также проверяются policy/history/journal drift, незавершённый intent, конфликт
кодового inventory, отсутствие lock и невозможность `recover` без intent.

Результат: **17/17 PASS**, включая пять реальных SIGKILL; совместно с
history/fresh проверками — **70/70 PASS**. Общая Node-регрессия —
**2049/2049 PASS**, без skips (`/var/tmp/meshpn-acceptance-IMAVZu/report.json`).
Эти тесты используют подставную OS observation только на уровне файлового ядра;
fixed-layout factory отдельно проверен лишь на отказ от поддельного command runner.

Этот файловый прогон **не заменяет** единый реальный
`install → start → disable → remove → recover` в VM, early boot/fault проверки
или клиентские пилоты.

Schema2: **27/27 PASS** в отдельном файловом прогоне, включая11 process SIGKILL
(пять прежних и шесть на detaching/detached/reload/stop/removing).
Recovery выполняется после удаления доступности исходного source-каталога.
Service callbacks в этом прогоне — явная модель; реальные factory команды
нужно проверить в integrated VM. Общая Node-регрессия: **2074/2074 PASS**,
без skips (`meshpn-acceptance-iQeMc9/report.json`).
