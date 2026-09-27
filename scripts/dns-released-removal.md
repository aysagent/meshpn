# DNS: файловый откат после штатного disable

`scripts/lib/dns-released-removal.mjs` связывает read-only доказательство
[released-состояния](dns-deployment-inactive.md) с
[журналом code/config deployment](dns-deployment.md). Это библиотечная
транзакция, **не host CLI и не проверенный живой uninstall**. Она не вызывает
stop/reload/restart служб, не снимает firewall и не удаляет runtime-журналы.

## Что сохраняется до первого удаления

Отдельный private0700 каталог содержит журнал с двумя стадиями:
`removing → removed`. В нём записаны:

- identity root и собственного каталога, путь и SHA256 неизменяемых полей
  исходного deployment journal: его ID, identities, bundle и все13 descriptors;
- точные байты guard-policy (строго проверенный несекретный JSON до2048 байт),
  чей SHA256 обязан совпасть с descriptor исходной установки;
- `historySha256` реального released collector: SHA256 трёх runtime-журналов
  и проверенных inode/mode/ctime metadata. Это не подпись и не самостоятельная
  авторизация: свежий OS-check всё равно нужен перед каждым изменением.

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

Связка пока **не подключена к CLI и не прошла единый VM uninstall**. В частности,
ещё нужно согласовать `daemon-reload` после удаления manager drop-ins: collector
сейчас строго требует `NeedDaemonReload=no`, а библиотека ничего автоматически
не перезагружает. Это проверка следующего интеграционного этапа, не разрешение
обойти запрет или изменять службы на живом клиенте. Новая boot/bus/owner epoch
также не усыновляется. Radxa этим VPS2-набором не обслуживается.

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
