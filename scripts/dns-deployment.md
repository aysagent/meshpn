# DNS: единый журнал публикации кода и конфигурации

`scripts/lib/dns-deployment.mjs` связывает
[code bundle](dns-deployment-bundle.md) и
[13 файлов VPS2](dns-deployment-files.md) под общим inherited exclusive flock.
Это библиотечная часть **первой, ещё не активированной** установки. Host CLI,
start/reload/enable служб и post-activation uninstall здесь отсутствуют.
Radxa этим VPS2-набором не устанавливается.

Для post-disable removal добавлена отдельная [журналируемая связка](dns-released-removal.md)
с сохранённой guard-политикой и runtime-history fingerprint. Старый publisher
не получает автоматического права снимать работающий DNS; новая связка пока
не является host CLI и ещё требует единого VM-прогона.

## Порядок и восстановление

В отдельном private0700 каталоге находятся главный `journal.json` и дочерние
`code/`, `files/`. Привязаны identity root/каталогов, SHA256 approved bundle и
точный упорядоченный список path/mode/SHA256 клиентских файлов. Секретные байты
в главном журнале отсутствуют. Входные buffers копируются до первого await и
собственная копия очищается при любом исходе; оригиналом распоряжается вызывающий.

Порядок стадий:

`code → files → installed → removing-files → removing-code → removed`

Для будущего согласованного снятия systemd-зависимостей добавлена отдельная
файловая ветка `installed → detaching-files → detached`. Явная операция
`detach` применима только к полному13-файловому installed набору и удаляет
фиксированный suffix в обратном порядке: opt-in, client config, ключ, затем
networkd/resolved drop-ins. Остальные восемь файлов и весь код сохраняются.
Child file journal использует `detaching → detached`; parent остаётся
`detaching-files`, пока дочерний журнал не завершён. После любого обрыва
`recover` продолжает только эту ветку и останавливается в `detached`.
Продолжить полный rollback может лишь явный `remove` с отдельным OS-proof.
Данный файловый этап не выполняет daemon-reload/stop и не принимает quiescent
report сам по себе: его подключение к настоящему lifecycle ещё впереди.

Новая ветка проверена шестью process SIGKILL: durable parent intent,
durable child intent, отзыв opt-in, удаление первого/последнего drop-in,
durable child completion. После обрыва исходный source-каталог переименован;
`recover` работает по журналам без него, но не удаляет сохранённую часть.
Предварительный общий файловый прогон107/107 PASS; после добавления отказов
legacy/OS-proof и недоступного source — отдельные19/19 PASS. Полная Node
регрессия этого среза ещё впереди. Эти проверки используют тестовый OS callback,
а не заменяют настоящий integrated uninstall VM.

- До staging проверяется соответствие opt-in выбранному bundle. Существующий
  code/config не принимается, даже если байты совпадают.
- Конфигурация публикуется только после полного code bundle. При её операциях
  код повторно проверяется; изменение кода не позволяет опубликовать opt-in.
- Opt-in остаётся последним из13 файлов. В начале отката он удаляется первым;
  код перемещается в private `code/retired/` только после удаления всего набора.
  Рекурсивного удаления кода нет.
- `recover` продолжает записанное направление. Сначала проверяются **оба**
  дочерних журнала и фактические объекты; чужое изменение любого из них
  запрещает следующий setter. `remove` явно переводит незавершённую установку
  в откат; восстановление не превращает снятие файлов обратно в установку.
- После durable клиентского журнала recovery/rollback не требует исходного
  ключа или source bundle. До его создания для продолжения нужны прежние
  приватные входы с теми же hashes; можно вместо этого откатить только код.
- Незарегистрированный staging после обрыва **до** дочернего журнала остаётся
  для review. Он не принимается и не удаляется автоматически. Это безопасный
  отказ, не обещание recovery любой незавершённой подготовки.

Нужно заранее подготовить доверенные parent directories; эта библиотека
создаёт только свои два дочерних private каталога. Дочерние транзакции сохраняют
проверки same mount, exact ownership/inode и отсутствие overwrite. Старые
5/6/10-file journals не повышаются до нового набора и не усыновляются.

## Проверки и граница результата

```bash
npm run test:dns-deployment
```

Тест использует настоящие файлы, GNU mv и flock в приватном
user/mount/network/PID namespace с chroot. Code fixture содержит четыре
минимальных модуля; он **не** выдаётся за полный исполняемый installed bundle.
Проверка неактивности в этом файловом стенде — тестовый callback, а не
[реальная OS-проверка](dns-deployment-inactive.md). Следовательно, это не
доказательство live install или активации DNS в VM.

Семь SIGKILL покрывают durable code preparation, publication кода, подготовку
client journal, publication opt-in, отзыв opt-in, переход к удалению кода и
перенос кода в архив. Дополнительно проверяются конфликты code/config/lock,
отсутствие adoption orphan staging, изменение входных buffers и точный откат.
Первый прогон обнаружил ошибку завершающего read-only inspect после успешного
переноса кода в архив; проверка состояния исправлена только для closing phases.
Итоговый отдельный прогон: **18/18 PASS**, семь SIGKILL.
Общая Node-регрессия: **1991/1991 PASS**, без skips
(`/var/tmp/meshpn-acceptance-SmVx6l/report.json`), включая прежние30 bundle и77
file-set тестов после выделения общего изолированного harness. Это не новый
VM PASS и не live-пилот.

Следующий интеграционный шаг: полный source bundle, реальные inactive OS checks,
единый VM install/activate/disable/uninstall и ранний boot graph. Нужно измерить
стоимость повторных OS/inventory проверок на полном bundle; текущий короткий
fixture не подтверждает ни достаточную скорость, ни укладывание в VM deadlines.
После этого остаются installed Radxa и оба согласованных клиентских пилота.

## Стоимость проверки и полный файловый VM-сценарий

Замер исходной связки показал349 вызовов `assertInactive` за одну установку
даже с четырьмя code files. При примерно6с на реальную OS-проверку в TCG это
непригодно для ограниченного VM-прогона. Теперь полный OS-check остаётся на
входе/выходе операции и перед каждой публичной публикацией/удалением, включая
detach staging hardlink: этот detach делает opt-in single-link authority file.
Приватное staging и чтение собственного inventory проверяют lock/контекст,
inode/hash/mount, но не запускают вложенные полные OS-проверки.
При публикации конфигурации точный inventory установленного кода всё равно
сверяется. Нет TTL-cache неактивности или исключения по «слишком медленной VM».

Регрессионные проверки отклоняют потерю неактивности перед move, перед первым
config link и между publication opt-in и его detach. Число полных проверок для
набора68 code files ограничено числом видимых операций, а не числом файлов.

Новый `dns-vm-lab.mjs --case=publication` использует все JS/MJS скрипты snapshot,
собранные builder в `/source/clean-vpn`, настоящий PID1/D-Bus/firewall collector
и общий boot flock. Проверяет file publication, загрузку import graph трёх
entrypoints через заведомо неверные аргументы, затем inactive rollback с
сохранением кода в архиве. Повторяется на двух загрузках VM без NIC/shared FS.
Первоначальный firewall и `/etc/resolv.conf` должны сохраниться.

Это ещё **не** готовый live source packager, активация DNS, early boot graph
или post-activation uninstall. Синтетическая конфигурация для публикации не
имеет готового networkd baseline, и её службы в этом сценарии не запускаются.
Состояние полностью откатывается **до** reboot; active-transaction reboot
этим не проверяется. Initramfs root пересоздаётся на каждой загрузке; сохранение
архива в настоящем persistent root через reboot этим также не доказано.

Результат: **6/6 PASS на двух загрузках**
(`/var/tmp/meshpn-dns-vm-9CAnjT/report.json`), host DNS unchanged. Все270 файлов
кода frozen snapshot совпадают с рабочим кодом после прогона. Установка:
216139/218615мс и40 полных OS-checks; откат:163134/164597мс и33 проверки.
Это TCG timing, не прогноз для Radxa/VPS. Оба лимита420с на операцию и900с
на загрузку сохранены; DNS queries0. Промежуточный набор125 тестов файловых
транзакций прошёл до добавления пяти новых boundary/count регрессий; отдельно
эти5/5 и57/57 VM protocol/host-refusal тестов также прошли.
Финальная общая Node-регрессия: **1997/1997 PASS**, без skips
(`/var/tmp/meshpn-acceptance-8QpRuR/report.json`), включая все новые boundary
проверки и прежние SIGKILL. Пересоздаваемые guest/initrd/kernel завершённой VM
удалены для места; report, serial logs, image manifest и raw state disk сохранены.
