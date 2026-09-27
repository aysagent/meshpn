# Установленный контроллер VPS 2 — проверяемая интеграция

Установленный CLI прошёл focused VM-проверку start/disable в двух загрузках;
Ограниченные systemd-службы также прошли отдельные8/8 проверки в двух загрузках
(`meshpn-dns-vm-SGJprZ`, срез6961374). Это не инструкция запуска на живом клиенте
и не готовый установщик. Клиент Radxa этим backend не
обслуживается: его собственная интеграция остаётся частью DNS v1.

`dns-client.mjs --start` / `--disable` используют настоящий installed opt-in,
проверенный code bundle и общий inherited flock. Запуск из checkout,
поддельный token и произвольные пути/команды не дают доступ к OS backend.
Все рабочие пути фиксированы:

- `/var/lib/clean-vpn/dns-v1/guard` — журнал защитных правил;
- `/var/lib/clean-vpn/dns-v1/transaction` — coupled DNS transaction;
- `/var/lib/clean-vpn/dns-v1/transaction/link` — владение DNS-интерфейсом.

Родители проверяются без перехода по symlink; собственные каталоги root-owned
0700. Новые каталоги создаются после guard с fsync родителя. Замена inode/mode
родителя во время операции — отказ. Внешний слой использует тот же общий
координатор, restore proof и атомарные журналы, что уже проверялись в лаборатории.
Данные schema/backend в прежних journal форматах не являются разрешением:
installed authority выбирается отдельной factory, а не полем из JSON.

## Реальный OS backend

Factory сама создаёт pinned command runner и fixed system bus. Она не принимает
подменённый bus, исполняемый файл или authority callback. До создания link
проверяется fresh VPS2 baseline. Перед каждым изменением нужны:

- реальный guard обеих семей;
- тот же bus, владельцы resolved/networkd и invocation служб;
- неизменённый root-owned файл networkd-исключения;
- runtime unmanaged для конкретного существующего link;
- совпадение context и текущего состояния link с журналом.

Callbacks guard нужны общему журналу, но не заменяют проверку настоящих правил.
Resolved DNS setters используют тот же fixed bus и наследуемый lock. Probe
перед takeover — установленный protected readiness, включая владельца сокетов
и loaded credentials. Обычная остановка не снимает защиту.

`--disable` восстанавливает только собственную транзакцию, удаляет свой link
и разрешает снятие guard после общего restore proof. Ему не нужен работающий
adapter; но неизвестные настройки, смена manager context или stale boot не
становятся разрешением перезаписать DNS. Он не удаляет boot policy/unit-файлы
и не завершает uninstall: постоянное отключение предстоит связать с установщиком.

## Проверка

Fake authority/IO тестируется без host writes. После изменений общего backend
networkd249 namespace-прогон прошёл12 проверок и17 SIGKILL; baseline queries
под защитой0, оставшихся owned links0, host DNS/forwarding unchanged.
После разделения session/full authority общая Node-регрессия1900/1900 PASS
(`meshpn-acceptance-vl1MHe`). Это не заменяет положительную installed VM-проверку.

Прогон `/var/tmp/meshpn-dns-vm-FnCzQl` проверял sockets/readiness в обоих
boot и настоящий installed start/disable во втором. Installed state в этой
проверке bind-mounted на отдельный ext4 диск VM; завершённые journals
сохраняются отдельно. Это **не** reboot/crash active installed controller,
не restricted systemd-unit и не live-пилот. Итог — FAIL на installed `--start`:
CLI не вернул redacted refusal, helper завершился без результата. Read-only
debugfs сохранившегося диска показал active guard, root phase=link и child
stage=stamp-intent/ifindex3. DNS settings ещё не применялись. Похоже на предел
180 секунд команды, но прежний failure log не сохранял signal/killed; это
не выдаётся за окончательно подтверждённый timeout.

Найдены повторные полные обходы bundle во вложенных read-only командах:
один context выполнял11 обходов, наблюдение context/view/context — около49.
Внесено разделение session/full authority: чтения между полными проверками
проверяют процесс, namespace и lock; fixed runner отдельно закрепляет OS tool.
Полная проверка сохраняет config, manifest, каталоги, interpreter и все code files;
ip-mutators и D-Bus setters по-прежнему проверяют **полный bundle до и после**
системной команды. Внешние inspection сохраняют полные проверки.
Сырой session-only runner из runtime не возвращается. Таймауты не увеличены;
следующий VM-прогон должен подтвердить и корректность, и время работы.
В failure diagnostics добавлены только killed/signal/elapsedMs, без секретов.

Следующий focused run `/var/tmp/meshpn-dns-vm-OHG5ct` подтвердил таймаут
installed start: SIGTERM/killed=true,180106мс. Link уже создан, root достиг
settings/level0/pending=true; guard остался. Отчёт и raw disk сохранены,
пересоздаваемые guest/initrd/kernel удалены для освобождения места.
После этого убраны повторные полные config-проверки из вложенных read-only
команд (внешние full barriers неизменны), повторное чтение bus context внутри
той же операции и шесть helper-процессов для трёх DNS-полей заменены двумя.
`linkSnapshot` выполняет новый GetLink и typed multi-property read каждый раз,
без кэша состояния; malformed/missing/reordered ответы отклоняются.
Это не атомарный OS snapshot: journal readback/context brackets остаются.
Формат нескольких JSON-строк подтверждён
[исходником busctl249](https://github.com/systemd/systemd/blob/v249/src/busctl/busctl.c#L1962).

`meshpn-dns-vm-XkyQKR`: снова timeout180174мс, уже settings/level3/pending=true.
Затем full authority убрана из чистых context/view: они проверяют процесс,
namespace/lock и свежие busId/resolve1 owner; setters по-прежнему проверяют
полный bundle/config, обоих managers, guard и unmanaged link. Команда дополнительно
делает full authority перед возвратом результата. Полные readonly inspections
снаружи также сохранены. Это разделение read/mutation checks, не кэш OS state
и не разрешение на запись по результатам облегчённой проверки.
Последующий VM-срез: **`meshpn-dns-vm-M08EIu`,6/6 PASS, две загрузки**.
Обе пары installed `--start`/`--disable` прошли с неизменным лимитом180секунд:

| Загрузка | start | disable |
| --- | ---: | ---: |
| 1 | 171598мс | 174549мс |
| 2 | 167789мс | 172685мс |

Это TCG, не benchmark VPS/Radxa; запас времени небольшой. Проверены active и
released journal состояния, удаление собственного link, loaded credentials,
socket ownership и protected adapter readiness. Host DNS files unchanged.
Public NSS и ограниченный controller unit — следующий отдельный сценарий,
не часть этого PASS. Source manifest содержит261 installed files. После
захвата образа для следующего unit-case менялись только пять VM/test файлов
(`dns-vm-lab`, `dns-coupled-vm-driver`, `dns-installed-vm-check`, `dns-vm-protocol`,
`test-dns-vm`); runtime installed controller/backend/authority совпадают с образом.
Финальная Node-регрессия этого этапа:1903/1903 PASS
(`meshpn-acceptance-z9BN0q`), включая подготовленный unit-case verifier.
Успешный VM report, serial logs, source manifest и raw disk с двумя completed
транзакциями сохранены; пересоздаваемые guest/initrd/kernel удалены.

Отдельный `dns-vm-lab.mjs --case=installed` использует ту же NIC-less coupled
VM и настоящий CLI, но не повторяет старую аварийную матрицу. На каждой из
двух загрузок проверяет baseline/отказы, loaded adapter/защищённую readiness,
installed start и disable с проверкой журналов и удаления link. Диск хранит
завершённые журналы. Отчёт проверяется отдельным verifier; он не может быть
принят за coupled crash/lifecycle evidence. Между загрузками транзакция уже
восстановлена: `activeTransactionRebootTested=false`. Лимиты времени прежние.

Подробный результат и границы [controller units](dns-controller-service-plan.md)
учитываются отдельно от CLI-прогона. Далее: связать установку/enable/disable/uninstall,
проверить boot graph и выполнить Radxa-интеграцию.
Полный DNS v1 остаётся открытым до обоих согласованных клиентских пилотов.
