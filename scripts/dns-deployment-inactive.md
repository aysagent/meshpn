# DNS: проверка неактивности установки

`scripts/lib/dns-deployment-inactive.mjs` — read-only OS-проверка для будущего
установщика VPS2. Это не команда установки и не разрешение снять защиту после
использования DNS. Radxa требует отдельной проверки dnsmasq и resolver baseline.

## Что проверяется

Под общим boot/deployment flock, в исходных namespaces настоящего Linux PID1:

- `org.freedesktop.systemd1` на фиксированной системной D-Bus принадлежит UID0,
  PID1. Уникальное имя и ID шины проверяются повторно; auto-start и interactive
  authorization отключены. Исполняемые утилиты проверяет общий root-pinned runner.
- Нет выполняемых/ожидающих jobs clean-vpn DNS, resolved или networkd. Все
  загруженные `clean-vpn-dns-*` — только четыре известных inactive/dead service;
  MainPID, ControlPID и список процессов cgroup пусты. Список проверяется дважды.
- Нет процессов с точным installed argv entrypoint client/guard/adapter. Сырые
  argv не возвращаются и не журналируются; буфер ограничен и очищается.
  Переименованные процессы и произвольные wrappers этим не обнаруживаются.
- Нет собственного `cvdns*` link или зарезервированного адреса `192.0.2.1`.
  Guard отсутствует в обеих семьях IP; firewall backend совпадает с выбранным.
- Нет runtime history `/var/lib/clean-vpn/dns-v1` или boot namespace marker.
  Даже завершённый старый журнал требует отдельного recovery/uninstall, а не
  автоматического признания «первой установкой».

Нечитаемое/неизвестное состояние означает отказ. Команды ограничены по времени
и выводу. Снимок под кооперативным lock не защищает от стороннего root, меняющего
состояние в обход lock. Это также **не** проверка пригодности исходного DNS,
readiness adapter, политика облачных имён или доказательство restore.

## Отдельная проверка после disable

`inspectReleasedDnsDeployment` не ослабляет проверку первой установки. Для
VPS2 она повторяет OS-проверки jobs/services/cgroups/processes/links/firewall,
но вместо требования отсутствия истории читает сохранённые runtime-журналы:

- coupled transaction и owned-link child должны быть `released`, иметь общие
  ID/name/context; если сохранён original link, его ifindex должен совпасть;
- guard должен быть `released`, с точным входным guard policy, backend обеих
  семей, inode собственного каталога и текущими boot ID/network namespace;
- boot ID, все три namespace, D-Bus ID и уникальное имя resolved должны
  совпасть с журналами. Для resolved проверяются настоящий PID активного unit,
  root-owned executable и network namespace; данные читаются повторно;
- файлы журналов ограничены по размеру, root-owned, 0600, без symlink/hardlink;
  каталоги состояния — 0700, вся цепочка родителей проверена. Метаданные и
  содержимое повторно сравниваются. Отсутствующая/частичная история — отказ;
- оставшийся boot namespace marker допустим только для текущего контекста.

История **не удаляется и не усыновляется в новый контекст**. Нет остановки
служб, снятия guard или DNS-запросов. Результат — `releasedInactive: true`,
но `uninstallAuthorized: false`: принадлежность файлов установки и отдельное
разрешение на их удаление этот collector не доказывает. Он работает и без
opt-in/config-файлов, чтобы будущий uninstall мог перепроверять ОС после
отзыва opt-in. Состояние нового boot или перезапущенного resolved требует
отдельного recovery, а не автоматического разрешения удалить файлы.

Этот режим пока **не подключён к host CLI/установщику**. Проверены валидаторы
и безопасное чтение в изолированном root namespace. Следующий обязательный
шаг — прогон после настоящего installed `start → disable` в VM, затем
связывание с файловым rollback. Старые fresh/publication VM PASS этого не
доказывают; положительный ответ baseline DNS тоже остаётся отдельной проверкой.

Новый набор history/fresh: **53/53 PASS** (34 новых history-теста), общая
Node-регрессия: **2031/2031 PASS**, без skips
(`/var/tmp/meshpn-acceptance-wBi4hp/report.json`). Первый параллельный запуск
Node+VM столкнулся с нехваткой места: VM не была собрана, Node-набор завершился
с отказами (`meshpn-acceptance-tpVgHm`). Удалены только недособранные guest/initrd
`meshpn-dns-vm-AqnJZL`; успешная Node-регрессия затем выполнена отдельно.
После выделения общей fresh/released логики прежний fresh-сценарий повторно
прошёл **14/14 на двух загрузках VM** (`meshpn-dns-vm-NJGBAT`), DNS хоста не
изменён; все272 исходных файла `/project/` сверены с image manifest. Это
регрессия fresh gate, **не** VM-проверка released collector. После завершения
удалены только пересоздаваемые guest/initrd/kernel; отчёт, manifest и логи сохранены.

## Изолированный сценарий

`dns-vm-lab.mjs --case=deployment` проверяет настоящий collector на PID1 systemd
в VM без NIC и shared filesystem. Семь проверок на каждой из двух загрузок:
пустое состояние, загруженный inactive unit, отказы при работающем service,
оставшемся link, guard и runtime history, затем повторная проверка после точной
очистки fixture. `/etc/resolv.conf` и исходные firewall rules должны сохраниться;
DNS-запросы не отправляются. Этот результат нельзя засчитать как install/activate
или аварийное восстановление работающего DNS.

Для этого сценария есть настоящий `dbus.socket`: systemd проверяет состояние
и socket, и service перед подключением собственного API к системной шине.
Прежняя VM fixture использовала только resolve1/network1 и этой проверки не
покрывала. См. [systemd v255 manager_dbus_is_running](https://github.com/systemd/systemd/blob/v255/src/core/manager.c).

Результат: **14/14 PASS на двух загрузках VM**
(`/var/tmp/meshpn-dns-vm-RchXdO/report.json`), host DNS unchanged. Успешная полная
проверка занимает около6с на TCG; это не бюджет реального клиента. Тематические
Node-тесты collector/VM protocol/command runner: **87/87 PASS**.
После VM в collector изменено только формирование отказа при непустом cgroup:
теперь ошибка не содержит command strings. Это отдельно покрыто19/19 unit
тестами; VM-результат относится к срезу до этой правки диагностики. В launcher
также дополнена строка help, не код внутри VM.
Финальная общая Node-регрессия после правки: **1973/1973 PASS**, без skips
(`/var/tmp/meshpn-acceptance-c7c0EW/report.json`). Предыдущий полный проход
`meshpn-acceptance-y9TrqQ` также1973/1973 PASS; это Node-suite, не full browser
acceptance и не клиентский пилот.

Два первых запуска отказали
до первого сценария: системная шина была доступна, но имя systemd1 отсутствовало
из-за неполного guest D-Bus lifecycle. Отчёты сохранены в
`meshpn-dns-vm-gpZ9y2` и `meshpn-dns-vm-kiqzOw`; production authority gate не
ослаблялся. Regenerable guest/initrd/kernel удалены, отчёты/логи/manifest/диск
сохранены.

Далее — связать эту проверку с двумя файловыми журналами (code bundle и
unit/config/credentials), отдельной активацией и явным rollback/uninstall.
