# Radxa dnsmasq: журнал и аварийное восстановление — лабораторный этап

Статус: реализован persistent file journal и проверяется настоящий dnsmasq в
изолированном USB-стенде. **Это не установщик на Radxa и не host recovery CLI.**
Никакие `/etc/dnsmasq*`, `/etc/resolv.conf` или системные службы не меняются.

```bash
npm run test:dnsmasq-journal
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run dns:dnsmasq-lab -- --journal
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run test:dnsmasq-real
```

`--journal` включает USB-режим. Требования и схема сети описаны в
[dnsmasq-lab.md](dnsmasq-lab.md); дополнительно нужен `flock`. Предельное время
прогона — 120 секунд. Используется только приватный временный каталог, который
удаляется после завершения прогона. Слово persistent означает переживание
перезапуска контроллера в рамках стенда, не сохранение результата после cleanup.

## Что записывается и проверяется

- Точный исходный текст конфигурации, включая комментарии и две исходные DHCP
  option 6. Managed config генерируется строгим Radxa fixture compiler:
  один DNS для USB-клиента, один upstream на локальный адаптер, сохранённые DHCP
  диапазон/шлюз и `no-resolv`. Includes, hooks и неизвестные настройки запрещены.
- Исходный, подготовленный managed и подготовленный restored файлы имеют
  разные inode и SHA-256. Файлы — regular, без symlink/hardlink, приватные 0600;
  каталог — 0700, с проверяемой идентичностью и каноническим путём.
- Context: namespaces, boot ID, идентичность каталога, ifindex/name/MAC usb0,
  SHA-256 executable. Смена context отклоняется; reboot не присваивает старый
  журнал новому окружению автоматически.
- Направление apply/restore, курсор «конфиг → демон», pending intent и состояние
  завершения. Журнал не содержит исполняемых команд или произвольных путей.

Подготовленные файлы синхронизируются до записи исходного журнала. Перед
заменой конфига и перед активацией демона сначала записывается intent:
temporary file → fsync → rename → fsync каталога. Конфиг также заменяется
rename с fsync каталога. Recovery допускает только ожидаемое состояние до
операции либо её результат при сохранённом pending intent.

Совпадение текста при другом inode не считается доказательством владения.
Незавершённые подготовительные файлы не принимаются за разрешение на recovery;
отсутствующий/повреждённый журнал требует review. Новый enable поверх имеющегося
журнала не выполняется. Автоматического удаления старого журнала здесь нет.

## Поведение при отказах

Защита ставится перед подготовкой. В journal-режиме она включает namespace-only
OUTPUT TCP/UDP53 обоих семейств, а также USB INPUT/FORWARD. Это блокирует прямые
upstream даже у dnsmasq, ещё работающего со старым конфигом; разрешённый адаптер
слушает high port. DHCP и ответы локального DNS не блокируются этими правилами.

Enable/recover apply проверяет адаптер по UDP/TCP до выбора нового конфига и
повторно после активации демона. Файл на диске не доказывает состояние процесса:
backend отдельно сверяет принадлежащий стенду живой процесс и загруженный
snapshot, при необходимости перезапускает его. Leasefile сохраняется.

Обычный recover продолжает записанное направление; он не откатывает к прямому
DNS из-за ошибки адаптера. Explicit disable сначала надёжно записывает restore,
возвращает исходные байты и запускает baseline dnsmasq **под защитой**. Только
после проверки context/config снимается guard. Для disable не нужен рабочий
адаптер: оператор явно разрешает возвращение исходного прямого DNS.

`inspectDnsmasqTransaction` — read-only API, без setters, probes, guard и restart.
Он показывает записанное состояние и проверяет файлы/context, но не обещает,
что живой демон использует этот конфиг. Это пока не пользовательский host CLI.

## Проверки и границы доказательства

Unit/file tests проверяют прерывания fsync/rename, потерю подтверждения,
частичный enable/disable, повторный recover, ошибки readiness/демона/guard,
чужие файлы, изменённый context, невалидное хранилище и dry-run.

Реальный journal-стенд сохраняет 61 USB/DNS проверку и шесть DHCP DORA обменов.
Дополнительно семь настоящих SIGKILL контроллера: prepared, apply config,
apply daemon, restore intent, restore config, restore daemon, guard removal.
Конкурирующий контроллер отклоняется flock. Проверяются отказ recovery при
выключенном exit и блокировка baseline daemon до явного снятия защиты.

Контроллер держит flock, а namespace PID1 исполняет file/daemon/guard RPC.
SIGKILL ставится на подтверждённых границах, где setter уже закончен. **Это не
тест убийства backend посреди setter**, не host service lifecycle и не reboot.
Unit fault injection между rename/fsync также не является физическим power-loss.
При реальном развёртывании блокировка должна покрывать жизненный цикл всех
исполнителей; нельзя переносить RPC fixture как production supervisor.

Приватный каталог и lock обеспечивают координацию наших процессов, но rename
не является kernel compare-and-swap против враждебного писателя с тем же UID.
Системные конфиги с includes, владельцем-службой, правами 0644 и ACL этим
fixture backend не поддержаны. Не реализованы host resolver takeover,
boot guard, принятие новой boot-эпохи, independent pcap и live arm64-пилот.
Старые DHCP leases также требуют явной политики обновления DNS.

Дальше: ownership/service lifecycle и reboot в VM для dnsmasq; затем реальные
версии resolved 249/networkd, пользовательские dry-run/apply/recovery скрипты
и пилоты по [матрице клиентов](dns-client-matrix.md). Никакого SSH от помощника.
