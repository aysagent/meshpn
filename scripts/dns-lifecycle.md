# DNS lifecycle: offline plan и изолированный стенд

Это **не включение системного DNS в clean-vpn**. Host backend ещё не выбран:
нужна отдельная read-only диагностика реального клиента — systemd-resolved,
NetworkManager, resolvconf либо unmanaged `/etc/resolv.conf`. Автоустановки,
`--apply`, правок systemd units и изменений live VPN здесь нет.

Для первого шага на настоящем клиенте добавлен `npm run dns:inspect`
([read-only диагностика](dns-inspect.md)), без DNS-запросов и изменений настроек.
Не запускайте выбор backend по отчёту контейнера/рабочего окружения вместо клиента.

Для выбранного направления resolved есть [экспериментальный D-Bus backend и
реальный namespace-стенд](dns-resolved.md): `--resolved`. Он не подключён к
durable journal и не является разрешением на live настройку клиента.

## Запуск

```bash
# Без сети, чтения настроек хоста и побочных эффектов
npm run dns:lifecycle
npm run dns:lifecycle -- --scenario=conflict
npm run dns:lifecycle -- --scenario=startup-failure
npm run dns:lifecycle -- --scenario=restore-failure

# Реальный glibc DNS → adapter → enc-SNI exit → TLS-verified DoH fixture
# Публичные по классификации IP здесь только aliases lo в отдельном netns
npm run dns:lifecycle-lab -- --family=4
npm run dns:lifecycle-lab -- --family=6

# Дополнительно настоящий SIGKILL отдельного контроллера и recovery из журнала
npm run dns:lifecycle-lab -- --family=4 --crash
npm run dns:lifecycle-lab -- --family=6 --crash

npm run test:dns-lifecycle
npm run test:dns-lifecycle-real
npm run test:dns-lifecycle-journal
npm run test:dns-lifecycle-crash-real
```

Dry-run выводит JSON переходов и предлагаемых действий; default scenario `outage`,
также доступен `normal`. Он не проверяет текущую ОС и не является deploy-планом
для конкретного клиента. Флаг opt-in в модели обязателен, но не включает ничего
на хосте. Файл модели — `lib/dns-lifecycle.mjs`.

Стенду нужны Linux, Node22+, glibc `getent` с `-A`, unshare с user namespaces,
mount, iproute2, iptables/ip6tables и OpenSSL; для `--crash` также util-linux `flock`.
Запускать без sudo; если namespace
или инструмент недоступен, команда завершается ошибкой, без fallback на хост.
Один запуск ограничен45с, с `--crash` —120с (+ ограниченное завершение дочернего процесса).
Результат — JSON в stdout; временные сертификаты и fixtures удаляются.

## Согласуемый контракт

| Событие | Предлагаемое поведение |
| --- | --- |
| Явное включение | Установить независимый DNS guard, сохранить baseline, запустить adapter, выполнить защищённый DNS probe |
| Probe успешен | Проверить владение настройками, выбрать только managed DNS; подтвердить применение отдельно |
| Exit/adapter недоступен | Ошибка DNS; не возвращать baseline и не снимать guard автоматически |
| Restart/recovery | Сохранить первоначальный snapshot, проверить владение, guard и готовность заново |
| Кто-то изменил DNS | Conflict: не перезаписывать изменения; guard остаётся, нужна явная развязка конфликта |
| Явное отключение | Проверить владение, восстановить snapshot под guard, подтвердить восстановление, затем снять guard |
| Ошибка восстановления | Сохранить snapshot и защиту, не объявлять отключение успешным |

`listening` адаптера не означает готовности upstream. Restart, SIGTERM,
потеря exit и явное отключение защиты — разные события. Обработчик аварии не
должен автоматически восстанавливать открытый DNS. При неудачном старте после
установки guard baseline может остаться выбранным, **но заблокированным**;
снять это ограничение можно явным отключением.

Модель — предложение протокола, не транзакционный исполнитель: её действия
должен подтверждать backend, ошибки — переводить в безопасное состояние.
`blocked` описывает требуемое поведение, а не доказательство успешной установки
firewall. Для namespace backend ниже добавлен отдельный экспериментальный
journalled executor с process-crash recovery. Это не переносится автоматически
на resolved/NetworkManager или настоящий resolv.conf. Сравнение текста в базовой
fixture не заменяет проверки идентичности объекта в crash-стенде.

## Что реально проверяет стенд

Отдельные user/network/mount/PID namespaces, PID1 с приватным `/proc`, только `lo`,
private mount propagation проверяются **до** любых mount/firewall операций.
Shared propagation могла бы распространять mount-события между namespaces;
поэтому одного `--mount` недостаточно как инварианта безопасности.
[Linux mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).

Новые временные файлы bind-mount поверх `/etc/resolv.conf` и `/etc/nsswitch.conf`
видны только worker. Их исходные host inodes не редактируются; launcher сравнивает
хеши обоих host файлов до/после. `/run` скрыт приватным пустым каталогом, чтобы
glibc не обращалась к host nscd через pathname Unix socket. Symlink targets под
`/run` создаются заново только в этом приватном каталоге. Исходные DNS-настройки
не копируются в отчёт. Worker нельзя запускать напрямую вне namespace launcher.

`getent -A -s dns ahostsv4/ahostsv6` запускается отдельным процессом для каждого
запроса: используем glibc DNS backend, не resolved/NSS cache. `-A` отключает
AI_ADDRCONFIG, чтобы отсутствие IPv4 uplink у IPv6 fixture не подавляло сам A-запрос.
[glibc об этой опции](https://sourceware.org/pipermail/glibc-cvs/2022q4/080707.html).

У системного `nameserver` нет настройки произвольного порта, поэтому только в
стенде DNAT перенаправляет UDP/TCP `127.0.0.53:53` на high-port публичного adapter.
Его production CLI по-прежнему не слушает53 и не меняет firewall.
[Формат resolv.conf](https://man7.org/linux/man-pages/man5/resolv.conf.5.html).

В fixture firewall блокирует остальные исходящие UDP/TCP53 для IPv4 **и** IPv6.
Это намеренно простой guard в пустом netns, не backend для host firewall.
Проверяем23 системных lookup на каждый IPv4/IPv6 exit/upstream вариант:

- Положительные контроли доступности baseline DNS по UDP/TCP, через IPv4 и IPv6.
- Защищённые A/AAAA по UDP и TCP после readiness.
- Остановку exit и восстановление; недоступность port53 mapping и восстановление.
- Чужие изменения `resolv.conf`: отказ перезаписи и блокирование чужого IPv4/IPv6 DNS.
- Восстановление baseline до снятия guard; доступность baseline только после явного disable.
- Отказ readiness до переключения DNS и явный выход из этого состояния.
- Ноль запросов к baseline во время защиты, ноль OS lookup у exit bootstrap;
  освобождение adapter jobs/sockets/timers, отсутствие дочерних процессов и zombies.

Стенд использует combo enc-SNI relay fixture, **не полный clean-vpn процесс**.
TUN, маршруты, uplink, mesh, live exit не затрагиваются. Имеющийся adapter требует
совместимого enc-SNI exit; обычный `tls`-only exit для него не подходит.

## Чего этот этап не доказывает

Нет live backend, reboot/power-loss recovery, произвольных DHCP/VPN manager races,
LAN DNS, split DNS, resolved/NetworkManager integration. В базовой матрице
недоступность mapping моделирует потерю DNS listener. В `--crash` действительно
убивается **контроллер**, но не adapter, не весь backend и не namespace init.
Жизнь adapter принадлежит fixture; start/stop действия dry-run не управляют сервисом.
Проверка утечек — sentinel counters с положительными контролями, не pcap-аудит.
Блокирование53 не является общей защитой от DNS bypass: DoH приложений, DoT853,
другие порты и произвольный трафик требуют отдельной политики. DNS guard также
не заменяет полноценный VPN kill-switch.

Далее: read-only диагностика настоящего клиента → выбор **одного** backend →
адаптация журнала к его владению настройками и VM reboot tests → opt-in live
integration после согласования.
Существующий autostart kill-switch нельзя молча использовать как DNS guard:
его lifecycle и разрешения LAN не обеспечивают описанный выше DNS-контракт.

## Журнал и реальные process-crash tests (`--crash`)

`dns-lifecycle-transaction.mjs` работает в отдельном Node-процессе. Он общается
с fixture backend по ограниченному RPC; backend и настоящий DNS adapter остаются
в namespace init. Parent посылает **SIGKILL** только после подтверждения выбранной
контрольной точки, дожидается смерти процесса и запускает новый контроллер,
который читает журнал с диска, без старого JS state. Проверяется и DNS до recovery.

`flock -n -E 75 -F` удерживает блокировку на стабильном lock inode в течение
жизни контроллера: второй процесс получает75, после SIGKILL новый получает lock.
Нет удаления lock по PID/mtime и «протухших» таймеров.
[util-linux flock](https://man7.org/linux/man-pages/man1/flock.1.html).

Формат журнала фиксирован, ≤8192 байт, файл0600/каталог0700, UID проверяется;
symlink/hardlink, посторонние поля и неверная версия отклоняются. В журнале нет
команд, произвольных путей, секретов или текстов DNS-настроек. Snapshot и managed
config — отдельные приватные файлы. Запись: новый exclusive temp → fsync файла →
rename → fsync каталога; reader никогда не восстанавливается из оставшегося temp.
Для сохранения directory entry одного fsync файла недостаточно.
[Linux fsync](https://man7.org/linux/man-pages/man2/fsync.2.html).

Журнал содержит transaction ID, namespace scope, фазу и `device:inode + SHA-256`
original/managed/restored объектов. Source snapshots проверяются перед mount;
восстановленный текст обязан иметь тот же hash, что исходный. Перед изменением
проверяется текущий объект, а не только его содержимое. Чужой inode с теми же
байтами — conflict. Это не полная атомарная compare-and-swap операция ядра против
произвольного внешнего DNS manager; проверенные изменения контролируются стендом.

Порядок уточнён: **сначала guard, затем snapshot/journal**. Если процесс погиб до
первого commit, recovery блокируется: отсутствующий журнал не разрешает открытый
fallback или выдумывание baseline. Это сознательно может оставить DNS недоступным
до ручного разбора. Ошибка установки самого guard не доказывает fail-closed;
его установка/постоянство на реальной ОС требует отдельного backend.

На каждый IPv4/IPv6 combo вариант выполнены13 убийств контроллера:

- Шесть при enable: после prepared, apply intent, mount; при fsync temp/rename
  active-журнала и после active commit. Recovery возвращает active, сохраняя ID.
- Шесть при disable: restore intent, mount baseline, rename restored-журнала,
  restore commit, снятие guard, released commit. Recovery завершает уже записанное
  **явное** намерение отключения, а не автоматически отключает VPN после сбоя.
- Одно после guard до первого journal commit: recovery отказывает, guard остаётся.

Дополнительно проверены отказ второго контроллера, missing/corrupt journal,
same-content foreign inode, чужой IPv6 DNS, stale namespace scope, повреждённый
snapshot и отказ readiness из-за остановленного exit. Настройки при отказе не
перезаписываются, guard UDP/TCP53 обеих семей остаётся. Счётчики baseline не растут
до авторизованного отключения. После восстановления проверяется glibc lookup.

Released journal сохраняется как terminal record; ротация/архивирование и новый
enable поверх завершённой транзакции пока не реализованы. Каждый testcase получает
свой приватный каталог; reset между ними — действие **оператора стенда**, не
автоматический recovery. После выхода стенда fixtures целиком удаляются.

Флаги отчёта: `crash.journalRecoveryTested=true`, `rebootTested=false`,
`adapterSigkillTested=false`. Верхний `persistentRecoveryImplemented=false`
по-прежнему означает отсутствие полноценного установленного OS lifecycle.
SIGKILL при сохранённом ядре/page cache не моделирует power loss, boot ordering
firewall/resolver или восстановление namespace после reboot. Это ещё предстоит
проверять в VM, не перезагружая живой VPS.
