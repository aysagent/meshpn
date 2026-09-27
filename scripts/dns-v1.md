# DNS v1: конечный объём и критерии завершения

Цель уточнена 2026-09-26: пригодный для повседневной эксплуатации DNS на VPS и Radxa.
Основные тестовые клиенты — **VPS 2 и Radxa**, VPS 1 не используется для живого
клиентского пилота. Актуальная [матрица клиентов и порядок работ](dns-client-matrix.md).
Это не поддержка всех DNS-менеджеров и сетевых конфигураций.
DNS-функциональность не должна бесконечно задерживать работу над транспортом.

## Граница v1

- Две целевые интеграции: systemd-resolved на VPS и существующий dnsmasq на Radxa,
  после проверки владельца настроек. Это целевой объём, не заявление о готовности.
  Клиент и управляемый интерфейс должны быть явно выбраны; факт запуска resolved
  сам по себе не разрешает перезаписывать настройки networkd/NetworkManager.
- Клиентские запросы идут через существующий adapter → числовой exit →
  проверенный DoH upstream. Проверка CA/hostname и pinned bootstrap IP обязательны;
  прямой/plaintext fallback запрещён.
- Политика защиты системного DNS охватывает UDP/TCP53 IPv4 **и** IPv6. DNS AAAA
  не означает поддержку IPv6 data plane: clean-vpn пока туннелирует IPv4.
- На VPS 2 требуется явная политика облачных внутренних имён; на Radxa — сохранение
  USB DHCP и локального DNS. Произвольный LAN/split DNS не входит в объём.
  Неизвестные настройки отклоняются с диагностикой, а не молча упрощаются.
- Смена владельца, link identity, boot/context — повод сохранить журнал и
  остановиться для review. Безопасная остановка допустима; автоматическое
  присвоение чужой конфигурации не требуется для v1.

Отдельные приложения с собственными DoH/DoT, mDNS/LLMNR, всеобщая фильтрация
трафика и полноценный VPN kill-switch — отдельные границы. Нельзя выдавать
защиту системного resolver за предотвращение любых возможных запросов имён.
Resolved имеет несколько API и источников конфигурации; это причина проверять
политику клиента целиком, а не только строку nameserver.
[systemd-resolved v255](https://github.com/systemd/systemd/blob/v255/man/systemd-resolved.service.xml).

## Что уже есть

DoH wire/CA/bootstrap, bounded adapter, private resolved backend, write-ahead
journal, SIGKILL/restart контроллера и adapter, VM reboot/power-cut матрица.
Это проверенные составляющие, **не установленная системная DNS-интеграция**.
Для dnsmasq добавлены [private file journal и namespace recovery](dnsmasq-journal.md)
с сохранением USB DHCP, семью SIGKILL контроллера и OUTPUT/INPUT/FORWARD guard.
Отдельный [dnsmasq systemd/reboot стенд](dnsmasq-vm.md) проверяет настоящий
service lifecycle в VM, сохранение DHCP при отказе adapter и отклонение старого
boot-context. Это не live host takeover и не автоматическое принятие старого журнала.
Для системного resolver Radxa добавлена [транзакция dangling symlink](dns-resolver-object.md):
7 controller SIGKILL, 9 реальных NSS-проверок и 3 конфликта в synthetic `/etc`, PASS.
Она сохраняет USB DHCP, точно возвращает ссылку и сама не снимает guard.
Общий [координатор с dnsmasq](dns-radxa-journal.md) прошёл 15 controller SIGKILL,
62 USB/dnsmasq проверки и 7 DHCP DORA в namespace. Его [VM lifecycle](dns-radxa-vm.md)
прошёл 12/12 проверок в двух загрузках и 3/3 whole-guest crash точки (ещё шесть загрузок);
точный возврат сломанной ссылки не означает восстановление исправного baseline.
Добавлен явный localhost-file baseline resolver для будущего согласованного
перехода Radxa; live repair и снятие guard этим не разрешаются.
Для VPS 2 [resolved 249 + networkd](dns-networkd-lab.md): 11 namespace-проверок
настоящего DHCP renew/reconfigure и отдельного VPN DNS-link, без takeover `eth0`.
Явная QNAME deny-policy проверена при удалении/замене DHCP domains. Ещё нужны
выбор live-политики (блокирование/защищённый resolver) и установщик/откат.
Отдельный [empty-link journal](dns-owned-link-journal.md)
проверен с 18 controller SIGKILL, [coupled namespace-координатор](dns-coupled-journal.md)
с address/UP и DNS-state — с 17 controller SIGKILL. Его
[systemd/reboot VM-режим](dns-coupled-vm.md) — 11/11 PASS в двух загрузках,
без автоматического принятия старого epoch; три whole-guest crash точки —
3/3 PASS (ещё шесть загрузок). Физический power loss хоста не моделируется.
Это ещё не live-проверка VPS 2.
В README отдельно отмечены ограничения транспортов, маршрутов и IPv6.
Для следующего клиентского этапа подготовлен [read-only preflight](dns-client-preflight.md):
служба/процесс/источники config и networkd-selected file собираются одной командой.
Он не устанавливает интеграцию и не закрывает live-критерии ниже.
CLI адаптера получил [явную стартовую readiness](dns-exit-adapter.md#проверка-перед-объявлением-готовности)
через UDP/TCP A/AAAA и opt-in systemd notification. Ошибки/отмена/восстановление
проверены на настоящем CLI в IPv4/IPv6 namespaces. Его отдельный service теперь
прошёл [systemd 255 VM lifecycle](dns-systemd-vm.md): 12/12 проверок в двух загрузках,
с независимым exit/origin fixture и adapter-only SIGKILL. Установщик и клиентские
пилоты остаются; другие VM cases пока используют свои прежние fixture services.
Добавлен [offline renderer клиентского adapter service](dns-adapter-service-plan.md)
с DynamicUser/credentials. Он ничего не устанавливает; 25 unit/CLI проверок
и новый непривилегированный VM lifecycle (12/12, две загрузки) прошли.
VM использует2 vCPU MTTCG при неизменном DoH deadline1500мс; это не benchmark
Radxa или подтверждение live-конфигурации. Подробности отказов и диагностики —
в отчёте [systemd VM](dns-systemd-vm.md).
Выделен общий [client guard executor](dns-client-guard.md): собственные цепочки,
проверка порядка/владения, отдельные IPv4/IPv6 commits, без global firewall restore.
Его [persistent journal](dns-client-guard-journal.md) прошёл16 controller SIGKILL
для двух профилей. Добавлен [ранний systemd guard](dns-boot-guard.md), проверяемый
на реальном CLI в VM: независимая boot policy, stop без удаления правил,
без принятия stale DNS journal. **16/16 проверок в двух загрузках VM, PASS**,
Node1659/1659. Привязка journal к ID boot policy и exact resolved restore proof
теперь проверены под одним lock: **20/20 в двух загрузках VM, Node1670/1670,
22 namespace SIGKILL PASS**. Следующая связка уже подключена к целевому
coupled backend VPS2: отдельный DNS-link, настоящий CLI adapter с DynamicUser,
общий boot/DNS lock, root/link/guard журналы и доказательство удаления своего
link перед release. **19/19 в двух загрузках VM PASS**, Node1674/1674.
Новая аварийная матрица **3/3 PASS, шесть загрузок, по9 проверок**.
Результаты и отказы этой новой связки учитываются отдельно в
[coupled VM](dns-coupled-vm.md), не наследуются от прежнего fixture.
Radxa coordinator с явно заданным localhost-file baseline теперь также связан
с boot guard/CLI adapter: **20/20 в двух загрузках VM PASS**, Node1677/1677.
Аварийная матрица этой связки: **3/3 PASS, шесть загрузок, по9 проверок**;
точные snapshot-границы записаны в [Radxa VM](dns-radxa-vm.md).
Его guard снимается только после завершения трёх DNS-журналов и подтверждения
реального dnsmasq с restored config; dangling baseline этим не разрешён.
Далее — live controllers, opt-in установщик/откат и пилоты. VM не выполняет
согласование или repair baseline настоящей Radxa.
Файловая часть opt-in установки теперь имеет [журнал и точный откат](dns-deployment-files.md):
пять фиксированных новых artifacts, без overwrite существующих файлов, 47/47
проверок, включая7 process SIGKILL. Это ещё не live entrypoint: активация служб,
реальные клиентские controllers и полный uninstall остаются следующим шагом.
Координация двух профилей выделена в [общий client controller](dns-client-controller.md)
и подключена к обоим VM workers: единые `start`/`disable`, guard-first порядок,
выбор настоящего restore proof, запрет неявного разворота restore в start.
Это ещё не live OS factories/entrypoint; прежние VM authority gates сохранены.
Новые lifecycle VM общего controller: VPS2 **19/19**, Radxa **20/20**, каждый
в двух загрузках PASS; Node1735/1735 PASS. Это не установка на живых клиентах.
Последующий fix делает начальное разрешение guard binding одноразовым внутри
lifecycle; потеря журнала не вызывает повторную привязку.57 unit/1740 Node PASS,
граница VM-среза и исправления — в [guard journal](dns-client-guard-journal.md).
Общий [исполнитель команд ОС](dns-system-command.md) подключён к обоим VM
controller: root-pinned tools, fixed system D-Bus, наследование lifecycle flock
командами. Новый прогон VPS2:19/19, Radxa:20/20, по две загрузки PASS;
Node1754/1754 PASS. Сохранён также первый отказ readiness Radxa до запуска
controller; отдельный повтор прошёл без увеличения таймаутов. Это ещё не live
OS authority/entrypoint и не установка; private fixture files нельзя напрямую
подставлять вместо публично читаемого resolver настоящего клиента.
Добавлен public-layout resolver backend: target0644/parent0755 отдельно от
private snapshots/journal0700, проверка same mount и identity обоих каталогов.
После исправления EXDEV, подготовки TLS-контекста один раз при startup и
добавления ограниченной трассы новая public-layout Radxa VM прошла
**26/26 в двух загрузках**, включая NSS обычного UID, private state и offline
restore (`meshpn-dns-vm-L5itxn`, срез `1de98a7`). Node1779/1779 PASS.
Прежние отказы startup1500мс не скрыты; успешный прогон не устанавливает их
причину. Трассы и границы результата — [resolver object](dns-resolver-object.md).
Новая трёхточечная crash-матрица выполнена: **3/3, шесть загрузок, по12 проверок
PASS** (`meshpn-dns-vm-ZqbtFB`, `c3ccc0c`, уже с TCP noDelay). Baseline queries0
под guard, positive controls PASS, host DNS unchanged. Эта конечная матрица
public-layout завершена; installed entrypoint/установщик и пилоты остаются.
Начат [installed opt-in/authority](dns-installed-authority.md): отдельное
разрешение связано с bundle/config hash и guard ID, есть только read-only
`dns-client.mjs --inspect`. Это не готовая команда переключения DNS;
OS factories/mutating commands пока не подключены.
VPS2 installed `--inspect` получил строгий config и read-only baseline проверки:
уникальные D-Bus владельцы resolved/networkd, runtime-selected network file/hash,
явная deny-policy внутренних имён, stub/NSS и отсутствие конфликтов DNS-link.
После исправления scalar D-Bus property и подготовки настоящего networkd
в VM installed CLI прошёл позитивный и три отрицательных сценария в каждой
загрузке. Новый coupled lifecycle: **21/21, две загрузки PASS**,
`meshpn-dns-vm-KXJ20n`; Node1841/1841 PASS. Это read-only baseline, **не mutation
authority**. Следом — installed запуск/отключение, согласованное исключение
DNS-link из networkd, loaded adapter credentials, установщик/откат обеих
платформ. Ограничения и схема — [installed authority](dns-installed-authority.md).

Явное networkd-исключение теперь входит в VPS2 file plan (шесть файлов;
Radxa по-прежнему пять). Реальный networkd249 подтвердил unmanaged для нашего
link и managed для отрицательного контроля, включая DHCP renew/reconfigure.
Coupled journal прошёл 17 SIGKILL, чужие/повреждённые/stale данные отклонены,
оставшихся owned links и baseline DNS queries под защитой — 0.
Node **1853/1853 PASS**, включая same-device/different-mount отказ публикации.
Installed baseline проверяет файл исключения, но это ещё не доказательство
загруженной политики: runtime-проверка нужна в installed OS factory перед
setters. Предыдущие 21 VM-проверка предшествуют этому новому file gate;
installed start/disable и интеграция установщика всё ещё впереди.

Следующий шаг: добавлена [проверка загруженного adapter](dns-installed-adapter.md)
через installed `--inspect-adapter`: настоящий PID/unit/argv, изоляция процесса
и побайтное совпадение трёх credentials с исходными файлами. На первом boot
NIC-less VM проверены позитивный случай и отказ после изменения ключа только
на диске. Общая Node-регрессия1870/1870 PASS; двухзагрузочный прогон затем
завершился21/21 PASS (`meshpn-dns-vm-TJnMKi`, source617cb49).
Проверка не отправляет DNS и не разрешает takeover. Следом нужны привязка
UDP/TCP listener к этому PID, readiness под guard и installed setters/lifecycle;
на живых клиентах ничего не менялось.

Socket ownership и явный `--probe-adapter` реализованы следующим срезом:
проверяются реальные loopback UDP/TCP inode, FD MainPID и UID; guard должен
уже присутствовать перед четырьмя запросами, процесс/credentials/listener
повторно сверяются после них.1890/1890 Node PASS, включая реальные сокеты
чужого PID и закрытие listener. Это ещё **не VM PASS нового probe**: завершённый
`meshpn-dns-vm-TJnMKi` содержит предыдущий617cb49; следующий образ должен
проверить новые socket/readiness-сценарии и точные счётчики запросов.

## Три этапа и текущий статус

1. **Boot-fault VM (выполнен:4/4 PASS):** ошибка установки guard, read-only storage журнала,
   повреждённый journal, провал protected readiness. Проверить отсутствие DNS
   setters до успешной подготовки, сохранность данных, отсутствие baseline
   fallback и явное восстановление. Эта матрица конечна: четыре сценария.
2. **[Интеграция и systemd в VM](dns-systemd-vm.md) (выполнен в VM):** обычный guest systemd PID1, явный opt-in,
   управляемые start/stop/restart/boot, отказ dependencies, актуальный baseline,
   отказ при конфликте владельца и безопасный disable. Проверен реальный исполнитель
   и измеренный порядок запуска; повтор на настоящих CLI adapter/boot guard:
   20 проверок в2 загрузках с общим guard journal/lock, PASS. Это не live installer
   и не замена отдельных target VPS2/Radxa интеграций.
3. **[Пилоты VPS 2 и Radxa](dns-pilot.md):** сначала доделать обе системные интеграции
   и проверить их клиентские профили по матрице, затем проверить исходный DNS
   и аварийный доступ; с отдельным разрешением установить интеграцию. Один
   ограниченный 24-часовой прогон на каждом из двух клиентов и фиксированный набор событий: запуск,
   3 переподключения, рестарт adapter, отказ exit, reboot, явное отключение.
   Независимый захват на uplink проверяет отсутствие запрещённого fallback;
   фиксируются восстановление, ресурсы и итоговое состояние настроек.

Первые два этапа выполняются без изменения живого клиента. Пилот нельзя считать
завершённым только по VM: нужны конкретный клиент, доступ и согласованные изменения.
VPS в роли клиента должен подключаться к **другому** exit. Radxa с оборванным
resolv.conf symlink сначала требует согласованного восстановления baseline;
автоматически включать resolved на ней этот план не разрешает.

## Отсечка «DNS v1 завершён»

Последний локальный этап: [installed VPS2 controller](dns-installed-controller.md)
прошёл настоящий CLI start/disable на двух загрузках NIC-less VM,6/6 PASS
(`meshpn-dns-vm-M08EIu`). Проверены active/released journals и удаление link;
это не active-transaction reboot, не готовый installer и не live-пилот.
Ограниченные [systemd controller units](dns-controller-service-plan.md) затем прошли
8/8 в двух загрузках (`meshpn-dns-vm-SGJprZ`,6961374): stop/restart, SIGKILL adapter
и disable без adapter. Ранний boot graph опубликованных drop-ins, полноценный
baseline-positive-control и installer ещё впереди; далее также installed Radxa
backend. Живые критерии ниже не закрыты.

Файловый этап установщика расширен до явного приватного VPS2-набора:
ключ/config/opt-in публикуются с журналом, opt-in — последним и удаляется первым.
Прежние наборы не обновляются автоматически. Это не установленный bundle и не
активация служб; следующий шаг — публикация кода, настоящая inactive-проверка
и единая VM-проверка install/activate/disable/uninstall.
Для кода добавлена [отдельная файловая транзакция](dns-deployment-bundle.md):
проверенная копия, write-ahead publication без overwrite и rollback с сохранением
bundle в private archive. Это ещё не единый installer или live activation.
Добавлена [настоящая OS-проверка неактивности перед первой установкой](dns-deployment-inactive.md):
PID1/D-Bus, jobs/cgroups, процессы, links, оба firewall и отсутствие runtime history.
Она не является restore proof и не разрешает удаление после активации.
Отдельный VM-сценарий прошёл14/14 на двух загрузках (`meshpn-dns-vm-RchXdO`),
без DNS queries и изменений DNS хоста; это ещё не installer PASS.
Обе файловые транзакции связаны [общим журналом публикации](dns-deployment.md):
код перед opt-in, откат конфигурации перед архивированием кода. Это ещё
библиотечная inactive-only установка, без host CLI/активации; полный bundle
с реальными OS-проверками теперь прошёл отдельную файловую VM-проверку:
270 code files +13 client files, публикация/import graph/inactive rollback,
**6/6 PASS на двух загрузках** (`meshpn-dns-vm-9CAnjT`). Это не запуск DNS,
не active-transaction reboot и не uninstall после использования; единый
activate/disable/uninstall и ранний boot graph остаются следующим шагом.
Для uninstall подготовлен отдельный read-only `inspectReleasedDnsDeployment`:
три released-журнала, текущий boot/bus/resolved context и реальная неактивность
ОС проверяются без удаления истории. Fresh gate не ослаблен. Отдельный
VM `start → disable → inspection` прошёл **14/14 на двух загрузках**
(`meshpn-dns-vm-2CDNva`), включая отказ при активном журнале/работающем service
и успешную проверку без opt-in/config. Режим пока не подключён к установщику;
последующий файловый rollback ещё должен быть проверен в едином сценарии.
Это не active-transaction reboot и не положительный baseline health test.

Этот чек-лист выполняется для VPS 2 и Radxa. VM PASS подтверждает отдельные
механизмы, но не ставит автоматически галочки за live-конфигурацию и пилот.

- [ ] Поддержанная конфигурация и владелец DNS документированы и проверяются до takeover.
- [ ] Защищённый UDP/TCP readiness предшествует выбору managed DNS; DNS-настройки
  не меняются при отказе guard/storage/readiness или повреждённом журнале.
- [ ] Включение, остановка, авария, reboot и повторный запуск соответствуют
  измеренной fail-closed политике. При невозможности установить guard нельзя
  заявлять о защите: контролируемые network/consumer dependencies не запускаются.
- [ ] Чужие изменения не затираются; disable восстанавливает только принадлежащий
  текущему context baseline. Старые данные сохраняются для review.
- [ ] Клиентский пилот прошёл: разрешённые запросы работают, запрещённого DNS
  fallback нет, память/сокеты/таймеры/процессы в согласованных бюджетах.
- [ ] Есть инструкция установки/проверки/отключения и проверенный откат.
- [ ] На Radxa сохранены DHCP/локальные имена, проверены USB DNS-путь и его обходы.
- [ ] На VPS 2 проверены политика внутренних имён и DHCP reapply без direct fallback.

После выполнения этих критериев — фиксируем DNS v1 и возвращаемся к транспорту.
Другие менеджеры DNS, произвольный LAN/split DNS, hot reload, собственный DNSSEC
validator и физическое отключение питания накопителя не становятся новыми
обязательными этапами v1. Критерии не ослабляются ради даты; новые пожелания
выносятся в отдельные задачи. Прежние VM результаты не закрывают новые сценарии
нового VPN DNS-link или live dnsmasq/USB: точные клиентские конфигурации,
cloud-name policy, системный resolver Radxa и оба пилота ещё требуют проверки.
