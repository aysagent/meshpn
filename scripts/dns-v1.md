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
