# DNS: VPS 2 и Radxa — основные тестовые клиенты

Уточнение объёма пользователя 2026-09-26: запуск нужен на обоих VPS и Radxa,
а не только на одном выбранном клиенте. VPS 1 исключён из **живых клиентских
испытаний**; совместимость обычной resolved-конфигурации остаётся направлением,
но её сходство с VPS 2 не означает live PASS на VPS 1.

| Клиент | Наблюдаемая схема | Оставшаяся работа |
| --- | --- | --- |
| VPS 2 | Ubuntu 22.04, resolved 249, networkd/DHCP, DNS 10.129.0.2, ru-central1.internal / auto.internal | Прочитать effective network config (в отчёте EACCES), выбрать политику внутренних имён, проверить DHCP reapply и версию 249 |
| Radxa | Armbian/Debian 12 arm64, dnsmasq, usb0, no-resolv, два публичных upstream, dangling resolved symlink | Подтвердить include/daemon config, сохранить USB DHCP/локальные имена, исправить неоднозначную DHCP option 6 и системный resolver через управляемый переход |
| VPS 1 | Ubuntu 24.04, resolved 255/networkd, явный DNS 8.8.8.8, Docker | Не использовать как живой тестовый client; контейнерный DNS не считать покрытым системным |

Исходные наблюдения: `fixtures/dns-clients/`. Это не deployment templates,
не полная effective config и не разрешение на takeover. Адреса VPS/MAC из
диагностических отчётов специально не сохраняются в fixtures.

## Общая архитектура

Обе системные интеграции используют существующий DNS adapter → числовой exit →
проверенный DoH resolver. Для Radxa сохраняется dnsmasq, принудительный переход
на resolved не нужен. Во время protected mode прямые upstream должны быть
**заменены**, а не дополнены локальным adapter; `no-resolv` сохраняется.

На VPS 2 политика облачных имён остаётся невыбранной. Нельзя ни автоматически
оставить direct exception, ни молча отправить внутренние имена публичному resolver.
Mock backend уже проверяет точное восстановление наблюдённого DNSEx/Domains и
отказ при DHCP-подобном возврате чужих настроек; это не настоящий DHCP/networkd тест.

Общий dnsmasq Radxa обслуживает системные и USB-запросы одним upstream. Его
переключение затрагивает обе группы: нельзя обещать защиту только одного входа
через общий DNS forwarding. Запросы USB-клиента напрямую к сторонним DNS обходят
dnsmasq и требуют отдельной routing/guard проверки. DHCP option 6 их не блокирует.

## Порядок работ и конечная граница

1. Диагностика и исходные fixtures. Ограничить общий command concurrency;
   не исполнять конфиги/хуки при сборе; не выбирать backend автоматически.
2. Два изолированных профиля: resolved 249 + cloud DNS/DHCP reapply; dnsmasq +
   USB peer с настоящим DHCP/DNS. [Первый dnsmasq smoke](dnsmasq-lab.md) реализован,
   но lease exchange, host takeover, guard и durable recovery в нём отсутствуют.
3. Реальные ownership/journal/guard и start/stop/restart/reboot для обеих схем.
   Radxa resolv.conf переключается отдельной проверяемой транзакцией, а не
   слепой заменой dangling symlink. DHCP не должен отключаться при отказе exit.
4. Реальные units/config и откат проверяются в VM, затем с отдельным разрешением
   и независимым аварийным доступом — по одному ограниченному 24-часовому пилоту
   на VPS 2 и Radxa. VPS client соединяется с другим exit.

DNS v1 закрывается после выполнения чек-листа для обеих схем, а не после первого
успешного VPS. Настоящая Radxa/arm64, точные версии и USB-путь требуют измерения;
x64 dnsmasq smoke это не заменяет. IPv4/IPv6 DNS guard обязателен, но AAAA-ответ
не означает поддержку IPv6 data plane. Собственные DoH/DoT приложений, произвольные
LAN, другие менеджеры и общий VPN kill-switch не становятся обещаниями этой версии.
