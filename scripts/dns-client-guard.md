# Клиентский DNS guard: общий исполнитель VPS 2 / Radxa

`lib/dns-client-guard.mjs` — reusable исполнитель правил для будущего клиентского
controller, **не установщик и не самостоятельная команда host apply**.
Ранее guard жил внутри конкретных стендов; теперь правила и проверка владения
общие для обоих клиентских профилей. Persistent guard journal/systemd entrypoint
ещё не подключены. Нельзя копировать лабораторные команды на рабочий хост.

## Политика

| Профиль | OUTPUT UDP/TCP53 | INPUT/FORWARD |
| --- | --- | --- |
| VPS 2 | Только `127.0.0.53` через `lo`; остальной IPv4/IPv6 DNS53 DROP | Не меняются; gateway/контейнерный DNS не входит в этот профиль |
| Radxa | Только `127.0.0.1`/`::1` через `lo`; другие назначения DNS53 DROP | Для указанного USB-интерфейса INPUT допускает только явно выбранный локальный IPv4 DNS; другой DNS53 INPUT и весь DNS53 FORWARD IPv4/IPv6 DROP |

Разрешённый локальный путь использует `RETURN`, не `ACCEPT`: чужие ограничения
firewall после нашего hook продолжают действовать. Не-DNS трафик, включая DHCP,
возвращается в исходную цепочку. Нет исключения для established DNS connections.
Порты адаптера выше1023 не затрагиваются. DoH/DoT приложений, mDNS, DNS на другом
порту и полноценный VPN kill-switch не являются обещаниями этого guard.

Radxa: USB DNS и системный localhost DNS используют общий dnsmasq. Его forwarding
должен быть переключён на adapter до допуска запросов; guard сам upstream не
меняет. DHCP option6, восстановление resolv.conf и проверка локальных имён —
обязанности общего controller. Здесь не выбирается DNS policy облачных имён.

## Владение, применение и снятие

Вход строго задан: `{schema:1,client:'vps2'|'radxa',id:<32 lower hex>}`; Radxa
дополнительно требует `usbInterface` и `usbAddress`. ID генерируется и сохраняется
controller до первого setter. Один управляемый guard на network namespace.
Имена цепочек `CVD_<16 hex>_O/I/F`, полный ID в comments. Совпадение сокращённого
имени не даёт права присвоить цепочку: сравниваются полный ID и все правила.

Исполнитель получает bounded `read(family)` (iptables/ip6tables `-S`),
`restore(family,batch)` (`iptables-restore --wait 2 --noflush`) и обязательный
`assertContext()`. **Caller** держит flock, проверяет namespace/boot/backend,
identity USB-интерфейса и долговечный intent; модуль не подменяет эти проверки.
Нельзя использовать произвольный `assertContext:()=>{}` на клиенте.

До setters проверяются обе семьи: цепочки либо полностью отсутствуют, либо
совпадают по правилам, порядку, references и первому месту hook. Чужие, неполные,
дублированные или переставленные правила отклоняются без исправления за владельца.
Есть предел256KiB на снимок. Посторонние цепочки/правила не сериализуются обратно.

Каждая семья применяется одним restore batch. Используется `-N`, а не декларация
`:CHAIN`: существующая одноимённая цепочка должна вызвать ошибку, не flush.
`--noflush` сам по себе **не** защищает объявленные пользовательские цепочки
от очистки — это видно в [реализации Netfilter](https://git.netfilter.org/iptables/tree/iptables-restore.c?id=f69e30c0107ceff61296045cfd36ea0506d54186).
Общего атомарного commit между IPv4 и IPv6 нет. Отказ второй семьи сохраняет
первую; успех объявляется только после readback обеих. Пропавшее подтверждение
commit восстанавливается чтением без дублирования. Во время незавершённой установки
нельзя объявлять защиту полной или запускать controlled workloads.

Снятие — только `release(authorizeRestoredBaseline)` после явного согласованного
restore; callback должен проверять долговечное намерение и актуальный baseline.
Нет снятия при stop/destructor, rollback после ошибки установки или восстановления
всего firewall из старого снимка. Удаляются точные правила и пустые собственные
цепочки; `-F` не используется. Чужое добавление может сорвать removal, оставив
правила для review. Ошибка одной семьи не разрешает удалять вторую вслепую.

Внешний firewall manager, который параллельно переставляет/сбрасывает правила,
не является поддержанным ownership-контекстом. Readback не предотвращает изменение
после проверки; план установки должен отклонять такую конфигурацию либо иметь
отдельно согласованную координацию. Проверка только `active` у guard service
недостаточна. Backend `legacy`/`nf_tables` должен быть зафиксирован controller.

## Проверки

```bash
npm run test:dns-client-guard
MESHPN_DNSMASQ=/absolute/trusted/dnsmasq npm run dns:client-guard-lab
```

Lab сам создаёт private user/network/PID/mount namespaces. Внутри user namespace
UID0 нужен для локального forwarding sysctl; host sudo не нужен. Создаются только
synthetic veth USB/uplink и DNS/DHCP fixtures. Нет TUN, SSH, внешнего сетевого
доступа, установки пакетов или host DNS setters. `--isolated` на хосте отклоняется.
Проверяется неизменность host resolver/NSS и обоих forwarding sysctl.

Матрица: положительные DNS controls до защиты, отказ IPv6 commit и сохранение
IPv4 deny, обе IP-семьи и UDP/TCP, локальный stub, неперекрытие чужого firewall,
конфликт первого hook, сохранность сторонних правил после release; Radxa —
реальный USB DHCP DORA, DNS53 INPUT/FORWARD bypass и точный возврат baseline.
Отдельно в момент release после проверки добавляется чужое правило в собственную
цепочку: commit обязан отказать, оставив весь предыдущий family ruleset нетронутым.
Это проверка исполнителя, не SIGKILL durable journal или live клиентский пилот.

2026-09-27: **30/30 unit/host-refusal PASS**, **11/11 namespace PASS**,
iptables/ip6tables1.8.10 `nf_tables`, dnsmasq2.90; два настоящих DHCP DORA.
Node-регрессия **1602/1602 PASS**, `/var/tmp/meshpn-acceptance-bKaw65/report.json`.
Legacy backend, persistent journal, boot ordering и реальные версии клиентов
не выводятся автоматически из этого результата. Следующий шаг — сохранить
guard intent/identity и подключить проверку к клиентскому systemd controller.
