# Журнал принадлежащего VPN DNS-интерфейса

Статус: отдельный слой **пустого dummy-интерфейса** в private namespace,
не установщик и не восстановление всей DNS-интеграции. Проверен на
resolved/networkd 249 из Ubuntu `.22`, dnsmasq 2.90, Linux 5.4 стенда.

```bash
node scripts/dns-networkd-lab.mjs --link-journal \
  --systemd-dir=/absolute/path/to/extracted/lib/systemd \
  --dnsmasq=/absolute/path/to/dnsmasq

MESHPN_SYSTEMD249_DIR=/absolute/path/to/extracted/lib/systemd \
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run test:dns-owned-link-real
npm run test:dns-owned-link
```

Запуск обычным пользователем, не sudo. Все требования и границы изоляции — в
[networkd-стенде](dns-networkd-lab.md). Без `--link-journal` остаётся прежняя
11-сценарная DNS/DHCP матрица. С флагом после неё запускается новый набор, в том
же изолированном окружении, без сети хоста. Тайм-бюджет launcher — 120 секунд.

## Что хранится и восстанавливается

Private regular journal `0600` внутри owned directory `0700`, один writer под
process-lifetime `flock`. Переходы записываются через fsync временного файла,
rename и fsync каталога. Остаточные временные файлы не используются при recovery.

В журнале: случайный id, namespace net/mnt/pid, boot ID, bus ID, уникальный owner
resolved, имя интерфейса, ifindex после создания и текущая фаза. Имя `cvdns…`
содержит 32 случайных бита, locally administered MAC — другие 40 бит id.
Они задаются при создании; полная метка `clean-vpn-dns:<id>` ставится в alias
отдельной операцией с собственным write-ahead intent.

Это важно: в фактическом окружении `ip link add … alias …` сохранил MAC, но
не сохранил alias. Промежуток до отдельного setter теперь явно журналируется
и проверяется SIGKILL. До первого ACK допустимо принять только совпадающие
имя/MAC/type/пустое состояние с durable create-intent; после ACK дополнительно
обязателен тот же ifindex. Recovery не ищет «похожий» интерфейс по одному имени.

Последовательность: prepared → create-intent → unstamped → stamp-intent →
created → delete-intent → deleted → released. Recovery продолжает последнюю
**зафиксированную** операцию. Если запись delete-intent не дошла до rename,
действителен предыдущий created state: для удаления нужно снова явно disable.
Отмена до фактического создания сохраняется и не создаёт интерфейс при recovery.

## Защита от чужих изменений

Создаётся только dummy, DOWN, MTU 1500, без master и IP-адресов. DNSEx и Domains
должны быть пустыми. У пустого link допускаются оба значения автоматического
DefaultRoute; без DNS-сервера это не новый DNS-путь. Перед setters/deletion
backend повторно проверяет контекст и наблюдаемое состояние.

Неверная метка/MAC/ifindex, поднятый интерфейс, адреса, DNS/domains, отсутствующий
созданный интерфейс, повторное использование удалённого имени, другой boot/bus/
daemon owner/namespace, missing/corrupt journal — отказ с сохранением guard,
без исправления чужих настроек. Уже настроенный DNS-интерфейс этот слой **не
удаляет**: его должен сначала освободить будущий координатор DNS-транзакции.
Старый boot-context намеренно не принимается автоматически.

Это проверка принадлежности между сотрудничающими компонентами, не защита от
root/CAP_NET_ADMIN противника: он может подделать маркеры или изменить link
между проверкой и kernel command. `flock` не блокирует сторонних администраторов.
Не проверяются все возможные link attributes/sysctl, только указанный контракт.

## Проверки

- 17 границ write-ahead/create/stamp/delete/release и один SIGKILL сразу после
  установки guard без журнала: **18 настоящих SIGKILL контроллера**.
- Конкурирующий контроллер получает lock conflict; исходный продолжает владеть lock.
- 6 отказов: missing/corrupt journal, чужой alias, настроенный DNS, пересоздание
  с теми же маркерами и другим ifindex, подменённый boot ID.
- После аварии до ACK создания прямой DNS блокируется; после явного disable
  возвращается актуальный DHCP DNS. Временных owned links не остаётся.
- Private PID1 остаётся единственным процессом, zombies=0; host DNS files и
  forwarding неизменны. Unit-тесты дополнительно покрывают другие конфликты.

Контроллер журнала действительно убивается, но backend RPC исполняет переживший
его namespace supervisor. Это не SIGKILL supervisor/daemon/ядра, не power loss и
не VM reboot. Подменённый boot ID — тест отказа, не выполненная перезагрузка.

## Следующий этап

Согласовать в одном write-ahead координаторе создание link, address/UP, применение
DNSEx/Domains/DefaultRoute, отказ адаптера и отключение в обратном порядке.
Только после освобождения DNS/address-state разрешать удаление link и снятие
guard. Затем проверить совместные границы SIGKILL и systemd/reboot в VM.

В JSON отдельный `ownedLinkJournal` имеет `dnsSettingsCoupled:false` и
`rebootTested:false`; верхний `durableJournalTested:false` по-прежнему означает,
что основная 11-сценарная DNS-транзакция пока использует in-memory backend.
Не переносить этот standalone fixture на live VPS/Radxa. DNS v1 ещё не закрыт.
