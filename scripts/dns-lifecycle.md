# DNS lifecycle: offline plan и изолированный стенд

Это **не включение системного DNS в clean-vpn**. Host backend ещё не выбран:
нужна отдельная read-only диагностика реального клиента — systemd-resolved,
NetworkManager, resolvconf либо unmanaged `/etc/resolv.conf`. Автоустановки,
`--apply`, правок systemd units и изменений live VPN здесь нет.

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

npm run test:dns-lifecycle
npm run test:dns-lifecycle-real
```

Dry-run выводит JSON переходов и предлагаемых действий; default scenario `outage`,
также доступен `normal`. Он не проверяет текущую ОС и не является deploy-планом
для конкретного клиента. Флаг opt-in в модели обязателен, но не включает ничего
на хосте. Файл модели — `lib/dns-lifecycle.mjs`.

Стенду нужны Linux, Node22+, glibc `getent` с `-A`, unshare с user namespaces,
mount, iproute2, iptables/ip6tables и OpenSSL. Запускать без sudo; если namespace
или инструмент недоступен, команда завершается ошибкой, без fallback на хост.
Один запуск ограничен45с (+ ограниченное завершение дочернего процесса).
Результат — JSON в stdout; временные сертификаты и fixtures удаляются.

## Согласуемый контракт

| Событие | Предлагаемое поведение |
| --- | --- |
| Явное включение | Сохранить baseline, установить независимый DNS guard, запустить adapter, выполнить защищённый DNS probe |
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
firewall. На реальном клиенте ещё необходимы durable journal, блокировка
конкурентных запусков, проверка владельца/идентичности объекта, атомарные операции
и recovery после SIGKILL/reboot. Сравнение текста в fixture не заменяет эти проверки.

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

Нет live backend, durable snapshot, process-crash/reboot recovery, DHCP/VPN manager
races, LAN DNS, split DNS, resolved/NetworkManager integration. Недоступность
mapping моделирует потерю DNS listener, но это **не SIGKILL тест adapter/supervisor**.
Жизнь adapter принадлежит fixture; start/stop действия dry-run не управляют сервисом.
Проверка утечек — sentinel counters с положительными контролями, не pcap-аудит.
Блокирование53 не является общей защитой от DNS bypass: DoH приложений, DoT853,
другие порты и произвольный трафик требуют отдельной политики. DNS guard также
не заменяет полноценный VPN kill-switch.

Далее: read-only диагностика настоящего клиента → выбор **одного** backend →
журнал владения и crash/reboot tests → opt-in live integration после согласования.
Существующий autostart kill-switch нельзя молча использовать как DNS guard:
его lifecycle и разрешения LAN не обеспечивают описанный выше DNS-контракт.
