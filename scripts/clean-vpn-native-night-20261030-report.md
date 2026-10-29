# Ночная работа 30 октября: native clean-vpn

Основные пункты выполнены и проверены отдельно от повседневной пары. Новые
бинарники и функции не устанавливались в daily-сервисы Radxa/VPS. Настройки
сети Mac не менялись. Физический transparent smoke использовал временные
изолированные экземпляры; отдельный отчёт фиксирует восстановление состояния.

## Готовые изменения

| Область | Результат | Где пользоваться и читать ограничения |
| --- | --- | --- |
| Именованные клиенты | `add laptop`, автоматический стабильный IP, отдельные ключи, export/import, rename/revoke/rotate, журнал и recovery | [CLI](clean-vpn-native-clients.md) |
| Работающий exit | Atomic peer reload через SIGHUP; неизменённые сессии продолжают работу, отозванные закрываются | [Reload и доказательства](../fixtures/clean-vpn-native-peer-reload-20261030.json) |
| `laptop.mpn` | Приватный UDP/TCP resolver, scoped systemd-resolved zone на exit, клиентский DNS через authenticated tunnel; без public fallback | [DNS](clean-vpn-native-peer-dns.md) |
| Админка | Управление клиентами exit, capabilities по роли/транспорту, сроки сертификатов, диагностический экспорт без credentials | [Отдельная установка exit](../admin/EXIT-INSTALL.md) |
| VPN + web одним запуском | Managed Compose, отдельный непривилегированный web, Unix broker, без Docker socket у приложения, optional DNS sidecar | [Compose](clean-vpn-native-managed-containers.md) |
| Alpine | Исходная ARM64 musl сборка, runtime около 101 MiB на первоначальном измеренном snapshot; финальные образы имеют отдельные ID/размеры в отчётах | [Alpine](clean-vpn-native-alpine.md) |
| Получение адреса от exit | Opt-in H1/H2 discovery с PSK/TLS-exporter proof, затем отдельное подтверждение полной сессии; изолированный owner и Compose | [Runtime assignment](clean-vpn-native-runtime-address.md) |
| Обновление сертификата | Новый leaf/key под прежним CA в отдельном candidate-каталоге, без установки или restart; проверка неизменности trust | [Renewal](clean-vpn-native-certificate-renewal.md) |

Адрес по-прежнему закреплён за зарегистрированной идентичностью на exit.
Discovery убирает необходимость хранить его в клиентском config, но не создаёт
DHCP leases и не позволяет двум устройствам с одним ключом стать независимыми
клиентами. Имя `laptop.mpn` не заменяет USB-админку `mpn.local`.

## Проверки с существенными результатами

- Linux enrollment — 8/8: boring/combo, H1/H2, fixed/discovery, ротация и
  настоящий native обмен пакетами.
- Exit admin/systemd — по 9/9 boring и combo; реальный web→broker→manager→native.
- `.mpn` — 23/23 scoped resolved и 11/11 native tunnel/NSS, затем пять минут:
  минимум 17724 запроса, 64 рестарта resolver, без private DNS fallback.
- Исправлены и отдельно воспроизведены registry ABA-гонка при rollback и DNS
  DNAT до появления/после удаления TUN. Для второго случая есть независимый
  WAN capture на nft и legacy; удаление `LOCAL` из лабораторной копии правил
  действительно ломает тест.
- [15-минутный combo soak](../fixtures/clean-vpn-native-multi-client-soak-20261030.json)
  и [30-минутный Alpine soak](clean-vpn-native-alpine-soak.md): четыре клиента,
  соответственно 6948 и 14013 смешанных раундов, квоты relay, освобождение
  ресурсов. Второй snapshot предшествует address-discovery delta.
- Netem/crash/health — 21/21. Физический transparent smoke — 8/8 TLS и
  8/8 JA3/JA4/ALPN через внешний wlan0 capture; [точная граница](../fixtures/clean-vpn-native-transparent-wan-20261030.json).
- Managed discovery + DNS — по 12/12 в Podman и настоящем Docker Engine/Compose
  на ARM64 Linux, включая NSS, stop/start/SIGKILL, active-client preservation.
  [Docker отчёт](clean-vpn-native-docker-compat.md).
- Address owner — по 8/8 nft и legacy. Native discovery/session: 75 уникальных
  JS-сценариев с учётом связанных interoperability tests; ASAN/UBSAN/LSan —
  34/34. Повторные прогоны не суммируются как новые тесты.
- Независимый observer сверил discovery и полную сессию с synthetic и частичным
  Chromium-derived профилями. При перестановке extensions сырой JA3 меняется;
  сверяются нормализованный JA3, JA4 и поля профиля. Это не доказательство полной
  неотличимости от браузера.
- Финальный ARM64 musl CTest — 14/14; native renewal/review — 12/12, без skips.

## Границы, которые остаются

Transparent/combo сохраняют экспериментальный статус. Был один ранний WAN
timeout; последующие bounded smoke прошли, но это не длительная WAN-приёмка.
Quota на одну идентичность не гарантирует доступность против нескольких
согласованно действующих клиентов или внешнего connection flood.

Discovery пока предназначен для свежих изолированных runtime/контейнеров.
При смене адреса или source config требуется пересоздание namespace, а не
автоматическая переделка работающих маршрутов. В этом owner нет автоматического
SSH-восстановления времени; ошибки сертификата/clock-skew закрывают доступ.
Existing-host installers и обычный экспорт админки остаются fixed-address.

Compose `.mpn` проверен через клиентский NSS. Собственный libc resolver
exit-контейнера не подключён к приватной зоне: там можно запросить resolver
явно на `127.0.0.1:1055`. Для host exit есть отдельный resolved scope. Один
network namespace не изолирует обращения NSS к host resolved через общий
AF_UNIX/D-Bus; контейнеры не получают host bus или общий `/run`.

Сборка/проверка полного amd64 native в отдельной офлайн QEMU VM — текущая
резервная работа; успешная загрузка Alpine и запуск компилятора уже подтверждены.
Результат сборки будет внесён отдельно. Ни ARM64-гейты, ни multiarch base manifest
сами по себе не являются amd64-приёмкой.

Следующая эксплуатационная работа после лаборатории: выбранная версия engine
и control plane, bounded trial новых функций на тестовых портах, затем отдельное
решение о переносе нужных функций в ежедневную пару. Автоматического переключения
работающей пары эта ночная серия не выполняет.
