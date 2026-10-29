# Ночь 30 октября: выполнение плана

Пользователь разрешил продолжать все этапы самостоятельно до завершения либо
его остановки утром, включая параллельную работу. Физическая daily-пара и сеть
Mac не переключаются; новые экземпляры — только с сетевой изоляцией.

1. Управление клиентами: реализован manager/CLI, автоподбор стабильного IP,
   отдельные packet/relay keys, export/import, revoke/rotate/rename, journaled
   rollback и recovery. 12 manager checks и 4 real-native enrollment scenarios
   passed. [Инструкция](clean-vpn-native-clients.md).
2. Hot reload exit: реализация и испытания в работе отдельным агентом.
3. `.mpn`: bounded loopback UDP/TCP resolver готов и проверен; системное
   направление зоны ещё не интегрировано. [Документ](clean-vpn-native-peer-dns.md).
4. Админка: client API/UI и role/capability controls в работе.
5. Combo/transparent: расширенная текущая регрессия и последующий soak впереди.
6. Общий Compose: supervisor/broker и web в отдельных контейнерах в работе.
7. Alpine: musl build и последующая приёмка в работе.
8. Резерв: handshake address allocation, certificate lifecycle, diagnostic export,
   актуализация документов. Выполнять после основного, не считать закрытым заранее.

Состояние обновляется по мере приёмки; эта запись не заменяет итоговый отчёт.
Изменения в `device/` ведёт отдельная работа пользователя — не включать в наши
коммиты и не откатывать.
