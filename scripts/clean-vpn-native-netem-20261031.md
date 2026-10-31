# Combo: помехи и восстановление, 31 октября

Локальный Podman/Linux, отдельные namespace/TUN/firewall, порт 3443. Рабочие
Radxa/VPS и настройки сети Mac не менялись. Образ
`localhost/cvpn-runtime:diagnostics-20261031`, бинарник
`2d3d26a984008030fdc285d03dfb1ac98244e41d132170da5c08c98ea8ebe648`
с диагностикой из `73025af`; новые HTTP-параметры в этот образ **не входят**.

Полный структурированный [receipt](../fixtures/clean-vpn-native-netem-20261031.json).
Повтор: `clean-vpn-native-combo-runtime-lab.mjs` с `CVPN_COMBO_NETEM=1`,
`CVPN_COMBO_HEALTH=1`, `CVPN_COMBO_LOAD_SECONDS=60` и именами runtime/observer
через соответствующие `CVPN_RUNTIME_IMAGE`/`CVPN_OBSERVER_IMAGE`.

Успешно проверены:

- реальный launcher, TUN, LAN HTTPS, UDP/TCP DNS и запрет прямого uplink;
- независимый pcap: сохранённый packet TLS и исходные relay JA3/JA4;
- совместная нагрузка packet и четырёх relay пользователей, перегрузка слотов;
- delay, loss, reorder, blackout: обе ветки восстанавливаются, ресурсы освобождаются;
- отказ relay не переключает запрос в packet-ветку;
- активный health check обнаруживает отсутствующий REDIRECT и недоступный origin,
  даже когда packet-ветка здорова; неверные CA/имя/ответ отклоняются;
- exit SIGKILL/recreate сохраняет replay state; client SIGKILL с удержанным
  namespace оставляет доступ закрытым; новый namespace восстанавливает обе ветки;
- SIGTERM и cleanup собственных контейнеров, сетей и томов.

Это проверка восстановления в изолированной ARM64 VM, не обещание производительности
на физическом канале. Сценарий, параметры помех, измерения и границы ресурсов
сохранены в receipt; сырой текст tcpdump исключён, его исходный отчёт закреплён SHA256.
