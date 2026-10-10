# Native combo physical preflight

Первый physical-acceptance checkpoint — только инвентаризация хоста и точный
offline-план. Он не является установщиком и не разрешает активацию.

```bash
sudo node scripts/clean-vpn-native-physical-preflight.mjs \
  --role=client \
  --name=trial-client \
  --binary=/root/dev/meshpn/native/clean_vpn/build/clean-vpn-engine \
  --config=/root/native-trial/client-combo.json \
  --site-profile=/root/native-trial/client-site.json
```

Для exit используется `--role=exit` и его собственные config/site-profile.
Все пути абсолютные, исходные JSON owner-only. Команда выполняет локальные
`--capabilities` и `--check-config` у указанного engine, но не запускает VPN.

Отчёт содержит:

- SHA-256, права, timestamps и ELF architecture бинарника;
- hashes config/site-profile без key/certificate bytes и без raw config;
- capability и offline `installNative(... apply:false)` verdict;
- точные будущие systemd units и firewall/TUN plan;
- интерфейсы, адреса, маршруты, listeners, forwarding и hashes текущих tables;
- конфликты unit/bundle/TUN/port и соответствие endpoint выбранному uplink;
- явные operator decisions, которые невозможно подтвердить автоматически.

Никаких DNS/HTTPS/WAN probes нет. Не создаются TUN, journal, bundle, unit,
firewall rules или sysctl writes; службы не запускаются и не останавливаются.

Текущий site profile имеет строгий fresh dedicated-host контракт: управляемые
tables пусты, forwarding выключен, TUN отсутствует, uplink/LAN подготовлены
внешним `link_unit`, но административно DOWN. Он не является способом наложить
native combo поверх действующей Radxa/VPS. На exit профиль запрещает новые WAN
SSH connections; отдельная console/rescue и management policy обязательны.

`ready-for-reviewed-trial-plan` означает лишь согласованность наблюдений с этим
контрактом. `mutationAllowed` всегда `false`. Для работающей Radxa ожидаемы
blockers существующего firewall, UP links и legacy VPN: они нужны для проектирования
отдельной transient-интеграции, а не для автоматического удаления.
