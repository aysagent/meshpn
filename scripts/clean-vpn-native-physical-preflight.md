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
- hashes config/site-profile без private-key/PSK bytes и без raw config;
- публичные сертификаты CA/exit в DER для офлайн-проверки trust chain и имени;
- capability и offline `installNative(... apply:false)` verdict;
- точные будущие systemd units и firewall/TUN plan;
- интерфейсы, адреса, маршруты, listeners, forwarding и hashes текущих tables;
- конфликты unit/bundle/TUN/port и соответствие endpoint выбранному uplink;
- явные operator decisions, которые невозможно подтвердить автоматически.

Никаких DNS/HTTPS/WAN probes нет. Не создаются TUN, journal, bundle, unit,
firewall rules или sysctl writes; службы не запускаются и не останавливаются.

Для одной пары на доверенной машине создаётся одноразовая случайная challenge:

```bash
openssl rand -hex 32
```

Её значение передаётся обоим preflight как `--pair-challenge=...`. В отчёт
попадают раздельные HMAC proof для boring packet PSK и transparent relay PSK,
но не ключи и не их обычные hashes. Challenge должна быть новой для каждого
сопоставления; ключи обязаны быть случайными 32-байтными значениями. Этот proof
не заменяет отдельную проверку сертификатной цепочки и имени сервера.

Текущий site profile имеет строгий fresh dedicated-host контракт: управляемые
tables пусты, forwarding выключен, TUN отсутствует, uplink/LAN подготовлены
внешним `link_unit`, но административно DOWN. Он не является способом наложить
native combo поверх действующей Radxa/VPS. На exit профиль запрещает новые WAN
SSH connections; отдельная console/rescue и management policy обязательны.

`ready-for-reviewed-trial-plan` означает лишь согласованность наблюдений с этим
контрактом. `mutationAllowed` всегда `false`. Для работающей Radxa ожидаемы
blockers существующего firewall, UP links и legacy VPN: они нужны для проектирования
отдельной transient-интеграции, а не для автоматического удаления.

## Сопоставление двух хостов

Сохранённые stdout-отчёты (вместе с BEGIN/END либо как raw JSON) можно
сопоставить локально:

```bash
node scripts/clean-vpn-native-physical-pair-plan.mjs \
  --client=/root/native-trial/client-preflight.txt \
  --exit=/root/native-trial/exit-preflight.txt
```

Планировщик требует отчёты не старше часа, сверяет endpoint/port/public name,
TUN subnet, отсутствие пересечения LAN и tunnel, capability contract и hashes
исходных config/site-profile. Он не выполняет команд и также всегда оставляет
`mutationAllowed:false`. При одинаковой одноразовой challenge сопоставление
также проверяет оба PSK. Без challenge PSK остаётся открытым gate. Публичный
exit certificate chain проверяется по имени/срокам/подписям до CA из клиентского
config; private key в отчёт не попадает. Успех этих проверок всё равно не
разрешает мутацию хоста.
