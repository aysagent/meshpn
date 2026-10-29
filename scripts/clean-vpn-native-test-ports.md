# Native: тестовые порты рядом с повседневным VPN

Checkpoint 2026-10-29. Повседневная boring-tls пара Radxa↔VPS остаётся на `443`.
В этой работе физические машины не подключались и не изменялись. Все проверки
прошли в выделенной Linux VM Podman; сеть, DNS и маршруты Mac не менялись.

## Что теперь можно задавать

Native engine уже поддерживал произвольный TCP listener. Исправлены ограничения
в offline-генераторе, публикации контейнера и CLI независимого pcap observer.

| Параметр | Значение |
| --- | --- |
| `runtime-config --port=3443` | Клиент подключается к exit на 3443; listener exit по умолчанию тоже 3443 |
| `--exit-port=4443` | Необязательный отдельный listener внутри exit namespace |
| `container start --publish=3443` | Публикует `3443:config.port/tcp`, только для exit |
| `pcap-fingerprints --port=3443` | Анализирует выбранный порт; без опции остаётся 443 |
| Origin HTTPS | Остаётся 443 для transparent interception |
| Локальный transparent listener | В стенде 10443; не является внешним портом exit |

Пример **offline** подготовки нового boring-tls комплекта (адреса заменить):

```bash
node scripts/clean-vpn-native-runtime-config.mjs create \
  --directory=/absolute/new/test-bundle --mode=container \
  --endpoint=192.0.2.10 --exit-address=172.30.77.2 \
  --server-name=vpn.example.net --port=3443 --clients=2
```

Для отображения `3443 → 4443` добавить `--exit-port=4443`, а в отдельном exit
контейнере использовать `--publish=3443`. Генератор сам ничего не публикует,
не устанавливает службы и не меняет сеть. Передавать каждой роли только её
каталог из bundle, как описано в [runtime](clean-vpn-native-runtime.md).
Первичная приёмка портов использовала boring-tls launcher. Следующее дополнение:
[combo LAN runtime](clean-vpn-native-combo-runtime.md) с явным replay volume,
совместной нагрузкой packet/relay и crash/recreate в отдельных контейнерах.
Standalone transparent launcher пока не добавлен.

Независимая проверка сохранённого capture:

```bash
node scripts/clean-vpn-pcap-fingerprints.mjs \
  --pcap=/private/test-wire.pcap --destination=192.0.2.10 --port=3443 \
  --profile=fixtures/native-tls-profiles/chromium-156-bounded-cold.json
```

Это анализ файла, не управление VPN. Для transparent сравнивать с исходным
ClientHello приложения: SNI с relay token меняется, а JA3/JA4 не доказывают
побайтовое совпадение или неотличимость всего сетевого поведения.

## Граница изоляции

**Другого порта недостаточно для второго host-profile в том же namespace.**
Текущие host owners используют фиксированный TUN/peer subnet и журналируют
сетевое состояние в пределах namespace. Второму экземпляру нужны:

- отдельный network namespace/контейнер, свои service/container names;
- новые PSK, отдельные config и replay directory/volume;
- отдельный listener/published port и правила только для тестового namespace;
- независимые stop/recovery/cleanup, без вызовов управления повседневной парой.

Старые direct-trial скрипты с остановкой legacy не подходят для этого сценария.
Нельзя переиспользовать их как установщик тестового VPN рядом с действующим.
Не требуется менять системный DNS физического хоста или подключать приложения
Mac к тестовому шлюзу. Будущий physical smoke также должен сначала проверять
занятость порта и принадлежность ресурсов, не освобождая их принудительно.

## Локальная приёмка

Стенд `clean-vpn-native-port-lab.mjs` запускает NIC-less systemd container в
выделенной Podman VM. Внутри — локальные origin DNS/HTTPS, отдельные client/USB/exit
netns, общий адрес exit с отображениями `443` и `3443`. Реального интернет-трафика
и портов, опубликованных на Mac, нет.

Пара на `443` непрерывно выполняет HTTPS-запросы. По очереди рядом запускаются
boring-tls, combo-tls, transparent-tls на `3443`. Проверяются:

1. Настоящий HTTPS, для packet-пути также TUN и DNS UDP/TCP.
2. SIGKILL тестового exit и восстановление.
3. Остановка exit: запросы тестового клиента не проходят напрямую или через 443.
4. Повторный запуск и остановка тестовой пары с удалением её TUN.
5. Неизменность PID, конфигурации, маршрутов и firewall базовой пары.
6. Внешние capture: сохранённый профиль packet TLS и исходные JA3/JA4 relay.

Отдельно runtime container lab проверяет boring-tls на `3443`, а вложенный
Docker в NIC-less контейнере — настоящую публикацию `3443 → 4443`. Последний
использует обычный bridge **внутри изолированного Docker daemon**: Docker не
публикует внешний порт из internal-only сети. Проверка занятости порта должна
оставлять первый exit работающим.

Машиночитаемые результаты: [test-ports report](../fixtures/clean-vpn-native-test-ports-20261029.json).
Итог: 13 проверок совместного стенда, 24 Podman runtime, 25 Docker publish;
16 unit/CLI тестов и 6 регрессионных тестов админки. Все прошли. Базовая пара
в совместном стенде выполнила 36 непрерывных HTTPS-проб без ошибки.
Это ограниченный функциональный прогон ARM64, не WAN benchmark и не длительный
soak. Использованы ранее собранные проверенные бинарники, их SHA записаны
отдельно для каждого стенда; C++ engine в этом изменении не пересобирался.

### Повторить локально

Для совместного стенда требуется локальный образ `localhost/clean-vpn-port-lab:local`.
Он собирается по `containers/clean-vpn-native-port-lab.Containerfile` из существующего
systemd lab base, tcpdump и явно переданного бинарника своей архитектуры с
`ENGINE_SHA256`. В build context должны быть только `Containerfile` и `engine`;
не копировать credentials или весь рабочий каталог. База описана в
[host lifecycle](clean-vpn-native-host-network.md).

```bash
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
  node scripts/clean-vpn-native-port-lab.mjs /private/tmp/NEW-port-report.json
```

Скрипт копирует только tracked worktree inputs `scripts/` и `fixtures/`; новые
файлы стенда должны быть добавлены в git. Имя контейнера случайное; в `finally`
удаляется только он. При ошибке рядом с report сохраняется `.failure.log`.

Для обычного контейнерного стенда без публикации:

```bash
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
CVPN_RUNTIME_IMAGE=localhost/clean-vpn-native-runtime:final-arm64 \
CVPN_OBSERVER_IMAGE=localhost/clean-vpn-native-observer:night-arm64 \
CVPN_LAB_PORT=3443 CVPN_TEST_LAUNCHER=1 \
  node scripts/clean-vpn-native-runtime-lab.mjs /private/tmp/NEW-runtime-report.json
```

`CVPN_LAB_PUBLISH_PORT=3443 CVPN_LAB_PORT=4443` включает отдельную проверку
публикации на хосте выбранного container engine. Применять только к выделенному
Linux-стенду; для Mac использовать вложенный Docker без сети/port bindings наружу.
Не направлять этот режим на повседневный VPS или обычный Docker Desktop.

## Что дальше

1. Завершён bounded checkpoint: [transparent faults](clean-vpn-native-transparent.md)
   и [combo нагрузка/lifecycle](clean-vpn-native-combo-runtime.md). Продолжение —
   длительный mixed soak, loss/delay/reordering и новые случаи по его результатам.
2. Расширять готовность launcher отдельно от native engine: автоматический
   combo bundle, end-to-end relay health и standalone transparent provisioning.
3. Когда узлы доступны — ограниченный тест на отдельном порту и в отдельных
   namespace, сохраняя повседневную пару; затем независимый capture и benchmark.
