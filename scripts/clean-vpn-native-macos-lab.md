# Native clean-vpn lab на macOS

Это воспроизводимый вход в существующую Linux x86-64/QEMU лабораторию с Apple
Silicon Mac. Переписывания VM-сценариев под Darwin нет: Podman поднимает
выделенную ARM64 Linux VM, внутри неё запускается Ubuntu 24.04 `linux/amd64`, а
уже там штатный `clean-vpn-native-lab.mjs` запускает NIC-less x86-64 guest.
Сборка выполняется в amd64 userspace через Rosetta, но сам QEMU берётся из
отдельного ARM64 stage и исполняется ядром Podman VM нативно; только гостевой
x86-64 CPU эмулируется через TCG. Это исключает двойную эмуляцию QEMU.

Вложенная эмуляция медленнее обычного Linux x86-64, но сохраняет важные свойства
стенда: Linux `/proc`, matching kernel/modules, настоящий systemd PID 1,
iptables, network namespaces и реальные guest TUN. QEMU запускается с
`-nic none`; shared filesystem внутрь QEMU не передаётся. Скрипт не создаёт TUN,
routes или firewall rules на macOS и не обращается к физическим VPS/Radxa.

## Одна команда

Для отдельного Chromium capture-стенда без пересборки native engine:
`npm run lab:native:mac -- --browser-capture`.
Условия изоляции и формат результата: [браузерные захваты](clean-vpn-native-browser-capture.md).

Нужен установленный Podman. Остальное создаётся автоматически:

```bash
npm run lab:native:mac -- --native-combo-boot
```

Первый запуск:

1. создаёт отдельную Podman machine `meshpn-clean-vpn-lab` с 6 CPU, 6 GiB RAM и
   sparse disk 100 GiB;
2. собирает content-addressed Ubuntu 24.04 amd64 image;
3. устанавливает в image отдельные x86-64 kernel/modules и QEMU tools;
4. копирует в cache только отслеживаемые Git файлы текущего worktree;
5. собирает helper, TUN addon и native engine;
6. создаёт проверенный DNS bootstrap и трёхзагрузочный host-boot base;
7. запускает выбранную native VM-матрицу.

Первый прогон долгий и требует сети для OCI/APT/CMake dependencies. Podman image,
исходники зависимостей, native build и host-boot base сохраняются в named volume
`meshpn-clean-vpn-lab-cache`. Последующие запуски инкрементальны; Podman VM можно
запускать и останавливать за несколько секунд.

Результат экспортируется в:

```text
~/Library/Caches/meshpn-clean-vpn-lab/results/meshpn-native-lab-*/report.json
```

## Команды

```bash
# Профили: cached build, CTest, real-TCP capture/verify и negative auth; без boot-base
npm run lab:native:mac -- --tls-profiles

# H2 memory/backpressure: 1/4/8 клиентов, два размера окон, без сети контейнера
npm run lab:native:mac -- --h2-budget

# Быстрый multi-client прогон: cached build, CTest, 32 клиента; без QEMU boot-base
npm run lab:native:mac -- --multi-clients

# Только подготовить toolchain/build/base, без native VM-матрицы
npm run lab:native:mac -- --prepare

# Основные актуальные combo-сценарии
npm run lab:native:mac -- --native-combo-network
npm run lab:native:mac -- --native-combo-boot
npm run lab:native:mac -- --native-combo-load
npm run lab:native:mac -- --native-combo-benchmark

# Состояние; status намеренно не запускает остановленную VM
npm run lab:native:mac -- --status

# Освободить RAM Podman VM; persistent cache остаётся
npm run lab:native:mac -- --stop
```

Также поддержаны прежние `--native-only`, `--native-systemd`, `--native-boot`,
`--native-routes`, `--native-network`, `--native-site-boot` и
`--native-transparent-boot`.

Опции:

- `--machine=NAME` — использовать другую выделенную Podman machine;
- `--rebuild-image` — принудительно пересобрать container image;
- `--refresh-base` — создать новый DNS/host-boot base, не удаляя прежний.

`CVPN_PODMAN_MACHINE=NAME` задаёт имя машины без CLI-флага. Wrapper не меняет
default Podman connection или глобальный `~/.config/containers/containers.conf`.
Для `machine init` применяется отдельный tracked config с AppleHV/Rosetta;
после старта и до сборки проверяется настоящий amd64 shell (поле `Rosetta` у
остановленной machine для этого недостаточно). При известном сбое stale `gvproxy` socket выполняется
ровно один штатный повтор `podman machine start`; wrapper не удаляет runtime
socket или VM image самостоятельно.

## Cache и актуальность

Container image адресуется хешем Containerfile. Host-boot base адресуется хешем
его tracked source inputs и kernel release. Изменение C++/CMake вызывает обычную
инкрементальную пересборку. Неотслеживаемые файлы worktree, включая сертификаты,
в лабораторный worktree не копируются.

Успешный macOS прогон подтверждает ту же изолированную x86-64 VM-логику, но не
заменяет ARM64/Radxa, WAN и физическую Radxa ↔ VPS приёмку.
