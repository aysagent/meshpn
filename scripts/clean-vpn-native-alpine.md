# Альтернативный Alpine runtime

`containers/clean-vpn-native-alpine.Containerfile` добавляет Alpine рядом с
Ubuntu. Engine, BoringSSL, nghttp2 и Brotli собираются из исходников под musl;
glibc-бинарник не копируется. Ubuntu systemd/QEMU лаборатория сохранена.
Общий VPN+admin Compose описан [отдельно](clean-vpn-native-managed-containers.md).

Alpine 3.22.7 закреплён multi-platform digest
`sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f`.
Native зависимости используют существующие pinned CMake revisions. Context
содержит только разрешённые исходники и SHA-256 каждого файла; приватные
конфигурации, SSH/PSK и device-проект в builder не передаются. APK/APT пакеты
берутся из репозиториев дистрибутива, поэтому bit-identical пересборка всего
образа не обещается. SHA бинарника и ID фактического образа фиксируются отдельно.

## Что потребовалось адаптировать

- По умолчанию один compiler job. При параллельной компиляции двух engine
  targets в ограниченном тестовом контейнере один `cc1plus` был убит; serial
  retry прошёл. `--build-arg JOBS=2` разрешён при достаточной памяти.
- `linux-headers` для BoringSSL на musl; без него отсутствовал `linux/random.h`.
- Явный `sys/time.h` в socket test: musl не предоставлял timeval через побочное
  включение другого заголовка.
- `util-linux` для существующих namespace/lifecycle проверок и явные aliases
  `/usr/sbin/ip*` к Alpine `/sbin`: shared control-plane использует Debian пути.
- Проверены nft и наличие legacy utilities. Runtime сохраняет тот же Node
  control-plane, C++ data plane, CA validation и namespace guard.

## Измерения ARM64, 30 октября 2026

Размеры ниже — локальный uncompressed `image inspect Size`, не размер скачивания
и не RSS. Общие слои при суммировании учитываются повторно. Ubuntu/Debian строки
получены на подготовительном runtime snapshot; это сравнение упаковки, не
строгий benchmark одинакового commit.

| Образ | Байты | Примерно MiB |
|---|---:|---:|
| Alpine native runtime | 105617294 | 100.7 |
| Alpine VPN + bounded supervisor | 105825727 | 100.9 |
| Alpine web/API | 77808148 | 74.2 |
| Ubuntu VPN + bounded supervisor | 217435322 | 207.4 |
| Debian Node 24 web/API | 261989617 | 249.9 |

На проверенном Alpine Node 22.23.4; Debian frontend использует Node 24.
Снижение размера образа не доказывает снижение памяти или рост скорости engine.

## Проверки и границы

ARM64 musl собран и проверен в изолированных контейнерах Podman на Apple Silicon.
CTest: 13 тестов; native regressions включают H1/H2, TLS profile/JA3/JA4,
transparent/combo, namespace rules, live peers reload и WAN fixtures. Общий
Compose проверяет обе роли, actual TUN packets, HTTP auth, browser capture TLS с
проверкой сертификата, add/revoke без смены exit PID, stop/start/SIGKILL.
Точные snapshots, числа и ограничения — в
[JSON отчёте](../fixtures/clean-vpn-native-containers-20261030.json).

Прямой amd64 container build остановился на первом `/bin/sh`: `Exec format
error`. VM-wide binfmt не меняли. Вместо этого подтверждён отдельный native ARM
QEMU, который загрузил amd64 Linux kernel и Alpine 3.22.7 musl userspace без NIC,
host share, KVM или диска. Это проверка runner, **не** сборка native engine для
amd64. Его воспроизводимый smoke описан [отдельно](clean-vpn-native-amd64-qemu.md);
поддержку engine по одному multiarch base manifest не заявляем.

После базового отчёта отдельная Docker 28.5.2 / Compose 2.40.3 лаборатория
прошла managed private-DNS gate 11/11 на ARM64. Rootless mode, физические
Radxa/VPS, cold boot и host Wi-Fi/USB/DNS этими прогонами не подтверждены. Для ежедневного включения нового image на реальной
машине остаётся отдельный bounded smoke с восстановлением состояния.
