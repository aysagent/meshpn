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

После private DNS, discovery и исправления сигналов `400e7d8` актуальные
ARM64 образы измерены повторно тем же `podman image inspect Size`:

| Образ | Байты | MiB | Image ID, начало |
|---|---:|---:|---|
| Native runtime | 108969007 | 103.9 | `58d01b02a361` |
| VPN + supervisor | 109222956 | 104.2 | `38bee9f2f35e` |
| Web/API | 77817936 | 74.2 | `860d7fba27f8` |

[Финальный managed receipt](../fixtures/clean-vpn-native-managed-signal-fixed-20261030.json)
содержит полные идентификаторы и SHA engine. Импорт того же image ID в Docker
даёт несколько другое значение Size; его отдельный результат сохранён в
[Docker receipt](../fixtures/clean-vpn-native-docker-signal-fixed-20261030.json).
Для сравнения размеров используйте один и тот же engine и способ подсчёта.

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

После TSan обнаружена и исправлена межпоточная гонка signal flags
(`400e7d8`): [подробности](clean-vpn-native-tsan.md). Исправленный musl engine
и fixture пересобраны; 14/14 address/reload/worker-signal integration и 12/12
Podman managed gates прошли на новом engine SHA `613b7f07…`.
[Отдельный итоговый receipt](../fixtures/clean-vpn-native-managed-signal-fixed-20261030.json)
сохраняет предыдущие CTest/soak результаты привязанными к их исходным snapshot,
не переносит старые измерения на новую сборку.
