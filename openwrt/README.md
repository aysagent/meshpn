# Локальные OpenWrt-пакеты

`clean-vpn-native/Makefile` — исходный пакет для OpenWrt SDK 25.12.6. Это
первый engine-only этап [OpenWrt-плана](../scripts/clean-vpn-openwrt.md),
не готовое LuCI-приложение. Распространение в общий feed не требуется.

В APK входят normal `clean-vpn-engine` (без тестового packet FD), три публичных
TLS-профиля и лицензии зависимостей. Установка не создаёт config с ключами,
init service, UCI, netifd interface или firewall rules. Для настоящего TUN
нужен совместимый `kmod-tun` и отдельно подготовленная сеть. Установка APK
сама по себе не включает VPN и не даёт гарантий DNS/kill switch.

## Сборка

SDK — Linux x86_64 toolchain, даже для ARM target. На Mac используем отдельный
Podman Linux builder с доступным выполнением amd64; настройки сети Mac и
глобальный binfmt эти команды не меняют. Готовый runtime не требует Node.

Recipes двух использованных вспомогательных образов сохранены в
[lab/sdk-builder.Containerfile](lab/sdk-builder.Containerfile) и
[lab/qemu-arm.Containerfile](lab/qemu-arm.Containerfile). Они расширяют уже
подготовленные локальные Linux/ARM cache images проекта. Image-build скачивает
APT-пакеты **внутри builder**, не устанавливает пакеты на Mac; SDK compile и
VM tests затем работают с `--network=none`. APT здесь не snapshot-locked:
точные полученные image IDs и tool versions фиксируются в dated receipts,
bit-for-bit воспроизводимость будущего APT build не обещается. Не подменять
отсутствующий локальный base image одноимённым registry image.

```sh
podman --connection meshpn-clean-vpn-lab-root build --pull=never \
  -f openwrt/lab/sdk-builder.Containerfile \
  -t localhost/cvpn-openwrt-sdk-builder:20261031 openwrt/lab
podman --connection meshpn-clean-vpn-lab-root build --pull=never \
  -f openwrt/lab/qemu-arm.Containerfile \
  -t localhost/cvpn-openwrt-arm-qemu:20261031 openwrt/lab
```

Нужны C/C++ build tools, make, Git, Python, Perl, Go, rsync, gawk, file, unzip,
wget и ncurses development headers. SDK выполняет штатные prerequisite checks;
не обходить их через `FORCE=1`. Сборка непривилегированная, без сети. Перед ней
подготовить SDK и четыре закреплённых public source cache с `.git` из обычной
native-сборки: BoringSSL с нашими patches, nlohmann/json, Brotli, nghttp2.
SDK user должен иметь доступ к этим копиям; права исходного build cache менять
не нужно. `native/clean_vpn/CMakeLists.txt` проверяет закреплённые revisions.

С Mac из корня проекта подготовить публичный allowlisted source context:

```sh
node scripts/clean-vpn-native-runtime-context.mjs /NEW/public/source
```

Внутри отдельного SDK workspace, где `/source` — этот context read-only,
`/sdk/cvpn-deps/tls` содержит `boringssl-src` и `json-src`, а
`/sdk/cvpn-deps/http` — `brotli-src` и `nghttp2-src`:

```sh
mkdir -p /sdk/package/clean-vpn-native
cp /package/Makefile /sdk/package/clean-vpn-native/Makefile
cd /sdk
make defconfig
sed -i '/^CONFIG_AUTOREMOVE=/d; /^# CONFIG_AUTOREMOVE is not set/d' .config
printf '\nCONFIG_PACKAGE_clean-vpn-native=m\n' >>.config
printf '\n# CONFIG_AUTOREMOVE is not set\n' >>.config
make defconfig
make package/clean-vpn-native/compile -j1 V=s \
  CVPN_NATIVE_SOURCE=/source \
  CVPN_TLS_DEPS=/sdk/cvpn-deps/tls \
  CVPN_HTTP_DEPS=/sdk/cvpn-deps/http
```

`/package/Makefile` здесь — read-only mount нашего Makefile. SDK workspace и
копии зависимостей принадлежат непривилегированному builder user. Не копировать
в context реальные PSK, сертификаты, admin state или всю рабочую директорию.

Наследуются SDK optimization/hardening flags. Fortify wrappers отмечены
system headers: их GNU `include_next` не должен ломать наш `-Wpedantic -Werror`.
Fortify и warnings для собственного кода остаются включены. Static C++ runtime
явно связывает `libstdc++` и `libgcc_eh`: SDK GCC specs самостоятельно не
добавляет exception unwinder при `-static`. Exceptions движка не отключаются.

Локальные APK находятся под `bin/packages/TARGET/base/`. Не переносить
закрытый signing key SDK в repository или диагностический отчёт. При установке
собственного APK доверие этому ключу настраивается отдельно; лабораторный
`--allow-untrusted` ограничен одноразовой VM без NIC.

## Приёмка

Основная приёмка: SDK build → ELF/static inspection → APK inventory → установка
в одноразовую VM соответствующей архитектуры → проверка SHA установленного
engine → normal capabilities/config validation → настоящие TUN H1/H2,
отрицательные контроли маршрута/stop/PSK и native procd respawn/stop.
Используется **сам engine из APK**, без packet FD fixture:

```sh
node scripts/clean-vpn-openwrt-native-payload.mjs \
  --normal-only --architecture=amd64 \
  --engine=/absolute/extracted/usr/sbin/clean-vpn-engine \
  --package=/absolute/clean-vpn-native-0.0.0-r1.apk \
  --tun-helper=/absolute/tun-device \
  --tun-module=/absolute/official-kmod-tun.apk \
  --tun-index=/absolute/official-packages.adb \
  --directory=/NEW/private/payload
```

`tun-device` — static lab helper из `lab/tun-device.c` соответствующей
архитектуры, собранный её SDK compiler. Он и test credentials в APK не входят.
Official module/index SHA закреплены в payload helper; repository update и
установка kmod идут offline со штатной проверкой подписи гостя. `--normal-only`
без TUN inputs отвергается, чтобы capabilities-only запуск не выдавался за
packet acceptance. Проверки ограничены loopback/test aliases внутри VM;
WAN/NAT/DNS и сетевой owner этим не проверяются.

Дополнительный FD fixture и integration-test можно собрать для лаборатории:

```sh
staging_dir/host/bin/ninja -j1 \
  -C build_dir/target-TARGET_musl/clean-vpn-native-0.0.0/build \
  clean-vpn-engine-fixture integration-test
```

Использовать фактическое имя target directory своего SDK. `CONFIG_AUTOREMOVE`
нужно отключить **до** package compile, как в примере выше: SDK по умолчанию
удаляет промежуточный CMake build после успешной упаковки. В первых APK-прогонах
он был удалён; поэтому именно APK прошли normal-only TUN/procd/PSK gates,
никакие чужие fixture binaries им не приписываются.

Подготовка private носителя: [native payload helper](../scripts/clean-vpn-openwrt-native.md),
параметры `--architecture=amd64|arm64` и `--package=/absolute/local.apk`.
VM runner также принимает явный `--architecture`. Это функциональные TCG
проверки, не throughput benchmark и не приёмка физических роутеров.

После engine-only этапа остаются production TUN/network acceptance,
UCI/procd/netifd/fw4/DNS ownership с восстановлением, rpcd ACL, LuCI, capture и
независимый observer. Эти пункты не закрываются успешной установкой APK.
