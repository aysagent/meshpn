# Изолированный amd64 QEMU smoke на ARM64

`clean-vpn-native-amd64-qemu-smoke.mjs` использует только уже загруженные
образы. Из amd64 laboratory image извлекаются закреплённый x86 kernel,
Seabios/ROM и ранее подготовленный **ARM64** QEMU с собственным loader/libdir.
Из amd64 Alpine извлекаются busybox, musl loader и os-release. Скрипт проверяет
архитектуры image/ELF, создаёт initramfs в userspace и запускает QEMU внутри
отдельного ARM64 контейнера. Foreign `/bin/sh` при извлечении не выполняется.

На Mac/Podman host не меняются сеть, binfmt или настройки VM. Контейнер
непривилегированный: uid1000, cap_drop ALL, no-new-privileges, read-only rootfs,
network none, ограниченные CPU/RAM/PID. Гость без NIC, диска и host share.
Время выполнения VM ограничено 90 секундами. Скрипт удаляет только созданные им
контейнеры; каталог публичных boot assets и image остаются для повторного
использования. Каждый запуск требует новых путей вывода.

Пример для существующего laboratory cache:

```sh
node scripts/clean-vpn-native-amd64-qemu-smoke.mjs \
  --engine=podman --connection=meshpn-clean-vpn-lab-root \
  --lab-image=localhost/meshpn-clean-vpn-lab:1f35b200e5e912e7 \
  --alpine-image=24ab38714e948bd49d24d566e97c1c104b63f85c2e642685e72393b37cfb9862 \
  --toolchain-image=localhost/clean-vpn-native-toolchain:night-arm64 \
  --directory=/private/tmp/cvpn-amd64-smoke-new \
  --report=/private/tmp/cvpn-amd64-smoke-new.json
```

Названия локальных cache images не являются инструкцией скачать неизвестный
образ: они должны уже существовать. Отчёт фиксирует фактические image IDs и
SHA-256 kernel/initramfs/QEMU/busybox/musl. В образе laboratory должны быть
`/opt/meshpn-native-qemu`, `/opt/meshpn-kernel-release`, соответствующий
`/boot/vmlinuz-*`, `/usr/share/seabios` и `/usr/share/qemu`.

30 октября 2026 воспроизводимый smoke прошёл: `uname -m` вернул `x86_64`,
Alpine 3.22.7 запустил динамический busybox через musl, после чего гость
штатно выключился. [Отчёт](../fixtures/clean-vpn-native-amd64-qemu-smoke-20261030.json).
Это основание для отдельной offline native сборки; CTest, TLS/JA3/JA4 и
контейнерный amd64 runtime этим smoke **не проверяются**.
