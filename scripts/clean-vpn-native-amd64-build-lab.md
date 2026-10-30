# Offline AMD64 native build на ARM64: повтор из лабораторного cache

Это инструкция для **уже подготовленного cache** Podman, а не универсальная
команда получения toolchain с нуля. Подготовка проверенных x86_64 APK и
закреплённых исходников описана в
[rootfs receipt](../fixtures/clean-vpn-native-amd64-rootfs-20261030.json),
отдельный минимальный bootstrap — в [QEMU smoke](clean-vpn-native-amd64-qemu.md).
Без перечисленных ниже локальных объектов сначала нужна новая проверенная
подготовка; не заменяйте отсутствующие образы случайными скачанными образами.

Guest — Alpine x86_64 с GCC 14.2, CMake 3.31.7 и Node 22.23.4. QEMU исполняется
как ARM64 userspace внутри отдельного контейнера. У guest нет NIC и host share;
контейнер имеет `network none`, UID 1000, cap_drop ALL, no-new-privileges,
read-only rootfs. Единственная постоянная запись — собственный ext4 disk.
Mac routing/DNS, binfmt и глобальные настройки Podman VM не меняются.
Guest 2 GiB/1 CPU, container 3 GiB/128 PID; один запуск ограничен 5400 секундами.
CTest/loopback TLS здесь не являются throughput benchmark или полной проверкой
AMD64 Compose/network-owner на физическом сервере.

[Итоговый receipt](../fixtures/clean-vpn-native-amd64-build-20261030.json):
baseline собран с нуля за 63 минуты, CTest 14/14 и JS 55/55; после signal-fix
оба engine пересобраны из сохранённого cache, CTest 14/14 и JS 56/56 прошли
без пропусков. Финальный прогон занял около 9 минут. Итоговый engine SHA-256:
`2d2a13bd0f28ba02a3e8a391a118b8257a1b4163e960ddbe9a8df3f274f591d1`.
Оба гостя штатно выключились; final stopped disk прошёл отдельный clean fsck,
baseline/fixed binary и logs сохранены раздельно. В receipt сохранены также
два промежуточных отказа bootstrap/overlay и их исправления.

Сохранённые локальные объекты от 2026-10-30:

| Объект | Название |
| --- | --- |
| QEMU + kernel + boot initramfs image | `localhost/cvpn-amd64-build-vm:20261030` |
| ARM64 tools для debugfs/e2fsck | `localhost/clean-vpn-native-toolchain:night-arm64` |
| Собственный disk volume | `cvpn-amd64-build-disk-20261030` |
| Файл в volume | `/disk/root-v2.ext4`, 6 GiB sparse, UID 1000/mode0600 |
| Исходный подготовленный rootfs volume | `cvpn-amd64-apk-rootfs-20261030` |
| Baseline container | `cvpn-amd64-build-vm-v2-20261030` |
| Финальный incremental container | `cvpn-amd64-build-vm-fixed-v2-20261030` |

Базовый source snapshot — `ed5bf16f10ddb71b2a6759f9058ec3abd8b2d344`.
Затем применены только `engine.cc` и новый worker-signal regression из
`400e7d8dd227fe0945878b2a89922b70eb35cbd5`. Пакеты и зависимости не менялись.
Первоначальный `/src/source-provenance.json` сохранён; дополнительный
`/src/overlay-receipt.json` содержит точные hashes overlay. Это явно составной
snapshot, а не утверждение, что guest всегда совпадает с текущим HEAD.

## Просмотр и повтор

Все команды адресуют только собственные лабораторные объекты. Удобное
сокращение в текущем shell:

```sh
p() { podman --connection meshpn-clean-vpn-lab-root "$@"; }
p inspect cvpn-amd64-build-vm-fixed-v2-20261030 --format '{{.State.Status}} {{.State.ExitCode}}'
p logs --tail 40 cvpn-amd64-build-vm-fixed-v2-20261030
```

`ExitCode=0` контейнера недостаточно: QEMU возвращает 0 и при guest build failure,
если guest после него штатно сделал poweroff. Требуются обе строки:

```text
AMD64_NATIVE_BUILD_TEST=passed
AMD64_NATIVE_BUILD_EXIT=0
```

Дополнительно проверить CTest 14 и все выбранные JS результаты, отсутствие skip
и соответствие source/binary hashes. Guest сохраняет `/build-run.log`.

Для повторного bounded запуска использовать **новое имя контейнера** и убедиться,
что ни одна VM не использует этот volume. Не запускать две VM на одном raw disk.
Текущий guest script принудительно удаляет оба engine object-файла перед Ninja,
затем повторяет CTest, 55 прежних JS сценариев и worker-signal regression.

```sh
p run -d --name cvpn-amd64-replay-NEW \
  --network none --cap-drop all --security-opt no-new-privileges \
  --memory 3g --pids-limit 128 --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v cvpn-amd64-build-disk-20261030:/disk \
  --entrypoint /usr/bin/timeout localhost/cvpn-amd64-build-vm:20261030 \
  --signal=TERM --kill-after=20s 5400 \
  /opt/meshpn-native-qemu/qemu-system-x86_64 \
  -nodefaults -no-user-config -nic none -display none -monitor none -no-reboot \
  -serial stdio -accel tcg -cpu qemu64 -m 2048 -smp 1 \
  -machine pc,dump-guest-core=off -bios /opt/seabios/bios-256k.bin \
  -L /opt/qemu-data -kernel /opt/guest-kernel -initrd /opt/guest-initrd.gz \
  -drive file=/disk/root-v2.ext4,format=raw,if=virtio,cache=none \
  -append 'console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on'
p logs -f cvpn-amd64-replay-NEW
```

## Offline edit и извлечение артефактов

Никогда не открывайте работающий guest disk для debugfs/e2fsck или второй VM.
Перед **любым offline редактированием**, даже после успешного poweroff, нужен
journal recovery. `sync; poweroff -f` не означает unmounted/clean ext4.
Именно это было проверено на реальном промежуточном отказе: первоначальная
debugfs-запись читалась правильно, но следующий boot проиграл старый журнал
поверх двух новых inode и завершился до компиляции с exit 1. Baseline artifacts
остались целы. Восстановление журнала, повтор overlay, второй fsck и повторное
сравнение dumped bytes устранили отказ. Этот этап нельзя пропускать.

```sh
# Только после State.Status=exited для всех VM с этим volume.
p run --rm --user 1000:1000 --network none --cap-drop all \
  -v cvpn-amd64-build-disk-20261030:/disk --entrypoint sh \
  localhost/clean-vpn-native-toolchain:night-arm64 -c \
  'result=0; /usr/sbin/e2fsck -f -y /disk/root-v2.ext4 || result=$?; test "$result" -le 1'
```

При status >1 дальнейший boot/edit не выполнять до разбора. Для нового source
overlay сначала проверить старый source/provenance, затем заменить только
явный allowlist файлов и добавить отдельный receipt. После debugfs снова fsck,
после него снова dump и byte/hash comparison. Не доверять только exit 0 debugfs:
он может завершиться0 при неуспешной отдельной команде. Новый guest должен
`touch` изменённые sources или удалить соответствующие object-файлы; timestamps
offline writer сами по себе не гарантируют пересборку.

Готовые одноразовые overlay images 2026-10-30 не являются универсальным updater:
они содержат проверки определённого before-hash и предназначались для одного
перехода. На уже обновлённом cache их повторно не применять.

Для экспорта stopped disk используется readonly mount и UID 1000 — владелец
mode0600 файла. Не добавлять DAC capabilities ради чтения.

```sh
p create --name cvpn-amd64-export-NEW --user 1000:1000 --network none --cap-drop all \
  -v cvpn-amd64-build-disk-20261030:/disk:ro --entrypoint sh \
  localhost/clean-vpn-native-toolchain:night-arm64 -c \
  'mkdir /tmp/artifacts; debugfs -R "dump /build-run.log /tmp/artifacts/build-run.log" /disk/root-v2.ext4; debugfs -R "dump /build/clean-vpn-engine /tmp/artifacts/clean-vpn-engine" /disk/root-v2.ext4; debugfs -R "dump /build/Testing/Temporary/LastTest.log /tmp/artifacts/LastTest.log" /disk/root-v2.ext4; debugfs -R "dump /src/source-provenance.json /tmp/artifacts/source-provenance.json" /disk/root-v2.ext4; debugfs -R "dump /src/overlay-receipt.json /tmp/artifacts/overlay-receipt.json" /disk/root-v2.ext4'
p start -a cvpn-amd64-export-NEW
p cp cvpn-amd64-export-NEW:/tmp/artifacts /private/tmp/cvpn-amd64-artifacts-NEW
p logs cvpn-amd64-replay-NEW > /private/tmp/cvpn-amd64-console-NEW.log
```

Проверить наличие файлов, SHA executable и обе guest markers в console.
Отсутствующий файл при прерванной сборке не считать успешным экспортом.
Перед строгим offline экспортом также восстановить журнал stopped disk,
сохранив console отдельно. Baseline и новые artifacts сохранять под разными
именами; binary не коммитится в репозиторий.

После работы убедиться, что собственные VM exited. Удалять можно только явно
созданные exporter/VM containers по их именам; не выполнять global prune.
Images и volume разумно оставить для быстрого следующего запуска. Удаление
`cvpn-amd64-build-disk-20261030` уничтожит compile cache и guest artifacts;
делать это только после нужного экспорта и явного решения отказаться от cache.
