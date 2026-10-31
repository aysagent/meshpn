# OpenWrt VM: готовый изолированный boot smoke

31 октября 2026: официальный OpenWrt 25.12.6 x86/64 загрузился в native ARM64
QEMU внутри Podman VM. [Receipt](../fixtures/clean-vpn-openwrt-vm-20261031.json)
фиксирует image ID, SHA256 загрузок/диска/консоли, восемь gates, состояние
завершения контейнера и повторный успешный прогон. Это начало OpenWrt-стенда,
не готовый VPN-пакет или приёмка LuCI.

Дополнительно тот же runner проверен с `--architecture=arm64`:
[ARMv8 receipt](../fixtures/clean-vpn-openwrt-arm-vm-20261031.json).
Это настоящий aarch64 guest, не ARM binary в x86 user namespace. procd/UCI и
respawn/stop прошли; границы изоляции остались теми же.

Проверены procd как PID 1, настоящий ubus system board, UCI write/read/commit,
запуск отдельной тестовой службы (`sleep`), её respawn с новым PID после SIGKILL,
stop и удаление собственных конфигураций. У guest только loopback. Сетевой
карты, KVM, 9p/virtiofs или постоянного guest-диска нет. Исходный ext4 image
читается через snapshot; записи гостя после завершения отбрасываются.
На Mac не меняются сети, DNS, маршруты, firewall, binfmt или доверенные CA.

## Повтор

Сначала получить эти два файла из [официального каталога](https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/):

```text
openwrt-25.12.6-x86-64-generic-ext4-combined.img.gz
f8538784d0288b4133a99ac2a68443e4922ffde6343e80df56a5882364b9d499
openwrt-25.12.6-x86-64-generic-kernel.bin
8f70595f3a6eec3112e007450a1a600153904deffa52ab368712342583cb387c
```

Runner не скачивает ничего. Он проверяет закреплённые hashes до создания VM;
GPG release signature этим не проверяется. Подменять образ другой версией
под тем же именем нельзя. Отдельные preflight tests проверяют отказ неверному
образу, симлинку и некорректной connection до создания выходных ресурсов.

Текущий **локальный cache**, подготовленный предыдущим amd64 bootstrap:

```sh
node scripts/clean-vpn-openwrt-vm-smoke.mjs \
  --connection=meshpn-clean-vpn-lab-root \
  --qemu-image=localhost/cvpn-amd64-b784ef245d:latest \
  --image-gz=/private/tmp/cvpn-openwrt-public-assets-20261031/openwrt-25.12.6-x86-64-generic-ext4-combined.img.gz \
  --kernel=/private/tmp/cvpn-openwrt-public-assets-20261031/openwrt-25.12.6-x86-64-generic-kernel.bin \
  --directory=/NEW/private/openwrt-smoke \
  --report=/NEW/private/openwrt-smoke.json
```

Directory/report должны быть новыми. Cache image уже должен существовать;
runner не скачивает одноимённый неизвестный образ. В нём ARM64 QEMU 8.2.2,
его собственный loader/libraries и BIOS, проверенные предыдущим bootstrap.
Guest остаётся x86_64; это userspace TCG, не VM-wide binfmt.

Для ARMv8 используются два файла из
[официального каталога armsr/armv8](https://downloads.openwrt.org/releases/25.12.6/targets/armsr/armv8/):

```text
openwrt-25.12.6-armsr-armv8-generic-ext4-rootfs.img.gz
3f25a4ee0537f0a4336833047d7933e884c29450eefb7ac758155cbd0f5278d3
openwrt-25.12.6-armsr-armv8-generic-kernel.bin
2b9ce48df5536e993ee691339057828488e4a31be9c2bb5d3f6120f1135fcbb0
```

Передать `--architecture=arm64` и cache image
`localhost/cvpn-openwrt-arm-qemu:20261031` с native ARM `qemu-system-aarch64`.
Используются machine `virt`, Cortex-A53, root `/dev/vda`, console `ttyAMA0`;
BIOS x86 здесь не нужен. Имя скачанного файла не является проверкой: runner
проверяет именно закреплённые SHA. Остальные параметры и новые output paths
аналогичны x86 примеру. Для x86 `--architecture=amd64` можно задать явно.

Container — UID1000, read-only rootfs, no-new-privileges, cap_drop ALL, network
none, 1.5 GiB memory cap, 2 host CPU quota; guest — 384 MiB/1 CPU, TCG cache
128 MiB. Deadline 180 секунд, собственное случайное имя, явная проверка удаления
контейнера. Файлы загрузок и pristine disk остаются для следующего повтора.
QEMU exit 0 сам по себе не считается успехом: нужны точные guest-маркеры,
подтверждение всех проверок и cleanup.

## Что пришлось исправить в harness

Начальный hostname может быть `(none)`; console принимает короткие команды
с ожиданием нового prompt. Минимальный образ не содержит `base64` и `stty`:
передача использует встроенный printf. Новому UCI package нужен собственный
файл до первого set. Ранние попытки с 768 MiB прекращались около начала guest
sleep, но тогда wrapper ещё не сохранял exit/OOM state; точная причина этих
попыток не доказана. На последующем прогоне QEMU использовал около 900 MB.
Добавлены exit/OOM/deadline данные и достаточный лимит; окончательный повтор
прошёл со штатными kernel clocks, без экспериментальных noapic/nohz/icount.
Это не заявление об исправлении Linux timers и не benchmark.

Далее — native binary/профили в guest, две сети/management и настоящий TUN,
затем SDK packages, fw4/netifd adapter, rpcd ACL и LuCI. Пока не проверены
OpenWrt VPN/DNS/kill switch, capture/observer workflow, APK/IPK установка,
обновление/rollback и конкретный физический роутер. Полный критерий остаётся
в [плане OpenWrt](clean-vpn-openwrt.md).
