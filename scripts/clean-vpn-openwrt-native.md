# Native внутри OpenWrt: первый compatibility smoke

31 октября: новая static amd64 musl сборка прошла в настоящем OpenWrt 25.12.6
production `--capabilities`/`--check-config`, затем реальные H2 и H1 TLS/packet
сессии через fixture FD и отрицательную проверку PSK.
[Receipt](../fixtures/clean-vpn-openwrt-native-20261031.json).

Production engine SHA:
`a6eec6c9f185a4fa1f57ae7862719fb7a3c3c0eabfdc41dd12fceabf0dbfd3bd`.
Это **generic Alpine musl static build**, не APK из OpenWrt SDK. До этого он
и отдельный fixture прошли CTest 14/14 и [64 native интеграции на amd64](../fixtures/clean-vpn-native-amd64-http-20261031.json).
Сборка выполнена в отдельной x86 VM без NIC/host share, на копии остановленного
cache-диска. Offline overlay проверен побайтно после journal recovery, export
сделан после poweroff/fsck; SHA совпал с guest build log. Исходный disk cache
не менялся. Первая попытка не дошла до compile из-за отсутствующего экспортированного
tool PATH; это исправлено в guest script и отдельно зафиксировано в receipt.

## Границы проверки

Normal engine имеет `packet_ipc:false`. Его ключи, профиль и CA проходят
обычную проверку config. TLS и обмен по 100 пакетам на H1/H2 выполнены отдельным
`clean-vpn-engine-fixture` с тем же TLS-кодом и тестовым packet FD вместо TUN.
Неверный PSK не допускает рабочую сессию. PSK и сертификаты сгенерированы
только для этого стенда; ключи Radxa/VPS сюда не копировались.

У guest нет сетевой карты. Контейнер QEMU непривилегированный, без capabilities,
с read-only rootfs. Базовый диск — disposable snapshot; дополнительный raw
ext4 носитель только для чтения содержит явно переданные test artifacts,
не общий доступ к filesystem Mac. После завершения VM оба носителя неизменны,
контейнер удалён. Mac trust store и настройки сети не менялись.

Не подтверждены TUN/routing/DNS leak/kill switch, native service через procd,
производительность, SDK ABI/package installation, LuCI или browser equivalence.
SDK-пакет имеет другой compiler/flags и требует отдельной приёмки.

## Дополнение: normal engine и настоящий TUN

После первого FD smoke тот же generic amd64 normal engine прошёл настоящий
OpenWrt TUN dataplane на H2 и H1. [Отдельный receipt](../fixtures/clean-vpn-openwrt-normal-tun-20261031.json)
фиксирует binaries, helper/script/media SHA, отрицательные контроли и cleanup.

Внутри одноразовой VM установили официальный matching `kmod-tun` через
подписанный repository index и штатные guest keys. Прямая установка standalone
APK сначала была отклонена как `UNTRUSTED`; явный offline repository update и
установка по package name прошли. Signature verification не отключали.

Production engine с `packet_ipc:false` запущен в двух ролях с persistent
`cvctun0`/`cvetun0`. Source-policy routes заставляют ICMP request и reply пройти
через разные TUN и authenticated TLS, несмотря на обе тестовые IP aliases в
одной VM. Четыре echo request/reply на каждый HTTP protocol прошли; normal
engine counters это подтверждают. Удаление маршрута даёт `unreachable` до
LOCAL fallback; остановленный client не пропускает пакеты. После восстановления
маршрута обмен снова работает. Оба native процесса завершаются SIGTERM с code 0.

Изменения только внутри disposable guest: две собственные policy tables,
rules и fw4 zone, тестовые адреса и sysctls. После test остаётся только `lo`,
собственная zone удалена; весь snapshot дополнительно отбрасывается при poweroff.
Helper [tun-device.c](../openwrt/lab/tun-device.c) заменяет отсутствующий
BusyBox `ip tuntap`, принимает только две фиксированные test interface names и
в APK не устанавливается. Его SDK compiler не делает generic engine SDK build.

Для повтора payload helper дополнительно принимает **вместе** `--tun-helper`,
`--tun-module`, `--tun-index`. Последние два должны совпасть с закреплёнными
официальными SHA для выбранной архитектуры, до генерации private credentials.
Helper — static ELF соответствующей архитектуры. Shell fixture находится в
[openwrt/lab/tun-smoke.sh](../openwrt/lab/tun-smoke.sh); запускать его только
через этот NIC-less VM harness. Это не installer физического роутера.

Пока не проверены WAN/NAT, DNS/kill switch, netifd ownership и reboot recovery,
LuCI/rpcd/capture/observer. TUN тест в одной VM не закрывает эти пункты.

## Дополнение: normal engines под procd

Следующий [отдельный прогон](../fixtures/clean-vpn-openwrt-native-procd-20261031.json)
повторил H1/H2 TUN gates и запустил normal client/exit как две настоящие procd
instances временной службы. После SIGKILL клиента procd выдал другой PID,
прежний PID исчез, exit сохранил свой PID и пакетный обмен восстановился.
Stop службы завершил оба native процесса; следующий пакет не прошёл.

Первый fixture ошибочно считал отсутствие PID между reap/respawn фатальной
ошибкой `jsonfilter` под `set -e`. Инструментированный повтор подтвердил точную
строку. В bounded polling разрешён этот временный empty result; проверки
нового PID, живого exit и реальных пакетов сохранены. Engine не менялся.

Это доказательство supervision native процесса, а не готовый OpenWrt service
adapter: UCI validation, ownership сети/DNS, crash journal, health API и
автозагрузка с восстановлением ещё требуют отдельной реализации и приёмки.

## Повтор с новыми static amd64 artifacts

`clean-vpn-openwrt-native-payload.mjs` принимает три ELF: normal engine,
fixture и integration-test. Он отвергает foreign/dynamic ELF до создания
credentials. Каталог должен быть новым и абсолютным:

```sh
node scripts/clean-vpn-openwrt-native-payload.mjs \
  --engine=/private/artifacts/clean-vpn-engine \
  --fixture=/private/artifacts/clean-vpn-engine-fixture \
  --integration=/private/artifacts/integration-test \
  --directory=/NEW/private/payload
```

Далее в отдельном Linux container `mke2fs -t ext4 -b 4096 -d /payload` создаёт
новый 64 MiB test-disk. Параметр `--payload-disk=/absolute/test.ext4` у
[OpenWrt VM runner](clean-vpn-openwrt-vm.md) подключает его read-only как vdb,
запускает фиксированный `/run.sh` в guest и требует дополнительных точных
native success-маркеров. Для этого режима raw disk ограничен 64 MiB; его SHA
и manifest бинарников/профиля сохранены в receipt. Не использовать тестовые
ключи этого носителя для установки на настоящих устройствах.
