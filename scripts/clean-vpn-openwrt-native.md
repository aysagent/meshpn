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
