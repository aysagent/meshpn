# Повторный combo WAN trial: блокировка до запуска

30 октября пользователь разрешил повторную проверку combo на Radxa/VPS и
попросил заменить имя сертификата на `personal-cert.internal`.

## Radxa: ошибки корневой файловой системы

SSH через USB доступен, но `/usr/bin/systemctl` и `/usr/bin/free` возвращают
`Bad message`; `tail` также недоступен. Это проявилось на read-only preflight,
до обновления Git, сборки, создания тестовых namespaces или запуска VPN trial.
Корень — `/dev/mmcblk1p2`, EXT4, на момент чтения `/proc/mounts` смонтирован rw.
Ядро многократно сообщает:

```text
EXT4-fs warning (device mmcblk1p2): ext4_dirblock_csum_verify:406:
inode #758: ... No space for directory leaf checksum. Please run e2fsck -D.
```

Это свидетельство проблемы метаданных EXT4; причина (накопитель, питание,
предыдущий некорректный shutdown и т. п.) не установлена. Формулировка
`No space for directory leaf checksum` не равнозначна доказательству нехватки
свободного места на диске. Рабочее состояние VPN на Radxa через systemctl
подтвердить не удалось. Никакого fsck, reboot, remount, изменения часов,
сборки или переключения служб на плате не выполнялось.

Приватная диагностическая копия: `/private/tmp/cvpn-radxa-storage-20261030.log`.
Дальше требуется возможность сохранить данные и проверить корневой раздел
офлайн, из другой Linux-системы/с другого загрузочного носителя. Не запускать
ремонт смонтированного корня по предложению из kernel log.

## Нейтральное имя сертификата

Установленный VPS leaf самоподписанный, CN/SAN `clean-vpn.daily.internal`.
На VPS подготовлен отдельный кандидат:

```text
/root/dev/meshpn/native/clean_vpn/build/personal-cert-candidate-20261030/
```

Он содержит новый RSA2048 key, self-signed certificate с CN/SAN
`personal-cert.internal`, сроком 365 дней, serverAuth purpose, CA:FALSE,
candidate `engine.json` и публичный `manifest.json`. Каталог 0700, файлы 0600.
Секретный ключ остаётся на VPS; в Git и на Mac не копировался.

SHA256 PEM сертификата:
`869201ad6efbea618989ba563acbfa1dc8438ff8418045d59faec3b1fb24d5da`.

Проверены OpenSSL trust/hostname, отказ для старого hostname, принятие config
установленным native engine. Исходные config/cert/key совпали по хешам после
подготовки. Полный клиентский TLS handshake с этим кандидатом пока не проверен.

**Кандидат не установлен.** Рабочий exit сохранил MainPID 340197 и active state
на preflight. Замена self-signed identity требует согласованно обновить trust
сертификат и `server_name` клиента; отдельно проверить explicit SNI и настройки
админки. Не заменять только одну сторону и не отключать TLS verification.

После восстановления Radxa: повторить preflight, проверить кандидата на
изолированном тестовом порту 3443, выполнить H2/H1 mixed combo с DNS captures
и независимым наблюдателем; лишь затем согласованно применять имя к daily-паре.
Смена имени сама по себе не доказывает браузерную неотличимость.
