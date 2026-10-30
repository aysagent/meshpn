# Повторный combo WAN trial: блокировка до запуска

**Обновление:** после новой загрузки блокер снят; загрузочный fsck выполнил
восстановление, команды и daily VPN снова доступны. Подробности ниже.

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

**Этот первый кандидат отклонён после реального native handshake; не устанавливать.**
OpenSSL verification и native `--check-config` не заменили проверку соединения:
получен `tls_verify_untrusted`. В закреплённой BoringSSL поиск trusted issuer
проверяет `keyCertSign`; у self-signed leaf оно намеренно отсутствовало.
Необходимая проверка не отключалась. Первый и диагностический повторный
combo trials завершились до готовности клиента, ресурсы удалены, host snapshots
совпали до/после. В fixture добавлено сохранение фиксированного reason-кода
discovery и bounded private `discovery.log`, чтобы причина не терялась.

Рабочий exit сохранил MainPID 340197 и active state
на preflight. Замена self-signed identity требует согласованно обновить trust
сертификат и `server_name` клиента; отдельно проверить explicit SNI и настройки
админки. Не заменять только одну сторону и не отключать TLS verification.

После восстановления Radxa: повторить preflight, проверить кандидата на
изолированном тестовом порту 3443, выполнить H2/H1 mixed combo с DNS captures
и независимым наблюдателем; лишь затем согласованно применять имя к daily-паре.
Смена имени сама по себе не доказывает браузерную неотличимость.

Вместо первого кандидата подготовлена нормальная цепочка в
`/root/dev/meshpn/native/clean_vpn/build/personal-cert-chain-20261030`:
CA `Personal Certificate Authority` (`authority/ca.pem`, CA:TRUE/keyCertSign)
и leaf `personal-cert.internal` (`exit/cert.pem`, CA:FALSE/serverAuth).
Клиент получает **только публичный CA**, приватный CA key остаётся на VPS.
SHA256 CA: `a5b7305447ebaa4569954b67e8bc2c984c1d092abdb5ae9e2d20af236431ad33`;
leaf: `77140258ed096d5a207c29b3f6e0896c816ec70f849f2a7b17f377687c53ffb7`.
Native combo discovery, packet session и HTTPS relay с этой цепочкой
успешно установились в изолированном WAN trial. Daily identity ещё не заменена.

## Повторная проверка после новой загрузки

При следующем подключении обнаружена новая загрузка
`aa441626-a4d3-4913-8a82-dd8bfae42842`; агент её не инициировал.
`/run/initramfs/fsck.log` содержит `recovering journal` и
`contains a file system with errors, check forced`. Initramfs проверил корень
до обычной загрузки; systemd-fsck-root пропущен из-за существующего маркера
`/run/initramfs/fsck-root`. Дата 2017 года в этом логе относится к ранним
несинхронизированным часам и не является датой текущей проверки.

`/sys/fs/ext4/mmcblk1p2/errors_count` теперь 0, first/last_error_time также 0.
В текущем dmesg ошибок EXT4 не найдено, `systemctl`, `free`, `tar` работают.
Daily engine PID2288, network owner PID749 и USB rescue socket активны.
Это позволяет продолжить bounded trial с наблюдением за файловой системой;
аппаратная исправность накопителя одним таким наблюдением не доказана.

Сохранена приватная копия выбранных конфигураций и установленных компонентов:
`/private/tmp/cvpn-radxa-recovery-backup-20261030/configuration.tar` на Mac.
Размер 80271360 байт, 1577 entries, tar exit0; архив прочитан и содержит daily
config. SHA256:
`b94b08c1e7f410a93826ee08ca7ec038d1ab81e1e0a56e68343fef42af5c0f94`.
Каталог 0700, архив 0600, поскольку содержит ключи и настройки. Это выбранный
файловый backup, не полный образ накопителя и не атомарный snapshot.
