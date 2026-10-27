# Native clock recovery: только после отказа по времени

Checkpoint 2026-10-27. Это подготовленный протокол и helper; автоматическая
интеграция с постоянным systemd lifecycle ещё не установлена на Radxa/VPS.
Никакого безусловного `ExecStartPre` для синхронизации часов нет.

## Условие запуска

1. Сначала клиент делает обычное соединение с полной проверкой CA, имени,
   срока сертификата и exporter-bound PSK.
2. Только `tls_verify_expired`, `tls_verify_not_yet_valid` или
   `auth_clock_skew` разрешают запрос доверенного времени. Первые два кода —
   причина проверить часы, не доказательство, что виноваты именно они.
3. Владелец lifecycle останавливает свой engine/service, сохраняя независимый
   kill switch и USB rescue. Helper проверяет отсутствие MainPID, start job и
   auto-restart до запроса и до изменения часов. Владелец обязан исключить
   параллельный запуск consumer до завершения recovery.
4. Отдельный SSH-ключ обращается по IP к закреплённому raw Ed25519 host key.
   SSH agent, пользовательский config, multiplex, proxy, password и TOFU не
   используются. Host key получают по уже проверенному каналу, не доверяют
   результату одного `ssh-keyscan`.
5. Ответ содержит свежий nonce, Unix time и признак синхронизации VPS.
   Проверяются формат, размер, RTT ≤5 секунд, неизменность локальных часов
   во время запроса и нижняя граница ранее принятого времени.
6. Часы меняются только при отличии больше погрешности измерения. Если
   SSH-время совпадает с локальным, helper ничего не переводит. Просроченный
   сертификат нельзя «чинить» переводом часов к его сроку действия.
7. Затем владелец lifecycle повторяет обычное TLS-соединение с теми же
   проверками. Ошибки не разрешают ослабить TLS или guard.

`ready`, таймауты/обрывы, неверный PSK, CA или hostname не разрешают recovery.
Одна автоматическая попытка на загрузку: `attempt.json` публикуется с fsync до
SSH. Ошибка запроса и restart службы не сбрасывают бюджет; после неудачи нужна
диагностика, а не бесконечные запросы. Новая загрузка сама запрос не вызывает:
сначала снова нужна одна из трёх ошибок. Read-only `probe` — отдельная ручная
диагностика, не boot hook и не автоматическая смена времени.

## Как отличаем неверный PSK от неверных часов

Клиент передаёт `x-clean-vpn-window` внутри уже защищённого H2. Это то же
15-минутное окно, которым подписан `authorization`. Обычная проверка ±1 окно
не меняется. Если она не прошла, exit проверяет MAC для заявленного окна,
используя настроенный peer PSK и TLS exporter **этого** соединения.

Только правильный MAC вне текущего окна получает `409` +
`x-clean-vpn-error: clock-skew`. Это отказ: peer address не захватывается,
`ready` не устанавливается, пакеты не принимаются. Неверный PSK, повтор MAC
из другого TLS-соединения, нечисловое/слишком длинное окно и произвольный
заголовок сами по себе такого ответа не дают. Граница unauthenticated
соединений и deadline остаются прежними.

Старый клиент с правильным временем продолжает работать без нового заголовка.
Старый exit не умеет выдавать этот диагноз; общий auth failure не заменяет
его и не включает SSH recovery. Изменяется H2 control header, не ClientHello.

## Ограничения доверия и установки

SSH доказывает, что время пришло от закреплённого VPS, а не что оно абсолютно
верно. Скомпрометированный VPS или ошибочный источник его времени могут
сообщить неверную дату. `NTPSynchronized=yes` — необходимое состояние сервера,
а не криптографическое доказательство правильности NTP.

На сервере нужен отдельный непривилегированный пользователь, отдельный ключ
клиента и root-owned helper. В `authorized_keys` обязательны **оба** ограничения:

```text
restrict,command="/usr/bin/timeout 5s /usr/bin/python3 -I /opt/clean-vpn-clock/clean-vpn-native-clock.py serve" ssh-ed25519 PUBLIC_KEY
```

Это пример для будущего установщика, не команда установки. Пользователь не
должен иметь password login, изменяемые им helper/authorized_keys, дополнительные
ключи с широкими правами или интерактивный доступ. Shell должен позволять
исполнить forced command; один `nologin` может заблокировать и этот путь.
`serve` принимает только `SSH_ORIGINAL_COMMAND=clean-vpn-clock-v1` и nonce.

Один `command=` не запрещает forwarding: нужен `restrict`.
[Документация OpenSSH authorized_keys](https://man.openbsd.org/sshd.8),
[параметры клиента SSH](https://man.openbsd.org/ssh_config.5).

Конфигурация клиента — root-owned regular file 0600, без symlink:

```json
{
  "version": 1,
  "host": "192.0.2.1",
  "port": 22,
  "user": "cvpn-clock",
  "identity": "/etc/clean-vpn-clock/identity",
  "known_hosts": "/etc/clean-vpn-clock/known_hosts",
  "state_dir": "/var/lib/clean-vpn-clock",
  "consumer_unit": "clean-vpn.service"
}
```

`known_hosts` содержит одну строку `clean-vpn-clock ssh-ed25519 BASE64`.
`state_dir` — 0700; ключ и state-файлы — 0600. Не использовать SSH certificate
вместо raw host key: bootstrap должен работать до восстановления даты.

API helper (ещё не подключён к autostart):

```sh
python3 -I scripts/clean-vpn-native-clock.py probe --config=/etc/clean-vpn-clock/config.json
# Только после отказа своего engine и завершённого stop consumer:
python3 -I scripts/clean-vpn-native-clock.py apply --config=/etc/clean-vpn-clock/config.json --failure=auth_clock_skew
```

`--failure` — assertion доверенного root lifecycle, не самостоятельное
доказательство события. Передавать код из своего контролируемого engine,
не из пользовательского ввода, сетевых заголовков или произвольного журнала.
Сам helper не останавливает службы, не перезапускает VPN, не меняет firewall,
DNS, RTC или конфигурацию NTP. `apply` отказывается работать на macOS.

## Проверки и следующий шаг

- `python3 -B scripts/test-native-clock.py`: условия запуска, бюджет через
  restart/ошибку SSH, совпадающее время при expired certificate, остановка
  consumer, pending restart, stale response, параллельная смена часов,
  nonce/размер/нижняя граница/права и server synchronization gate.
- `scripts/test-native-clock-ssh.py`: только disposable Linux container,
  `CVPN_DISPOSABLE_CLOCK_SSH_LAB=1`, сеть none. Настоящий sshd/SSH, временные
  ключи, отказ неправильному pin/identity и запрет shell/forwarding. Forced
  command в этом тесте — protocol fixture; он не подменяет реальную проверку
  `NTPSynchronized` на VPS. Не запускать на рабочем хосте: тест настраивает
  учётную запись внутри контейнера.
- `CVPN_BUILD=... node --test scripts/test-native-clock-auth.mjs`: реальный
  TLS/H2, часы ±13 часов/2017 без изменения часов хоста, неверный PSK и
  exporter, malformed windows, старый клиент, диагностика native client.

Следующий шаг — подключение к существующему host lifecycle с независимым
recovery, затем clock-fault/reboot в NIC-less VM и bounded physical check.
Реальное изменение системных часов и автоматический restart этим checkpoint
ещё не проверены и не объявляются готовым unattended autostart.

Итог локального checkpoint: 11/11 Python policy, 4/4 real SSH, 21/21
clock-auth/interop после исправления premature-stop race fixture; 10/10 CTest,
18/18 TLS-profile, native data-plane и 12/12 controller/diagnostics прошли.
Первый объединённый прогон (37/40) и причина трёх отказов сохранены в
[отчёте с SHA-256 исходников и артефактов](../fixtures/clean-vpn-native-conditional-clock-20261027.json).
На VPS выполнено только read-only чтение состояния systemd/часов: Python есть,
`NTPSynchronized=yes`; никакие ключи, службы или часы не менялись.
