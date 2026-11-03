# Развёртывание новой пары — 4 ноября 2026

Запрос пользователя: exit root@84.201.14.124, client Cubie A7Z root@192.168.8.1.
Изменения исходников/коммиты на Mac, доставка кода на узлы через Git.
Сеть Mac не менять. Предыдущую рабочую пару не переключать.

## Отложено: разделение привилегий

Пользователь попросил запомнить и вернуться позже. Не включать эту переработку
в текущее развёртывание: отдельный `clean-vpn` UID для engine, права на ключи,
config/replay/TUN, минимальные capabilities по роли/транспорту, согласование с
admin broker и обновлением бинарника. Установка остаётся root; web уже работает
как `meshpn-admin`; сетевые/clock операции остаются у выделенных служб.
Нужны тесты доступа, reload/update, reconnect и recovery под новым UID.

## Обнаруженные отличия

- VPS: Ubuntu 18.04/systemd 237/kernel 4.15, x86_64, 1 GiB RAM, Docker.
  TCP 443 занят `mtproto-proxy` (`telegrammessenger/proxy:latest`). Пользователь
  явно разрешил остановить этот proxy и передать 443 clean-vpn; контейнер,
  настройки и прежнюю restart policy сохранить для rollback.
- Cubie: Armbian Debian 13, aarch64, kernel 6.6, 8 GiB RAM; usb0 192.168.8.1/24.
  DHCP обслуживает systemd-networkd, DNS — systemd-resolved. Существующий gadget
  `armbian_multi_gadget`, службы armbian-usb-gadget*.
  Uplink при обследовании: iPhone USB tether `enx5e50d9f02053`, wlan0 down.
- Установщик 4421f91 поддерживает прежний фиксированный профиль .7/wlan0/dnsmasq.
  Его нельзя без адаптации запускать на новой плате; сохранять .8 USB rescue.

Статус: exit работает; приёмка клиента заблокирована отсутствием доступа после
второй перезагрузки. Развёртывание пары НЕ завершено.

Подготовлены opt-in параметры client install: `--usb-backend=networkd
--usb-address=192.168.8.1 --uplink=auto`. Проверяется существующий Armbian gadget,
его boot ordering, действующий networkd config, DHCP socket и resolved DNS
listener. Vendor-файлы и службы не переписываются. Guard cvks5 фиксирует .8;
DNS, NAT, combo redirect, admin/captive/mDNS используют ту же подсеть.
`auto` принимает один default через Ethernet/Wi-Fi, исключая usb0/TUN/lo;
смена интерфейса запускает штатное восстановление маршрутов.

На старом exit conditional SSH clock provider использует ограниченный shell
helper с фиксированными busctl/date командами (systemd 237 без timedatectl show).
Формат nonce/ответа тот же; неподтверждённое NTP время не выдаётся.
Runtime exit собирается в Alpine/Docker, без обновления glibc VPS.

## Выявлено при первой физической перезагрузке

Armbian USB firewall стартовал после раннего kill switch и вставлял свой
`ARMBIAN_USB_GADGET_FWD` перед guard. Native audit отказывал в запуске, однако
foreign ACCEPT разрешал прямой USB forwarding. HTTP 200 без проверки exit IP
в этом состоянии нельзя считать успешной VPN-проверкой.

Исправление включено в установщик: owned drop-ins задают порядок
local-fs → vendor gadget → vendor USB firewall → kill switch → networkd.
У vendor firewall отключена только неявная DefaultDependencies-связь с
basic.target, иначе получается цикл через gated networkd.socket. Vendor
скрипт, DHCP, gadget и resolver не заменяются. Drop-ins журналируются и
удаляются uninstall; повтор install добавляет их к уже установленной Cubie.
Произвольный ручной перезапуск чужого firewall во время VPN не входит в
поддерживаемый lifecycle: он может переставить собственные rules.

## Развёрнуто

- Exit: `84.201.14.124:443`, `combo-tls`, контейнер `clean-vpn-exit`,
  `restart=unless-stopped`; Docker включён при загрузке. Образ
  `clean-vpn-native:4421f91` (engine не менялся в последующих control-plane
  commits), Alpine musl, около 95 MB без build layers. Собственные network
  `cvpn-new-exit-net` и replay volume `cvpn-new-exit-replay`. Host network не используется.
- Сохранённый `mtproto-proxy` остановлен, restart policy временно `no`; исходная
  policy `always` записана в `/var/lib/clean-vpn-new-exit/telegram-proxy-before.txt`.
  Возвращать его можно только после остановки clean-vpn, иначе конфликт 443.
- Client: `native-client-network.service` → `native-client.service`, guard
  `clean-vpn-killswitch.service`; включён combo, peer `10.99.0.2`.
- USB-админка: **http://mpn-cubie.local/** или **http://192.168.8.1/**.
  `mpn.local` остаётся старой Radxa. Начальный пароль `admin`; изменения через
  web требуют сначала сменить этот пароль. Web — отдельный `meshpn-admin` UID.
- CA/cert: `personal-cert.internal`, отдельные packet/relay ключи на каждого
  из трёх клиентов. Исходные комплекты на VPS:
  `/var/lib/clean-vpn-new-exit/exports/client-{1,2,3}.bundle.json`.
  Cubie получила только client-1, файл `/root/clean-vpn-client-1.bundle.json`.
- Штатные networkd DHCP и resolved DNS сохранены. Установлены зависимости и
  Node 24.13.0 в `/opt/clean-vpn-node`, без Python. В исходном образе `/usr` и
  `/opt` имели root:root 0775; убрана групповая запись до 0755. Исходные режимы
  записаны в `/root/clean-vpn-downloads/{usr,opt}-mode-before.txt`.
- Временный build swap VPS выключен и удалён. Пробный loopback listener 8443
  и временный lab-контейнер удалены. На VPS сохранён owned modules-load файл
  для `ip6table_filter`: иначе старое ядро не даёт контейнеру поставить IPv6 guard.

## Приёмка

Санитизированные результаты: `fixtures/clean-vpn-native-cubie-deployment-20261104.json`.
CTest на Cubie 14/14, профильные regression 109/109, installer 11/11,
37 kernel/journal проверок с foreign USB ACCEPT. Реальные USB HTTP(S), UDP/TCP
DNS, 2 MiB download, 1 MiB upload, переключение combo/boring/combo прошли.
В boring внешний IP подтверждён как новый exit. Независимые USB/WAN pcap
сохранены на Cubie в root-only `/root/clean-vpn-downloads/acceptance/`;
profile matched, relay JA3/JA4 сохранены, kernel capture drops = 0.
Clock probe с pinned SSH прошёл без изменения времени; используется только
после распознанного time-related отказа native, а не при каждом включении.

Это ограниченная приёмка curl с ноутбука, не новая iPhone/Speedtest-browser
или длительная soak-проверка. Сеть Mac и прежняя рабочая пара не изменялись.

## Блокировка повторной загрузки

После установки boot-order drop-ins (`f6a7d54`) проверка systemd-analyze verify
на плате прошла, но после `reboot` плата не вернулась: USB-устройство исчезло,
SSH недоступен по 192.168.8.1 и прежнему uplink 172.20.10.3. Пользователь
переподключил питание/USB: сначала мигал индикатор и работал вентилятор,
затем мигание и вентилятор остановились; SSH и админка недоступны.
Причина не установлена: журнала этой загрузки нет. Нельзя считать это
доказанным аппаратным отказом или успешной проверкой cold boot.

Упрощённая модель зависимостей gadget/firewall/guard/networkd в отдельном
systemd-контейнере после restart запустила все четыре службы без зависших
jobs. Она использует заглушки ExecStart и не проверяет аппаратный gadget,
фактические firewall-скрипты или полный граф служб Armbian.
Следующий шаг — локальная консоль либо доступ к системному накопителю,
чтение журнала и проверка/откат последних owned drop-ins. Отрицательная
проверка USB kill switch после reboot пока НЕ выполнена.
Новый exit отдельно проверен: healthy на TCP 443; Telegram proxy остановлен.

## Восстановление UFS из SD

Пользователь загрузил A7Z с SD, SSH `192.168.7.1`. Проверены device-tree model
`Radxa Cubie A7Z`, root `/dev/mmcblk0p1`, UFS `/dev/sda1`, UUID
`f57f69a0-ca41-4383-a118-b9df026556b5`. Это новая rescue-система, а не прежняя
Radxa на таком же IP; использован отдельный SSH known_hosts.

UFS сначала смонтирована ro,noload. Журналы последних четырёх boot доходят
до запуска gadget/firewall/guard/networkd и basic/network.target (~13–15 s),
явной причины выключения в сохранённой части нет. Это не доказательство
отсутствия поздней ошибки. `e2fsck -fn` на размонтированном разделе завершился
с кодом 0, без структурных ошибок; часы SD отстают, поэтому была отметка
о last mount time в будущем. Автоматический repair не запускался.

Обратимое восстановление выполнено, но загрузка UFS после него ещё не проверена:

- Замаскированы только 8 project units: guard, native client/network/clock,
  admin broker/captive/web/socket. Конфигурации и ключи не удалены.
- Убраны два networkd gate drop-in и два новых vendor/guard ordering drop-in.
- Сохранены включёнными штатные SSH, networkd, vendor gadget/firewall.
  VPN и kill switch выключены; штатный direct forwarding может работать.
- Для диагностики временно `armbian-ramlog ENABLED=false` и journald drop-in
  `99-clean-vpn-recovery.conf` (persistent, SyncIntervalSec=1s, max 64M).
- Backup на SD и UFS: `/root/cvpn-ufs-recovery-20261104/before.tar`, SHA256
  `94f96ea4433416c9b01872541ee3e82fe8c21a11bcd55166a8c1484e52d3b886`.
  На UFS там же перемещённые units/drop-ins и README; на SD — recovery shell.
- Boot/USB/networkd/zram конфигурации сравнены с backup: не изменены.
  UFS синхронизирована и размонтирована. Перезагрузка/poweroff не выдавались.

Далее: выключить SD-систему, извлечь SD после остановки, загрузить UFS и
проверить SSH **192.168.8.1**. Админка на этом этапе отключена намеренно.
Не восстанавливать все службы сразу и не объявлять первопричину установленной
до чтения нового boot-журнала. Временные настройки логирования затем вернуть.

### Повторная попытка после частичного отката

Пользователь сообщил о повторном отключении. Снова загрузил SD; после штатного
replay pending EXT4 journal найден актуальный boot
`2c3c17ae70bf43c59a9b7c678dee407b`. Первый ro,noload показал старую запись
`cc5180d97553455198bbe98ab217c064`; её нельзя принимать за результат отката.
Актуальная запись подтверждает отсутствие запуска guard и новое отключённое
RAM logging, но обрывается вскоре после journal flush. Причина остаётся неизвестной.

Проверена точная история команд: между доступной загрузкой `b41abacd...` и
неудачной перезагрузкой — stop vendor firewall, restart native network owner,
git pull/install с двумя новыми ordering drop-ins, verify и `sync; systemctl reboot`.
В этот интервал ядро/DTB/загрузчик не изменялись. Hash ядра, DTB, fan overlay,
systemd и journald на UFS совпали с рабочей SD. Полный offline verify default.target
и journal verify не выявили ошибки, объясняющей отключение.

Подготовлен отдельный **временный диагностический** boot, ещё НЕ проверенный:

- В extraargs UFS добавлены `systemd.unit=clean-vpn-ufs-rescue.target panic=0`.
- Исходный boot env сохранён в
  `/root/cvpn-ufs-recovery-20261104/armbianEnv.before-minimal.txt`.
- Четыре `clean-vpn-ufs-rescue.*` unit: target, USB, network, SSH. Обычный
  multi-user/graphical target не запрашивается, project units остаются masked.
- Shell helper `/usr/local/libexec/clean-vpn-ufs-rescue-usb`: отдельный NCM
  gadget, USB 192.168.8.1, DHCP без объявления router/DNS, без mass storage.
- sshd использует исходный `/etc/ssh/sshd_config` и PAM, только ListenAddress
  ограничен 192.168.8.1; аутентификация не ослаблена.
- Прямые append logs `minimal-{usb,network,ssh}.log` в recovery directory;
  конфигурация проверена `bash -n` и offline `systemd-analyze verify`.
- UFS размонтирована, перезагрузка не выдавалась. Следующий шаг — физический
  запуск этого режима; не обещать успешный ремонт до его проверки.

Для удаления диагностического режима после получения доступа: восстановить
сохранённый boot env и удалить только три rescue service, rescue target и
rescue USB helper. Обычные службы не включать одновременно до выяснения причины.

### Минимальная загрузка: USB работает, DHCP не настроился

Пользователь подтвердил: экран больше не гаснет; Mac видит стабильный
`A7Z UFS recovery`, en20. SSH недоступен по IPv4, потому что Mac остался
с self-assigned 169.254 address. По возвращении на SD прямые logs показали:
USB configured 192.168.8.1; sshd listening 192.168.8.1:22; networkd видит
carrier/IPv6LL, но не конфигурирует usb0. Минимальный target не запускал
udevd; исправление добавляет его и trigger только /sys/class/net/usb0.
Это ещё не установление причины отказа обычной загрузки.

В минимальный режим v2 добавлены обычный getty login на tty1 и фиксированный
link-local `fe80::479:7cff:fe07:11e3` на USB. sshd использует прежний config/PAM,
слушает только 192.168.8.1 и этот IPv6 с zone usb0 (в systemd unit `%%usb0`).
Со стороны Mac использовать `%en20`, сверять исходный SSH host key; никаких
изменений адресов или маршрутов Mac для этого не требуется.
Конфигурация прошла bash/systemd verify и sshd -t в изолированном mount namespace.
Исходный минимальный режим сохранён в `minimal-v1.tar`, SD содержит скрипты
prepare-minimal*.sh. UFS размонтирована; физическая проверка v2 ожидается.

Строка `axp8191-bldo2: disabling` наблюдается также в рабочей SD-системе и сама
по себе не доказывает отключение платы; настройки регуляторов не изменялись.

### UFS rescue v2: доступ восстановлен, обычный cold boot ещё не принят

Физическая загрузка v2 прошла: root `/dev/sda1`, тот же UUID UFS, boot ID
`01e40486-07a6-41cd-b7cc-adcfd7eecdfb`. Сначала SSH восстановлен по USB IPv6LL
с проверкой исходного host key, затем заработал IPv4 `192.168.8.1:22`.
DHCP выдал Mac адрес `192.168.8.31`; настройки сети Mac не изменялись.

В минимальном режиме networkd ждал persistent lease storage, служба которого
не входила в rescue target. Только в генерируемой recovery-конфигурации
`/run/systemd/network/00-clean-vpn-ufs-rescue.network` добавлено
`[DHCPServer] PersistLeases=no`. DHCP слушает UDP 67; router/DNS не объявляет.
Это исправление recovery DHCP, а не установленная причина исходного отказа.

В этой загрузке последовательно запущены journald, modules-load, sysinit,
basic, D-Bus, logind, fan, Avahi, wpa_supplicant, Bluetooth и multi-user.
USB остаётся configured, роль usb_device, SSH доступен более 12 минут.
Штатные gadget/firewall исключены runtime ConditionPathExists без sentinel;
штатные networkd/socket/sshd runtime masked, чтобы не столкнуться с rescue
экземплярами. Следовательно, это не проверка исходного полного boot-графа.

При запуске multi-user обнаружен конфликт штатного getty@tty1 и rescue getty:
они перезапускали друг друга. Добавлен отдельный recovery drop-in
`/etc/systemd/system/getty@tty1.service.d/99-clean-vpn-ufs-rescue.conf` с
`ConditionKernelCommandLine=!systemd.unit=clean-vpn-ufs-rescue.target`.
Штатный getty пропускается только в rescue boot; rescue getty после исправления
сохраняет PID и счётчик рестартов. Failed units и ожидающих jobs больше нет.
При удалении rescue режима удалить также этот drop-in и console service.

На UFS сохранены `stages.log`, `live-kernel.log`, `staged-boot.log`,
`recovered-state.txt` и минимальные logs в указанном recovery directory.
Часы платы не использованы как источник достоверного времени события;
для сопоставления использовать boot ID и monotonic timestamps.

**Текущее состояние:** временный rescue target всё ещё указан в boot env;
VPN/kill switch/админка masked. Настройки и ключи сохранены. Обычная загрузка,
автозапуск VPN и доступ в интернет после восстановления НЕ проверены.
Новых reboot/poweroff после успешного rescue не выдавалось.

Следующий шаг — изолировать различия обычного USB startup и рабочего rescue:
vendor helper выбирает device role до bind и включает mass storage, rescue
выбирает роль после bind и использует только NCM. Причинность не доказана.
Не запускать оба gadget одновременно и не восстанавливать все units одним
действием. Рабочий SSH/IPv6 и console сохранить до проверки обычного cold boot.
