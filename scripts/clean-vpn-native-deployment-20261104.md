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

Статус: доступ к UFS восстановлен; от отдельного БП 5 В / 3 А обычные загрузки
и native VPN снова работают. Результаты восстановления и оставшиеся проверки
описаны в конце документа; исходный отказ на питании от Mac не считать
доказанным программным либо аппаратным диагнозом.

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

### Следующая попытка обычной загрузки: снова нет доступа

В живом rescue boot успешно переданы обязанности штатным networkd и sshd.
Обе передачи имели отдельный 60-секундный rollback timer; после подтверждения
таймеры отменены. Новый независимый SSH по `192.168.8.1` с исходным host key
прошёл, штатный networkd слушал DHCP 67. Runtime networkd/SSH masks сняты.

Для следующей загрузки подготовлен обратимый
`armbian-usb-gadget.service.d/99-clean-vpn-ufs-recovery.conf`: вместо старого
helper запускается проверенный `/usr/local/libexec/clean-vpn-ufs-rescue-usb`,
добавлены Requires/After udevd, сброшен ExecStop, отдельный ordinary-usb.log.
Vendor firewall сохранён в recovery directory и masked. Все project units
по-прежнему masked. `bash -n`, `sshd -t`, `systemd-analyze verify` для gadget,
networkd, ssh и graphical.target завершились успешно.

Рабочий rescue boot env сохранён как
`/root/cvpn-ufs-recovery-20261104/armbianEnv.working-rescue.txt`; перед reboot
восстановлен исходный env без systemd.unit. После `sync; systemctl reboot`
USB не появился, SSH по USB IPv4/IPv6 и прежнему uplink недоступен.
Пользователь подтвердил погасший экран. Новый boot ID и журнал ещё не получены.
**Это не успешная обычная загрузка.** Одной замены gadget helper недостаточно;
конкретная причина отказа всё ещё неизвестна. Не повторять reboot вслепую.

Запрошена загрузка SD. Следующий шаг: проверить модель/root/UUID, сохранить
журнал этой попытки, восстановить `armbianEnv.working-rescue.txt`, убрать только
новый vendor gadget recovery drop-in (сохранив его копию). Vendor firewall и
project units оставить masked. Вернуться к доказанно рабочему rescue boot;
новые boot-изменения делать только на основании полученных данных.

SD снова доступна, root `/dev/mmcblk0p1`; UUID UFS подтверждён. Получен
неудачный boot `3181398599614449b692656631caf3e6`: USB helper успел завершиться,
networkd выбрал recovery .network, затем запуск дошёл до basic.target (~14 s).
Явного panic/shutdown в сохранённом журнале нет. Последнее сообщение ALSA
само по себе не является диагнозом: такое же сообщение есть на рабочей SD
и в успешном rescue boot, ALSA state files совпадают по SHA256.

Журнал сохранён на обоих носителях как `ordinary-31813985.log`.
Точный рабочий env возвращён (SHA256
`960920cfe5bac9e635c20e58c25135205f902c6e633722ea14cbc8fffd600149`),
последний vendor gadget override убран и сохранён в recovery directory.
Vendor firewall/project units остаются masked. UFS sync + unmount выполнены.
Запрошено физическое возвращение с SD на этот проверенный rescue режим.

### Повторное восстановление подтверждено

UFS rescue снова загрузилась: boot `c8552771-c665-48bb-9f9f-b66b330de006`,
root `/dev/sda1`, DHCP UDP 67 и SSH USB IPv6/IPv4 работают, console NRestarts=0.
Поэтапный запуск до multi-user снова прошёл; checkpoints в
`stages-c8552771.log`. Поток dmesg дополнительно записывался на Mac в
`/private/tmp/cvpn-a7z-c8552771-kernel.log` (ограничение 600 секунд).
Networkd/sshd переданы штатным units с rollback timers; независимый SSH
подтверждён, timers отменены. Failed units нет.

Восстановлены из backup только `meshpn-admin-broker.service`,
`meshpn-admin-web.service`, `meshpn-admin.socket`. Админка на
`http://192.168.8.1/` дала HTTP 200 и с платы, и с Mac через en20.
VPN/network owner/clock/kill switch, captive и vendor firewall пока masked.
Rescue boot env оставлен без изменений; новой перезагрузки не выдавалось.

Пользователь подтвердил питание от Mac. System Profiler для gadget сообщает
bus_power=500, bus_power_used=250, extra_current_used=0 (мА). Это объявленные
USB-параметры, а не измерение мощности или доказательство причины отказа.
Radxa рекомендует 5 В / 3 А или выше:
https://docs.radxa.com/en/cubie/a7z/hardware-use/type-c .

Пользователь попросил не настраивать Wi-Fi: uplink должен быть через USB iPhone.
Уже есть DKMS ipheth, usbmuxd и
`/etc/systemd/network/09-armbian-iphone-uplink.network` (Driver=ipheth, DHCPv4,
RouteMetric=50). На момент проверки lsusb/idevice_id телефона не показывают;
на внешнем xHCI видны USB-хаб и Cardputer. Запрошено уточнение кабеля/порта.
Wi-Fi профили не менялись, сеть Mac не менялась, интернет на плате пока не проверен.

### USB iPhone uplink восстановлен и проверен

После уточнения пользователя (телефон подключён через хаб A7Z) iPhone появился
на xHCI-порту `1-1.3`, ipheth подключился автоматически. Networkd выбрал
`09-armbian-iphone-uplink.network`, выдал интерфейсу `enx5e50d9f02053`
DHCP-адрес `172.20.10.3/28`, gateway/DNS `172.20.10.1`, metric 50.
DNS example.org прошёл; curl HTTPS к example.org с явным bind к этому
интерфейсу вернул HTTP 200. NTP синхронизировался. Wi-Fi не подключён.

Независимый SSH с Mac к `172.20.10.3` через существующий маршрут en0 прошёл
с прежним host key; boot ID и UFS root совпали. Работают оба пути доступа:
USB `192.168.8.1` и iPhone uplink `172.20.10.3`. Маршруты/настройки Mac не менялись.
Это проверка прямого uplink платы, не VPN или forwarding для USB-клиента.
VPN остаётся masked, rescue boot остаётся выбранным. Обычный cold boot всё ещё
не принят. Запрошена доступность отдельного источника 5 В / 3 А для проверки
версии питания; команда на переключение питания или новую перезагрузку не дана.

### Подготовлен iPhone SSH при минимальной загрузке

Пользователь подтвердил отдельный QC/PD адаптер с выходом 5 В / 3 А и снова
включил UFS от Mac. Boot `5fc64327-0781-42e3-8129-3af699bb69ae` успешно
поднял прежний rescue. Для доступа после отключения USB от Mac добавлены:

- `usbmuxd.service.d/90-clean-vpn-ufs-recovery.conf`: временно
  DefaultDependencies=no, требует remount-fs и udevd; сохраняет исходный
  ExecStart с `--user usbmux --systemd`. Не подтягивает basic/sysinit ради модема.
- `clean-vpn-ufs-rescue-iphone.service` и helper `...-iphone-prepare`:
  modprobe ipheth и udev coldplug только Apple USB devices.
- `clean-vpn-ufs-rescue-iphone-ssh.service` и helper `...-iphone-ssh`:
  ждёт IPv4 на интерфейсе с driver=ipheth и запускает отдельный sshd только
  на полученном адресе. Исходные sshd_config/PAM/парольная политика сохранены.
  USB SSH продолжает работать отдельной прежней службой.
- `clean-vpn-ufs-rescue.target.d/20-iphone-access.conf`: Wants новой SSH-службы;
  отсутствие телефона не блокирует основной USB rescue.

Пройдены bash -n, sshd -t, systemd-analyze verify. До перезагрузки SSH через
iPhone прошёл при inactive basic/multi-user. После контрольной перезагрузки
**rescue режима** получен новый boot `3494755a-6f4a-4616-b6fa-8e7ca611a01f`:
UFS root, обе SSH-службы, ipheth DHCP `172.20.10.3`, usbmuxd активны автоматически;
новый вход через iPhone с исходным host key прошёл без ручного старта служб.
basic/multi-user остаются inactive, failed units нет. Команда reboot вернула
ошибку соединения с bus; фактическую перезагрузку подтверждает новый boot ID.

Boot env не изменён, SHA256 по-прежнему `960920cf...600149`.
Исходный target сохранён в `iphone-access-before/` в recovery directory.
Копия шести новых конфигурационных файлов без секретов на Mac:
`/private/tmp/cvpn-a7z-minimal-iphone-config.tar.gz`.
Для завершения восстановления удалить эти временные units/helpers/drop-ins,
включая usbmuxd drop-in; обычный ipheth .network сохранить.
Следующий физический шаг — штатное выключение и запуск от отдельного БП,
с iPhone через тот же хаб. Это ещё не проверка обычного cold boot или VPN.

### Отдельное питание: обычная загрузка впервые прошла

Пользователь подключил A7Z к отдельному QC/PD БП с маркировкой 5 В / 3 А.
Rescue boot `4c39b31d-df09-418b-ab12-bc0028d9c746` поднял iPhone SSH автоматически.

Для дальнейшей диагностики добавлен временный
`clean-vpn-ufs-arm-rescue-boot.service` (sysinit.target.requires): после remount-fs
и до sysinit/basic атомарно возвращает проверенный rescue boot env для
**следующего** включения. Проверяет SHA256 backup, sync, пишет boot ID/uptime
в `one-shot-boot-arm.log`. В rescue kernel command line unit пропускается.
Восстановление env предварительно отрепетировано. Это защита от повторного
ручного восстановления через SD, если отказ происходит после раннего шага.

Одноразовая обычная загрузка от БП прошла: boot
`40791a86-9327-45ae-807d-1a2198ef7c71`, kernel command line без rescue target,
graphical/multi-user/networkd/sshd active, failed units/jobs нет.
Пользователь подтвердил login на мониторе. systemd-analyze: 9.654 s kernel,
14.134 s userspace; graphical reached after 4.752 s userspace.
Early rescue arm сработал на uptime 11.64 s; boot env снова rescue.
Журнал `ordinary-psu-40791a86.log` сохранён на UFS, HTTP 200 через ipheth,
NTP synchronized. Это ещё не доказательство единственной причины питания:
сохранялись временные usbmuxd dependency override, USB helper replacement
и ранний recovery arm. VPN/admin/vendor firewall в проверке masked.

Следующая одноразовая проверка уже подготовлена: убран только временный
`armbian-usb-gadget.service.d/99-clean-vpn-ufs-recovery.conf`, возвращён штатный
gadget helper (NCM auto + исходный mass storage), early rescue arm сохранён.
Проверка прошла: boot `e83a46ab-1c78-4127-ad6d-0cc2b7e1ea14`, штатный
`armbian_multi_gadget`, graphical/networkd/sshd active, failed units нет.

### Native и админка восстановлены, проверен полный автозапуск

Из сохранённых копий возвращены guard, native network/engine/clock и admin
broker/web/socket/captive units. Включение guard+network owner сначала имело
независимый 180 s rollback timer; preflight eligible, engine ready, новый SSH
при guard прошёл, после проверки таймер отменён.

Временная настройка usbmuxd убрана из /etc/systemd/system/usbmuxd.service.d.
Вместо неё recovery generator
`/etc/systemd/system-generators/clean-vpn-ufs-rescue-usbmuxd` создаёт drop-in
только при kernel command line с rescue target. Обе ветви generator проверены
в приватной временной копии. При обычной загрузке usbmuxd имеет штатный
DefaultDependencies=yes и пустой DropInPaths. Восстановлены оба networkd gate
drop-in из исходного backup (Requires/After guard).

Полный обычный boot от БП `43a30d10-22ab-441e-b3dd-2f8874963e86` прошёл:
guard/admin/network owner стартовали сами. Owner один раз повторил запуск
через 10 s, пока iPhone не получил default route (`native_single_default_required`),
после чего engine ready, engine NRestarts=0, текущих failed units нет.
Локальная USB admin HTTP 200; listeners привязаны к 192.168.8.1%usb0:80/8443.
Native DNS UDP/TCP ответили; HTTPS строго через tun0 показал exit IP
84.201.14.124; download 1 MiB и upload 256 KiB завершились HTTP 200.
Новый HTTPS напрямую через ipheth к 1.1.1.1 при guard завершился timeout,
HTTP 000. Это ограниченная проверка, не полный аудит утечек.
Лог: `full-native-psu-43a30d10.log` в recovery directory.

Эти запросы идут от самой платы через packet/TUN ветку. USB-клиент и реальный
transparent interception после восстановления отдельно ещё не проверены.
Физического холодного запуска полного стека от БП ещё не было: выполнены
обычные software reboot после холодного старта rescue от БП.

Для сохранения прямого режима после выключения VPN/guard возвращены исходная
vendor firewall unit и оба installer ordering drop-in (vendor до guard,
DefaultDependencies=no у vendor). На текущем boot vendor start удерживался
runtime ConditionPathExists, чтобы не вставлять ACCEPT перед работающим guard.
Обычная загрузка с полным исходным порядком служб прошла:
`b24d94dd-900c-442d-85ed-a8c5bb013af0`. Vendor firewall и guard active;
в FORWARD hook `CLEANVPN_KS_FWD` стоит перед `ARMBIAN_USB_GADGET_FWD`.
Native ready, NRestarts=0, failed units нет, admin HTTP 200, DNS TCP отвечает,
HTTPS через tun0 подтверждает exit IP 84.201.14.124. Журнал сохранён как
`final-psu-stock-b24d94dd.log`.

После проверки удалена только requires-ссылка раннего rescue arm; daemon-reload
подтвердил отсутствие этой зависимости у sysinit. Атомарно восстановлен исходный
обычный `/boot/armbianEnv.txt`, cmp прошёл, SHA256
`53e5815b86d14223d8857c2d38eaa9d7e0bd44c3a4690eb69f96e796284c7953`.
Следующая загрузка обычная, автоматического возврата в rescue больше нет.
Receipt: `ordinary-native-restored.txt`. Плата оставлена работающей от БП.

Recovery helpers/target и условный usbmuxd generator сохранены для ручного
аварийного доступа; при обычной загрузке они rescue не включают. Диагностический
persistent journal и отключённый armbian-ramlog пока сохранены до проверки
физического холодного запуска. Четыре обычных software reboot от отдельного БП
прошли с постепенным возвратом штатных служб. Это поддерживает версию проблемы
питания от Mac, но без измерений не доказывает её. Следующие проверки — холодный
запуск полного стека и реальный USB-клиент, включая transparent-ветку combo;
после этого можно убрать оставшиеся временные диагностические настройки.

### Холодный запуск полного стека от БП принят

После штатного `systemctl poweroff` пользователь выключил/включил питание от
того же БП. Новый boot `9c3b8e81-847e-426b-b7fd-d35a1eca64ed`: UFS `/dev/sda1`,
обычный kernel command line без rescue target, boot env SHA256 не изменён.
Штатные gadget/firewall/guard/networkd/resolved/admin socket active, failed
units нет. iPhone получил DHCP на uptime 15.84 s. Network owner один раз
повторил запуск после отсутствующего default route; сеть готова на 35.43 s,
engine ready, NRestarts=0. NTP synchronized.

Проверки с самой платы: HTTPS через tun0 — exit IP 84.201.14.124;
native DNS UDP/TCP ответили; admin HTTP 200; download 1 MiB и upload 256 KiB
завершились HTTP 200. Guard hook перед vendor FORWARD hook. Результаты и журнал:
`cold-boot-9c3b8e81-acceptance.txt`, `cold-boot-9c3b8e81-journal.log` в recovery
directory. До выключения сохранены `before-full-cold-boot*.txt/log`.

USB `192.168.8.1` настроен, но no-carrier: БП занимает тот же разъём, куда раньше
подключался Mac. Пользователь подтвердил отсутствие адаптера для одновременного
внешнего питания и USB-клиента. Поэтому выдача USB DHCP lease и transparent
interception после восстановления остаются непроверенными; отсутствие DHCP
listener без carrier не засчитано как успешная проверка DHCP. Плата оставлена
на БП с работающим VPN, настройки сети Mac не менялись. Диагностические файлы
сохранены до завершения проверки USB-клиента.

После этого пользователь предложил снова подключить плату к Mac. Для сравнения
питания при той же конфигурации сохранён `before-mac-power-comparison.txt` и
обновлён журнал успешного холодного запуска от БП; выполнен штатный poweroff.
После подключения пользователь сообщил, что плата снова, похоже, выключается.
Проверка с Mac: A7Z/gadget отсутствует в IOUSB, TCP 22 недоступен как через
172.20.10.3, так и через 192.168.8.1. Нового boot ID и журнала пока нет;
это наблюдение потери устройства/связи, а не доказанный orderly poweroff.
Изменений конфигурации между успешным холодным стартом от БП и этой попыткой
не делалось. Результат усиливает версию проблемы питания/USB-подключения к Mac,
но эксперимент не разделяет питание, кабель и USB data path. Пользователю
предложено вернуть тот же БП и iPhone uplink для чтения persistent journal;
повторных запусков от Mac до разбора не планируется.

После возврата на тот же БП без правок конфигурации плата снова загрузилась:
boot `2b14df94-e812-447b-b1c8-eb3d0418d7cc`, UFS, engine ready/NRestarts=0,
failed units нет, HTTPS через tun0 — 84.201.14.124, DNS отвечает, admin HTTP 200.
Boot env checksum прежний. Между успешными boot найдены два коротких журнала
`ceb78ef81a1142c7b859adcd4b490a3b` и `ed827ce913f64003b6492cc7ec9fe95a`.
Оба скопированы в `mac-comparison-<boot-id>.log`; receipt успешного возврата —
`psu-return-2b14df94.txt` в recovery directory.

В сохранённых журналах этих двух попыток нет маркеров orderly shutdown,
kernel panic/Oops, OOM, thermal shutdown, EXT4/I/O error или старта native engine.
Последние сохранённые записи — ранний старт guard и flush journal. Это не
доказывает отсутствие ошибки после последней записи и не исключает проблему
драйвера/USB. Настройки/исходники/boot env не менялись; плата оставлена работающей
от БП. Проверка реального USB-клиента по-прежнему не завершена.

### Админка через iPhone uplink при отдельном питании

По запросу пользователя добавлен opt-in management access для standalone web:
`enx5e50d9f02053`, подсеть `172.20.10.0/28`, HTTP 8080, capture 18443.
Текущий адрес **http://172.20.10.3:8080/**. USB 192.168.8.1:80/8443 сохранён,
пароль общий; на момент приёмки ещё стандартный `admin`, требуется смена через UI.
Правила доступа и команды enable/disable: [admin README](../admin/README.md).

Первый apply выявил две ошибки интеграции, исправленные в исходниках: root
umask 077 делал опубликованный код нечитаемым для web UID; затем sandbox без
AF_NETLINK блокировал `os.networkInterfaces()`. Конфиг теперь root:meshpn-admin
0640, исходники 0644; owned drop-in допускает AF_NETLINK без сетевых capabilities.
Автоматическая проверка отклонила промежуточное предложение сделать web.json
0644; вместо этого применены более узкие групповые права 0640. Пароль не менялся.

Проверены 12 локальных тестов, первоначальные 11 также прошли на A7Z. С Mac:
главная HTTP 200, API без сессии 401, чужой Host 403; login/status/logout — 200.
С платы прежняя USB-админка отвечает 200. Проверен stop web → restart
`meshpn-admin-management.service` → HTTP 200; enable сохранён, systemd-analyze
verify прошёл. Физический reboot с этим новым opt-in ещё не выполнялся.
Native engine остался с PID 2146 и NRestarts=0 в boot 2b14df94; firewall/маршруты
для добавления админки не менялись. Сеть Mac не менялась.

Код коммитился на Mac. Первые изменения доставлены через origin; после отказа
GitHub SSH-авторизации коммиты до 2cdda77 доставлены через `git bundle`,
`git fetch` и `git merge --ff-only`, без редактирования исходников на плате.
Backup перед повторным apply: `/etc/meshpn-admin/management-backup-97OZMy`.

### Имя mpn-cubie.local и обычный порт 80

По следующему запросу management переведён на HTTP 80 с `--mdns`.
**Текущий URL: http://mpn-cubie.local/**, запасной **http://172.20.10.3/**;
8080 больше не слушается. Web остаётся UID `meshpn-admin`; добавлена только
CAP_NET_BIND_SERVICE. Сессии/Origin/CSRF и USB-админка сохранены.

Отдельная root-служба публикует текущий hostname админки через Avahi на
`enx5e50d9f02053`, отслеживает DHCP/смену имени. Её CAP_NET_ADMIN используется
для одного точного IPv4 mDNS OUTPUT-исключения. Новый guard распознаёт его
полную форму, частный source /32 и конкретный интерфейс; broad multicast,
DNS 53, wildcard interface и TUN запрещены аудитом. Guard/script обновлён из
Git с проверкой исходного SHA256, backup
`/root/cvpn-ufs-recovery-20261104/management-mdns-DFBg0D` и обновлением `after`
в native setup journal; guard/engine не перезапускались.

Avahi helper собран из Git-кода с `-Wall -Werror`. Management использует
dual-stack mDNS transport для A-записи, прежний USB-вызов сохраняет IPv4 default.
Backup прежнего helper — `mdns-helper.before-dual` в recovery directory.
Web listener остаётся IPv4; фиктивная AAAA-запись не добавляется.

На A7Z прошли 72 теста web/management/guard и read-only audit реального IPv4/IPv6
firewall. На Mac `dns-sd` получил A=172.20.10.3. Обычные curl и Node fetch по
имени получили HTTP 200; login/status/logout по http://mpn-cubie.local — 200.
Есть задержка около 5 s в dual-family DNS lookup, тогда как `curl -4` открывает
имя сразу. Публикация через оба mDNS-семейства эту задержку не устранила;
дальнейшее исследование отрицательного AAAA-ответа остаётся отдельной задачей.
Тест DNS-имени в URL/сертификате capture добавлен и прошёл локально.

Реальный stop/start mDNS-службы удаляет и восстанавливает только её правило;
guard status остаётся cvks5 для обеих семей. Engine PID 2146/NRestarts=0/ready
не изменился, failed units нет. Обе management-службы enabled; физический reboot
после этого изменения не выполнялся. Receipt — `admin-mdns-port80-acceptance.txt`.
Mac hosts/DNS/routes/Wi-Fi не менялись. GitHub по-прежнему отклоняет SSH-ключ;
код до 36e0416 доставлен на A7Z через Git bundle/fetch/fast-forward.


### Уточнение питания и одновременный Wi-Fi / USB iPhone

Пользователь проверил питание от Mac: A7Z отдельно, с дисплеем, с дисплеем
и iPhone загружается. Cardputer без iPhone тоже работает. Отказ воспроизводится
при дисплее + iPhone + Cardputer. Это поддерживает версию суммарной нагрузки,
а не безусловной невозможности питать A7Z от Mac; ток/напряжение не измерены.

При последующем подключении USB iPhone найден отдельный программный отказ:
network owner требовал ровно один default route. Wi-Fi wlan0 имел metric 600,
USB enx5e50d9f02053 — metric 50. Engine штатно остановился, owner повторял
native_single_default_required, guard оставался активным.

Исправлены выбор uplink и аудит repairUplink: используется уникальный минимум
метрики, порядок строк не учитывается; резервные defaults не удаляются.
Равные минимумы/ECMP отклоняются. Смена dev/gateway требует штатного recovery
с остановленным engine, без изменения живого набора маршрутов на месте.
67/67 Linux unit-тестов прошли; новый реальный netns сценарий проверяет два
uplink, потерю основного и возврат с recovery. Рабочая сеть Mac не менялась.

На A7Z обновлены два control-plane модуля из Git, их SHA256 в installed/prepared
manifest, сохранён backup /root/cvpn-uplink-update-UPSV8f. Preflight eligible;
engine PID 34314 ready/NRestarts=0, owner PID 32405. Оба default route сохранены,
exit /32 идёт через USB, внешний IP через tun0 — 84.201.14.124. DNS UDP/TCP
ответили, guard cvks5 обеих семей активен. Физическое отключение uplink для
повторного теста не выполнялось; смена проверена в отдельном netns.

Общее UI-исправление температур также установлено тремя статическими файлами,
без перезапуска web/VPN: блок «Температуры», отдельная подпись каждой thermal
zone. CPU/CPU B/CPU L/GPU/DDR/NPU/SoC получают короткие имена; неизвестные типы
сохраняются буквально, исходный тип доступен в title. Нет привязки к модели
или пяти датчикам. На прежней Zero развёртывание в этом сеансе не выполнялось.
Браузерная проверка админки и отдельные проверки A7Z/SoC/неизвестных/пустых
значений прошли. GitHub push снова работает; коммиты 469e1fa и 4a566a0 отправлены.

Полная изолированная kernel-матрица завершена: 38/38, без пропусков;
net/mount namespace + tmpfs /run, системные service-state ответы инъецированы.
Логи на A7Z: /root/cvpn-uplink-unit.log и /root/cvpn-uplink-netns.log.
Физические ограниченные передачи с платы через tun0: download 1048576 bytes,
upload 262144 bytes, оба HTTP 200. После нескольких минут PID engine/owner
прежние, NRestarts=0. Пересылка от отдельного USB-клиента этими запросами
не проверялась. Только перезагрузка страницы нужна для новых подписей датчиков.

### Стабильное имя iPhone — iphone0

На A7Z активировано общее правило `10-clean-vpn-iphone.link`: Match Driver=ipheth,
NamePolicy пустая, Name=iphone0. Сопоставления по MAC/серийному номеру/USB-порту
нет. Скрипт установки/удаления и границы: [iphone uplink](clean-vpn-iphone-uplink.md).
Native profile/owner принимают iphone0, прежние Ethernet/Wi-Fi имена сохранены.
На старой Zero правило в этом сеансе не устанавливалось.

Изменение доставлено через Git. Подтверждён независимый SSH по usb0/.8;
включён отдельный 180 s rollback timer до остановки owner. Сохранены два модуля,
installed/prepared manifests и web.json в `/root/cvpn-iphone-name-mHV0rn`.
Проверены исходные SHA256, обновлён ownership manifest. Guard не отключался.
Management CLI перенёс web/mDNS на iphone0, backup
`/etc/meshpn-admin/management-backup-Qxs7Ys`. Сетевой USB interface ipheth был
unbind/bind без перезагрузки платы и без изменения gadget/дисплея/хаба.

udev после повторного обнаружения подтвердил INTERFACE/ID_NET_NAME=iphone0,
ID_NET_LINK_FILE=/etc/systemd/network/10-clean-vpn-iphone.link. Штатный
09-armbian-iphone-uplink.network по Driver=ipheth выдал 172.20.10.5/28,
metric 50; Wi-Fi 172.20.10.3 metric 600 сохранён. Exit /32 идёт через iphone0.
Engine PID 91638 ready/NRestarts=0, owner PID 89824 active. DNS UDP/TCP ответили,
HTTPS через tun0 показал 84.201.14.124, HTTP на USB и iPhone IPv4 — 200.
mDNS guard exception привязано к iphone0 и текущему /32, cvks5 активен для
IPv4/IPv6. Rollback timer отменён после проверок; backup оставлен.

Проверка реального повторного обнаружения пройдена; физический reboot после
этого изменения не выполнялся. Linux config/setup tests 18/18 прошли;
полная netns matrix отдельно запускается с CVPN_IPHONE_PROFILE=1.
Повторный install правила идемпотентен, PID engine не изменился. С Mac
http://192.168.8.1/ и http://mpn-cubie.local/ ответили HTTP 200; имя выбрало
USB-адрес 192.168.8.1. Ранее известная задержка mDNS около 5 s сохраняется.
Матрица с iphone0 завершена: 38/38 настоящих netns/TUN/DNS/routes/NAT проверок,
без пропусков. Логи `/root/cvpn-iphone-unit.log` и `/root/cvpn-iphone-netns.log`.
При финальной проверке оба PID прежние, NRestarts=0, failed units нет.
