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

Статус: обследование и подготовка. Этот документ не подтверждает развёртывание.

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
