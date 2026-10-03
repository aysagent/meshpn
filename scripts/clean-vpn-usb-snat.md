# USB-клиент за текущим host VPN: точечный SNAT

Для постоянной установки теперь есть [USB-режим общего установщика](clean-vpn-usb-gateway.md).
Описанный ниже отдельный helper меняет только текущие правила SNAT и TCP MSS.
Текущая версия требует строгий USB guard `cvks4`; для старой установки сначала
нужно явное обновление через общий установщик, описанное по ссылке выше.
Сам SNAT-helper политику безопасности не обновляет.
На Radxa `fc8c50d` пользователь подтвердил: после применения SNAT
`curl --interface en9` на Mac возвращает `154.62.226.216`.

Установленная на Radxa конфигурация — host-client, native TLS, split-default,
`--ipv6=auto`, persistent guard both/block. В ней **нет** `--client-lan-subnet`.
Просто добавить этот флаг нельзя: IPv6 runtime и networkd installer пока
ограничены host-only. Ограничения не снимаются этой правкой.

Полученный от пользователя снимок: `ip_forward=1`, в POSTROUTING только
`-o wlan0 -j MASQUERADE`, FORWARD ACCEPT после persistent guard. Mac имеет
192.168.7.19/24 и scoped default через 192.168.7.1 на en9. DNS разрешил имя,
TCP не установился. Для выхода в TUN отсутствует SNAT: exit ожидает source
10.99.0.2, а forwarded-пакет сохраняет source 192.168.7.19.

`clean-vpn-usb-snat.mjs` добавляет одно именованное правило SNAT:

```text
-A POSTROUTING -s 192.168.7.0/24 -o tun0 -m comment --comment clean-vpn-usb-snat-v1 -j SNAT --to-source 10.99.0.2
```

Также устанавливает два правила `clean-vpn-usb-mss-v1` в mangle/FORWARD:
IPv4 TCP SYN/SYN-ACK из USB-подсети через `usb0 → tun0` и обратно к ней через
`tun0 → usb0`, MSS не выше 1360 при проверенном MTU TUN 1400. Все TCP-порты,
без изменения filter/kill-switch, без влияния на INPUT/USB SSH. Это устранение
TCP MTU black hole, а не универсальная обработка крупных UDP/PMTU.
`--status` проверяет полный текущий набор без записи (код 0 и `ready` только
если SNAT и оба MSS-правила присутствуют и профиль готов).

Проверяет активные VPN/guard/rescue, точный guard-профиль, имеющийся ip_forward=1,
адреса USB/TUN, обход exit через wlan0 и forwarded-маршруты тестовых адресов через
tun0. Неизвестные POSTROUTING/FORWARD правила, дубликаты и несовместимая сеть
вызывают отказ до записи. Параллельные администраторы firewall не поддерживаются.
Это не аудит произвольного native nft ruleset или всех routing policy.

На Radxa с уже работающим VPN:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-usb-snat.mjs
sudo env "PATH=$PATH" node scripts/clean-vpn-usb-snat.mjs --apply
```

Без `--apply` — только план. Повторное применение не добавляет дубликат.
Не меняются filter/guard, маршруты, IPv6, sysctl, services, USB или SSH.
Правила действуют только до reboot/их явного удаления: **это ещё не постоянный
режим USB-шлюза**. Сначала требуется реальная проверка Mac. При остановке VPN
правило не открывает wlan0: оно действует только для выхода в tun0; сохранённый
guard обязан продолжать блокировать публичный forwarded-трафик мимо TUN.

На Mac:

```bash
curl -q -4 -v --noproxy '*' --interface en9 --connect-timeout 5 --max-time 15 https://ifconfig.me/ip
```

Ожидаемый внешний IP: 154.62.226.216. Если остаётся таймаут, проверять scoped
маршрутизацию/фильтры второго VPN Mac и прохождение SYN через usb0/tun0;
не отключать наугад защиту. Успех одного HTTPS не означает приёмку DNS/IPv6
и всех forwarded-потоков. В текущем `cvks4` пересылка USB напрямую в LAN
запрещена; доступ к самой плате сохраняется.

Удалить только эти три правила, не останавливая VPN и не снимая guard:

```bash
sudo env "PATH=$PATH" node scripts/clean-vpn-usb-snat.mjs --remove --apply
```

## Потеря Wi-Fi и bypass к exit

При выключении/включении роутера пользователь получил новый DHCP IPv4
192.168.1.7, default через wlan0 восстановился, но `ip route get 154.62.226.216`
показывал tun0. Обходной /32 исчез; повторные TLS-подключения шли в собственный
туннель. Это дефект восстановления маршрутов, а не отсутствие Wi-Fi-ассоциации.

Перед очередной TLS/boring-TLS попыткой host split-default теперь проверяет
журнал и восстанавливает исчезнувшие **собственные** uplink-маршруты. Только
тот же boot, netns, интерфейс (ifindex/MAC/type) и прежний gateway; новый DHCP
адрес на этом интерфейсе допустим. Пока default отсутствует, подключение
откладывается. Чужие маршруты не заменяются, заимствованный чужой /32 после
исчезновения не присваивается. Смена gateway/interface требует отдельного
решения, как и незавершённые журналы после SIGKILL.

Это восстановление при следующей попытке соединения, не мгновенное обнаружение
обрыва и не обещание сохранения уже открытых TCP-сессий. Guard и USB не меняются.

## Проверки

### Постоянный MSS, 2026-10-04

- **440 PASS**: USB/host/guard/routes/bridge и модульная DNS tunnel регрессия
  (`node --test`, без файлов `*-real.mjs`, требующих отдельного окружения).
- **36 PASS**: `/var/tmp/meshpn-usb-snat-lab-4EdUel/report.json`.
  Реальные iptables-nft, veth MTU 1500 со стороны origin / 1400 на шлюзе,
  offload отключён только в VM. Контроль: 128 КиБ download работает с MSS,
  после удаления MSS зависает, после применения снова работает; также
  проверены 128 КиБ upload+download, идемпотентность, удаление обоих правил,
  неизменность guard, блокировка без TUN и локальная USB-доступность.
- **62 PASS (32 + 30, две загрузки)**:
  `/var/tmp/meshpn-usb-gateway-lab-4xWTiD/report.json`.
  Реальный systemd и аутентификация SSH:22/2222, поздняя готовность TUN,
  обновление точного старого helper с проверенной резервной копией,
  `--status`, сохранение SSH PID/guard, удаление SNAT+MSS и повторная загрузка.
  VPN readiness в этом стенде моделируется, это не полный VPN/TLS E2E прогон.

Хеши включённых production/VM-исходников сверены с рабочей версией.
Первый запуск `2zApHw` выявил отсутствующий TCPMSS plugin в старом образе.
Промежуточные `VuotZg`, `XvdFe0`, `g1P5T2` не прошли: искусственный DROP
по длине на OUTPUT видел GSO-агрегаты, а на receiving PREROUTING большой
пакет уже отбрасывался veth из-за MTU. Итоговый тест использует непосредственно
асимметричный MTU и положительный/отрицательный контроль, не искусственный DROP.
Эти неуспешные отчёты сохранены и не засчитаны как PASS.

Дополнительный широкий glob захватил `*-real.mjs`: они отказали в текущем
окружении из-за отсутствия `/dev/net/tun`/`conntrack`; в 440 PASS не включены.
Полный TLS E2E/soak на новой версии здесь не повторялся. Проверка постоянного
MSS на физической Radxa после обновления и reboot остаётся в
[списке приёмки](clean-vpn-radxa-next-checks.md). Большие UDP/PMTU не закрыты.

`node --test scripts/test-usb-snat.mjs scripts/test-vpn-host-routes.mjs` проверяет
предусловия, идемпотентность, отказ при чужих правилах/маршрутах, cleanup и вызов
ремонта перед каждой попыткой TLS. `clean-vpn-usb-snat-lab.mjs` использует
проверенный NIC-less QEMU image и отдельные namespace Mac/exit/router:
настоящие iptables-nft, SNAT, forwarded TCP/UDP53, блокировка без TUN, доступность
локального USB-пути и потеря маршрутов при моделируемой смене DHCP-адреса.

Ограничения VM: Linux peer вместо macOS, tun0 — veth-модель без VPN/TLS,
состояния systemd/rescue подставлены, UDP53 — синтетический roundtrip, а не
разрешение DNS. Это не проверка RF/Wi-Fi драйвера, автозапуска USB-шлюза или
реального Mac. Прямой TLS проверяется отдельным loopback regression suite.

Исторический прогон до строгой USB-политики `/var/tmp/meshpn-usb-snat-lab-ntW556/report.json`: **PASS, 29 проверок**,
хеши пяти включённых исходников совпали. Проверены положительные контроли:
без guard прямой IPv4/IPv6/UDP53 путь действительно работает, с guard при
исчезнувшем TUN — блокируется. Образ удалён, отчёт и boot.log сохранены.
Первый прогон `ojfuOM` сохранён как failed: UDP fixture отвечал с адреса
интерфейса вместо адреса запроса; исправлено явным bind тестового UDP-сервера.
Итоговая локальная регрессия routes/SNAT/guard/update/stop/HTTP-Date: **192/192**.
