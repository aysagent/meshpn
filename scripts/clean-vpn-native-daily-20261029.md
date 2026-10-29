# Постоянная пара Radxa ↔ VPS: boring-tls, 29 октября 2026

По явному разрешению пользователя native VPN оставлен **работающим с автозапуском**
на существующих Radxa и VPS. Админка управляет этой установкой. Старый Node VPN
и старый USB SNAT service на Radxa остановлены и отключены от автозагрузки.
Это выбранная личная установка, не утверждение о поддержке любого Linux-хоста.

## Как пользоваться

Через USB: **http://mpn.local/**, запасной адрес **http://192.168.7.1/**.
Пароль по-прежнему `admin`: он не менялся автоматически. Для изменения настроек
сначала сменить его в разделе «Устройство», затем войти снова. Веб-интерфейс
слушает только `192.168.7.1%usb0:80`; порт захвата — `8443` на том же интерфейсе.

Выбран `boring-tls` и профиль `chromium-156-bounded-cold-v1`
(в списке админки файл `native-daily-installed.json`). DNS интеграцией и маршрутами
управляет native network owner; dnsmasq/USB DHCP сохранены. Wi-Fi настройки
и файл пароля админки остались побайтово прежними. Конфигурация DNS upstream
в админке пока не редактируется: engine использует фиксированные upstream.

На Radxa управлять **сетевым owner**, чтобы TUN/маршруты/DNS менялись согласованно:

```sh
systemctl status native-daily-network.service native-daily.service --no-pager
systemctl restart native-daily-network.service
# Остановка VPN сохраняет kill switch: прямой интернет через плату не открывается.
systemctl stop native-daily-network.service
systemctl start native-daily-network.service
journalctl -u native-daily-network.service -u native-daily.service \
  -u native-daily-clock.service -n 80 --no-pager
```

На VPS owner — `native-daily-exit-network.service`, engine —
`native-daily-exit.service`. Установленные bundles находятся в
`/opt/clean-vpn-native/daily` и `/opt/clean-vpn-native/daily-exit` соответственно.
Только owners включены в автозагрузку; engine запускается своим owner.
Node остаётся в control plane/админке, payload/TLS/DNS обслуживает C++.

## Что проверено на физических узлах

- Новые ARM64/x64 binaries собраны из `eea428e`; CTest **10/10 на каждом**.
  Radxa: RelWithDebInfo, два compiler jobs, без low-memory, без расхода zram
  в проверенных замерах. VPS: один job, low-memory с сохранением оптимизации;
  временный собственный swap после сборки выключен и удалён.
- Первый реальный TLS отказ `tls_verify_not_yet_valid` запустил отдельный clock
  recovery. Закреплённый SSH host key, отдельный клиентский ключ и forced command
  для непривилегированного `cvpn-clock`; никакого shell/forwarding. Поправка
  **1904.426 с**, RTT **1847 мс**, затем обычная TLS/PSK проверка прошла.
  Проверка CA/имени/срока не отключалась. На двух последующих reboot время
  осталось подходящим, clock helper не запускался; attempt-файл не изменился.
- DNS A по UDP и TCP через обычный адрес resolver, NSS, HTTPS по IP и домену:
  успешны до и после reboot/recovery; HTTPS показывает IP выбранного exit.
  HTTPS к тому же внешнему адресу с явным bind к `wlan0` не прошёл при включённом guard.
- Stop/start через настоящий ограниченный backend админки: owner и engine
  останавливаются/запускаются вместе; guard остаётся активным. Неверное TLS-имя
  в settings вызвало rollback: config/settings восстановлены побайтово,
  pending journal убран, рабочий VPN возвращён.
- **Два reboot Radxa**. Первый подтвердил VPN/DNS autostart и выявил ошибку
  старого socket unit админки: `sockets.target → address.service → basic.target`.
  Исправление **`a0885e3`** доставлено через Git. Второй reboot поднял VPN,
  guard, USB rescue и socket админки без ручного старта. Вход по USB и
  разрешение `mpn.local` проверены; все **25 тестов админки** прошли.
- После второго reboot SIGKILL только native engine: systemd запустил новый
  PID, network owner сохранил PID, guard остался активен, DNS/HTTPS повторно прошли.
- На VPS добавлены ровно три собственных FORWARD/NAT правила. Foreign firewall
  совпадает с baseline без счётчиков; x-ui и Docker сохранили MainPID и active
  state. VPS не перезагружался. Его native owner включён в автозагрузку,
  но reboot именно этого VPS в текущем запуске не проверялся.
- Временный блок транзита Mac на Radxa удалён после испытаний. Сеть, Wi-Fi,
  маршруты, DNS и часы Mac не изменялись. USB rescue на `2222` проверен перед reboot.

## Проверка отпечатков

Наблюдатель читает pcap реального трафика, а не отчёт engine о собственном профиле.
В первом capture было четыре ClientHello: два прежнего Node VPN до завершения
его остановки **не совпали**, два native после переключения **совпали**.
Эти несовпадения не удалены из приватного исходного capture.

Отдельный VPS capture первого reboot: один новый native ClientHello, `matched`.
Ещё один capture через backend «наблюдателя» админки во время SIGKILL/reconnect:
один ClientHello, `matched`, tcpdump сообщил `kernelDrops=0`. Во всех четырёх
проверенных native ClientHello JA4 одинаковый:

```text
t13d0915h2_f91f431d341e_54d72502093d
```

JA3 меняется при допустимой перестановке extensions. Совпадение проверяется с
сохранённым bounded cold profile; HTTP-поведение браузера целиком не воспроизводится.
Parser JA3/JA4 общий с инструментами проекта, поэтому захват независим от engine,
но это не независимая реализация алгоритма и не доказательство неотличимости
от браузера. Прогоны не являются полным DNS/IPv6 leak-аудитом USB-клиента.

## Сборки и ограничения

SHA-256 установленного engine:

| Узел | SHA-256 |
| --- | --- |
| Radxa ARM64 | `7c991f48de5b5d25eecf0a9b65810dd98b0f2ba6c06122140663fff752015a62` |
| VPS x64 | `34cbdb14d6eb87ee57e3720674759d4325b14e2171401be26f5ef9606e6a56d1` |

TLS-сертификат этой отдельной пары действует до **2027-10-29 07:20:20 UTC**;
перед истечением нужна согласованная замена сертификата/доверенного CA.
SSH bootstrap доверяет времени закреплённого VPS и требует его признака
`NTPSynchronized=yes`; он не доказывает абсолютную точность источника времени.

Длительное отключение питания и повторное включение Radxa физически не выполнены:
SSH reboot не заменяет power-loss. Нельзя объявлять весь холодный сценарий закрытым
по этим двум загрузкам. Испытание с реально отстававшими часами при первом запуске
проверено отдельно и успешно.

Следующий эксплуатационный шаг — пользование этой boring-tls парой и отдельная
проверка включения после снятия питания, когда пользователь сможет включить плату.
Далее: физическая приёмка combo/incoming, развитие browser fidelity и OpenWrt/LuCI.
Для текущего boring-tls не требуется ждать этих расширений.
