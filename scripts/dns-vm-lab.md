# Изолированная VM-лаборатория DNS

`dns:vm-lab` — настоящий QEMU-гость для проверки reboot и потери гостевых
процессов/RAM. Это **не установщик DNS на клиент**, не изменение clean-vpn CLI
и не доказательство готовности live backend. [Offline-модель](dns-boot.md)
и read-only preflight остаются отдельными инструментами.

## Запуск

Нужен Linux x86-64, Node 24, локальное ядро с совпадающими несжатыми `.ko` в `/lib/modules`,
cpio, mke2fs, modprobe, ldd, iproute2, util-linux, legacy iptables, OpenSSL,
D-Bus/busctl и совместимый systemd-resolved. Builder рассчитан на Ubuntu 24.04
и проверенное в этой среде ядро; это не универсальный дистрибутивный builder.
QEMU/KVM и root на хосте не требуются: QEMU распаковывается отдельно, работает TCG.

В приватном временном каталоге подготовьте `.deb` через **`apt-get download`**,
проверьте происхождение APT metadata и распакуйте `dpkg-deb -x FILE DIR/root`.
Это не `apt install`; пакеты хоста не меняются. Нужны qemu-system-x86,
qemu-system-common, qemu-system-data, seabios, busybox-static и отсутствующие
динамические зависимости QEMU. В этой среде дополнительно потребовались
libfdt1, libslirp0, liburing2, libaio1t64, libpmem1, librdmacm1t64,
libfuse3-3, libndctl6, libdaxctl1. Набор зависит от хоста.

```bash
npm run dns:vm-lab -- \
  --tools=/absolute/private-tools-directory \
  --kernel=/boot/vmlinuz-MATCHING-RUNNING-KERNEL \
  --resolved=/absolute/trusted/systemd-resolved

# Только graceful reboot или одна точка аварии:
# ... --case=cycle
# ... --case=apply:DNSEx:set
# Четыре ранних отказа; отдельно настоящий systemd PID1:
# ... --case=faults
# ... --case=systemd
npm run test:dns-vm
```

Все три пути обязательны, неизвестные/повторные флаги отклоняются. Launcher
не скачивает файлы самостоятельно и не принимает host disk/initramfs.
SHA-256 каждого `.deb` проверяется по записи `apt-cache show` с `Filename: pool/`;
доверие к локальным APT metadata и исходным бинарникам — предусловие, не новая
независимая проверка подписи в launcher. Распакованный каталог должен оставаться
доверенным. Manifest фиксирует hashes скопированных файлов, ядра и всего initrd.

## Что запускается

Минимальный initramfs из явного набора локальных ELF/библиотек, BusyBox и
JavaScript исходников scripts. Host initramfs, `/etc` конфиги, сертификаты,
ключи и пользовательские каталоги не копируются. В госте создаются синтетические
passwd/NSS/resolv.conf; TLS-сертификат и секрет fixture генерируются заново.

QEMU: TCG, 1 vCPU, 1024 MiB RAM, `-nodefaults -no-user-config -nic none`, без
monitor/QMP, display, shared filesystem, проброса портов и физических дисков.
Для каждого сценария создаётся новый приватный raw ext4-диск 256 MiB.
`cache=writeback`, не `cache=unsafe`; guest flush не отключён.
[QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html).

Внешний BusyBox init устанавливает guest DNS53 guard, монтирует `/state`, затем
запускает UID1000 в отдельных user/net/mount/pid/uts namespaces. Внутренний
исполнитель снова ставит и проверяет UDP/TCP53 guard IPv4/IPv6 **до поднятия lo**
и до DNS workload. Внутри — реальный private D-Bus, systemd-resolved, DNS adapter,
enc-SNI exit и TLS DoH fixture. Интернет и TUN не нужны. Реальный upstream путь
в этой матрице IPv4; DNS A/AAAA проверяются отдельно от семейства транспорта.

## Матрица

- Graceful reboot: защищённый DNS → sync/remount-ro → guest reboot syscall →
  выход QEMU с `-no-reboot` → новый процесс QEMU с тем же диском. Это новая
  загрузка ядра, **не hot reset внутри прежнего процесса QEMU**. В этой среде
  hot reset зависал после `Restarting system`; он не считается пройденным.
  Отдельно проверяются подтверждение sync/remount-ro от init, сообщение ядра
  о reboot и нулевой exit QEMU; одного `reboot-ready` недостаточно.
- SIGKILL именно дочернего QEMU, без guest shutdown/дополнительного flush:
  `prepared:file-synced`, `prepared:renamed`,
  `apply:DNSEx:intent:dir-synced`, `apply:DNSEx:set`,
  `apply:Domains:ack:dir-synced`, `restore:DNSEx:set`,
  `restore:DefaultRoute:ack:dir-synced`, `guard-removed`.
- После каждой новой загрузки: другой boot ID, свежий resolved runtime,
  ранние DNS UDP/TCP запросы заблокированы; чужой context или отсутствующий
  committed journal не даёт права снять guard/восстановить старый snapshot.
- Старый каталог journal сохраняется; **явно разрешённая только в fixture**
  новая эпоха создаёт новый журнал текущего baseline. Защищённые A/AAAA-запросы
  проходят; explicit disable возвращает baseline, положительный UDP/TCP control
  доказывает, что sentinel действительно способен обслуживать запросы.

На каждый запуск QEMU есть deadline 240 секунд; вся матрица конечна (18 запусков,
18 загрузок ядра). При ошибке процесс VM завершается, следующие кейсы не запускаются.
`report.json`, `image-manifest.json`, ограниченные serial logs и гостевые диски
остаются в новом `meshpn-dns-vm-*` каталоге для разбора. Каталог приватный,
отчёты/диски `0600`. Хеши и metadata resolver/NSS/passwd/group хоста сравниваются
до/после; host firewall командами launcher не изменяется.

### Ранние отказы (`--case=faults`)

Отдельная конечная матрица из4 свежих загрузок:

- `guard-unavailable`: реальная iptables ошибка после удаления CAP_NET_ADMIN
  у процесса установки; контроллер не доходит до DNS backend, lo остаётся down,
  consumers ещё не запущены. Затем fixture явно восстанавливает защиту.
- `storage-readonly`: bind-remount journal storage read-only, ошибка EROFS до setters.
- `corrupt-journal`: повреждённый committed JSON не перезаписывается; recovery
  отклоняется. Испорченные bytes сохраняются при явной fixture-архивации.
- `adapter-unready`: exit остановлен, readiness не проходит, prepared journal
  остаётся с cursor0 без setters. После восстановления exit recovery сохраняет ID.

Во всех случаях baseline/settings неизменны, guard удерживается (либо старт
вообще прерван до его успешной установки), UDP/TCP baseline IPv4/IPv6 заблокирован.
Затем обязательны успешные protected A/AAAA и explicit disable с positive controls.
Чтобы измерять guard, тест не переименовывает resolv.conf работающего resolved:
используются прямые ограниченные socket probes к двум guest-only sentinels.
Для TCG glibc deadline5s, attempts1; это не изменение таймаутов production adapter.

## Границы результата и следующий этап

SIGKILL QEMU **не уничтожает host page cache**. Это guest power-cut, но не
физическое отключение питания хоста/накопителя и не исчерпывающая модель
переупорядочивания дисковых записей. До directory fsync допускается отсутствие
committed journal; orphan temp не используется для recovery.
[ext4 journaling](https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html).

В базовой reboot/fault матрице PID1 гостя — BusyBox, **не systemd**. Она не подтверждает ordering обычного
дистрибутива, NetworkManager/networkd/DHCP hooks, отсутствие запросов всех ранних
сервисов или реальный uplink. Namespace guard/архивация новой эпохи — только
fixture, не перенесённый на хост backend. Наличие boot ID в control fixture
не меняет schema существующего resolved journal.

Отдельный следующий режим — [гостевой systemd PID1/boot ordering](dns-systemd-vm.md)
(`--case=systemd`, до15 минут на загрузку). После VM — review владельца DNS конкретного клиента и согласованный
live opt-in с безопасным откатом. Сломанный symlink resolv.conf на Radxa
автоматически не исправляется.

Проверка в текущей среде: **9/9 VM-сценариев PASS (18 загрузок ядра)**,
`/var/tmp/meshpn-dns-vm-iTdXxF/report.json`. Более строгий отдельный reboot-прогон
с проверкой init commit marker и kernel restart message также PASS:
`/var/tmp/meshpn-dns-vm-J64ZJO/report.json`. В обоих hostDnsFilesUnchanged=true.
Регрессия: 1040 Node +14 Chrome/Firefox сценариев и10 реальных DNS lifecycle-тестов PASS.

Дополнительная boot-fault матрица: **4/4 PASS**,4 новых boot ID,
`/var/tmp/meshpn-dns-vm-rnhZv5/report.json`; hostDnsFilesUnchanged=true,
baselineQueriesDuringProtection=0. Предшествующие неуспешные прогоны выявили
слишком короткий glibc deadline: при1s вызов завершался, пока TLS request ещё
находился in-flight без ошибки adapter. Они не включены в PASS.

Контрольный повтор на окончательном коде: **4/4 PASS**,
`/var/tmp/meshpn-dns-vm-fvtXdN/report.json`; hostDnsFilesUnchanged=true,
запрещённых baseline queries=0 во всех четырёх сценариях.
