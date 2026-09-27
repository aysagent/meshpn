# DNS: единый VM-прогон установки, использования и удаления

`dns-vm-lab.mjs --case=installed-uninstall` запускает полный source bundle
из `/source/clean-vpn`, публикует13 клиентских файлов с журналом и выполняет
настоящие installed CLI `--start`/`--disable`. После disable вызывается
fixed-layout removal factory: detach, daemon-reload, guard stop, strict
released proof, удаление остальных файлов и архивирование кода.

VM не имеет NIC или shared filesystem. Подготовка синтетической сети,
исходного resolver и parent directories выполняется только после проверки
QEMU/PID1/namespace. Сам uninstall использует настоящие OS commands и журналы.

Шесть результатов на каждой из двух загрузок:

1. Отвечающий baseline DNS `10.129.0.2`: прямые UDP/TCP-запросы и NSS работают.
2. Полный source bundle и согласованный клиентский набор опубликованы.
3. NSS A/AAAA через UDP/TCP получает туннельные ответы; после отказа exit
   запросы не уходят на baseline. Прямые UDP/TCP-пробы baseline блокируются;
   его счётчик не растёт с момента включения production guard.
4. Реальные detach/reload/stop/uninstall завершаются с прежними PID/InvocationID
   resolved/networkd, код перенесён в private archive, runtime-журналы сохранены.
5. Повторный recover подтверждает завершённое удаление без повторной установки.
6. NSS UDP/TCP снова получает ответ baseline, чей счётчик действительно растёт.

Production guard проверяется до снятия внешних начальных правил VM. Положительная
проверка baseline выполняется до установки и после удаления; это позволяет
отличить успешную блокировку от отсутствия рабочего DNS-сервера.

Длительность всего сценария ограничена35 минутами на одну загрузку TCG:
в одном прогоне соединены ранее отдельные длинные операции publication,
start/disable и removal. Таймаут installed controller остаётся180 секунд.
Это не измерение быстродействия VPS или Radxa.

Сценарий не подтверждает active-transaction reboot, whole-VM crash recovery,
реальный клиентский пилот или host installer CLI. Перезагрузка выполняется
после полного завершения uninstall; на второй загрузке установка повторяется
в заново распакованном initramfs. Файловые crash-точки coordinator отдельно
проверяются в `test-dns-released-removal.mjs`.

Текущий запуск: `/var/tmp/meshpn-dns-vm-nSxWC2`; полный результат ещё не получен.
VM protocol/host-refusal тесты:59/59 PASS. Это не объявление VM PASS.
Общая Node-регрессия:2075/2075 PASS, без skips,
`/var/tmp/meshpn-acceptance-4p80HU/report.json`.
