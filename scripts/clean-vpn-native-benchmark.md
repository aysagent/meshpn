# Физическое сравнение legacy/native через Mac и Radxa

**Отложено 2026-10-07:** пользователь выбрал сначала закончить native на обеих
сторонах и только затем измерять скорость. Этот вспомогательный сравнительный
режим сохранён, но сейчас не требуется к запуску и не блокирует native-переход.

Один запуск `--benchmark` выполняет **три** независимых цикла
`legacy → native → legacy`. Используется прежний guarded trial: root USB rescue
SSH :2222, build lock, неизменный kill-switch, строгие journal/ifindex-аудиты и
возврат включённого legacy service. Следующий цикл начинается только после
успешного отчёта, guard/rollback verified и завершения предыдущего trial unit.
Никаких networkctl down/up, SIGKILL, изменения exit или установки native.

## Запуск после пуша

На Radxa (после последующих native-изменений потребуется актуальная сборка):

```bash
cd /root/dev/meshpn && git pull --ff-only && bash scripts/build-clean-vpn-native.sh
```

На Mac:

```bash
scp -P 2222 root@192.168.7.1:/root/dev/meshpn/scripts/clean-vpn-native-usb-check.mjs /tmp/clean-vpn-native-usb-check.mjs &&
node /tmp/clean-vpn-native-usb-check.mjs --interface=en9 --benchmark
```

Прислать один блок `CLEAN-VPN BENCHMARK BEGIN … END`. Обычно 5–10 минут; отказ
или восстановление могут занять больше. На время замера приостановить другие
скачивания, Speedtest, сборки и обновления. Не переключать ветку и не менять
services во время trial. Не нужны speedtest-cli/iperf и дополнительный worktree.

## Методика и пределы

Публичные [Cloudflare download/upload endpoints](https://github.com/cloudflare/speedtest)
`/__down` и `/__up` используются как генератор/приёмник тестовых данных. Это не
алгоритм Ookla, не сам официальный Cloudflare browser speedtest и не line-rate.

На каждой из девяти фаз:

1. Проверить выход через `154.62.226.216` по HTTPS; в первой фазе разрешить
   `speed.cloudflare.com` явно через DNS Radxa. Закрепить этот IP для всех фаз
   через curl `--resolve`, сохранить SNI и обычную проверку TLS-сертификата.
2. Прогреть тракт загрузкой 256 KiB, не учитывать её в Mbps.
3. Запустить четыре независимых HTTP/1.1 download соединения. Каждое запрашивает
   до 8 MiB, лимит 20 секунд. Успех — все байты или timeout на лимите с HTTP 200,
   проверенным TLS, ожидаемым remote IP и минимум 64 KiB. Другие ошибки не
   принимаются за медленное соединение. Частичные timed downloads отмечены.
4. Четыре upload соединения, по 1 MiB случайных синтетических байтов. Лимит
   30 секунд; каждый upload требует полной отправки **и финального HTTP 200**.
   Timeout upload не считается измерением доставленных серверу байтов.
5. Повторно проверить ожидаемый exit IP.

Mbps = сумма bytes четырёх потоков × 8 / общий wall time группы / 1 000 000.
Время включает создание curl, TCP/TLS и ожидание завершения всех потоков, а не
только payload. Если группа закончилась быстрее 3 секунд, отмечается влияние
startup overhead. HTTP payload не сжимается. Нет автоматических retry, способных
скрыть неудачный измеренный запрос. Прежние host smoke идут до/после переключений.

Всего до **340 MiB прикладных тестовых данных**, включая warmup/host smoke и
ограниченные ответы upload. Трафик TCP/TLS с заголовками/ретрансляциями больше.
Пользовательские файлы не читаются и не загружаются. Сами тела не сохраняются.
Привязка curl к USB, `--noproxy '*'`, IPv4 и контроль exit обязательны.
Один anycast IP не гарантирует неизменный Cloudflare POP/сетевой маршрут.

## CPU и отчёт

На Radxa раз в 250 мс читается `/proc` выбранного процесса и его дочерних
процессов: Node + helpers у legacy; Node wrapper + engine у native. Проверяется
identity root по starttime. Поля: CPU seconds, средний `meanOneCorePercent`
(100% = одно полностью занятое ядро), peak sum RSS KiB, число samples/процессов.
Часы ticks берутся через `getconf CLK_TCK`, не предполагаются равными 100.

CPU — **вся peer-фаза**, включая warmup, DNS/trace и задержку SSH/RPC, не только
нагрузочный интервал. Короткоживущие helpers/начальные ticks между samples могут
быть пропущены. Sum RSS может учитывать общие страницы повторно. Это не CPU
всей платы, softirq/ядра или exit VPS. Benchmark observer не включён в дерево.

Итог хранит девять строк, все исходные bounded curl-метрики и CPU, min/median/max
для шести legacy и трёх native фаз. В каждом цикле native Mbps делится на среднее
legacy-before/legacy-after. Если legacy меняется более чем на 25%, выдаётся warning.
Автоматического вывода «native ускоряет интернет» нет. При неполном цикле,
неверном exit, разных IP, неуспешном rollback/guard нет итоговых paired ratios.

После отказа последующие циклы не запускаются. Обычное восстановление legacy
проверяется даже при провале benchmark. Разрыв SSH не убивает worker; его waits
ограничены. При `manual-review-required` не чистить firewall/journals — оставить
USB rescue и прислать отчёт. `--report` на Radxa показывает последний цикл:

```bash
node /root/dev/meshpn/scripts/clean-vpn-native-trial.mjs --report
```

Локальная проверка включает реальные curl download/upload к локальному TLS
fixture, метрики/лимиты/nonce/CPU-парсер и прежние regression-тесты rollback.
Это не измерение WAN. Физический benchmark с Mac/Radxa пока ожидается.
