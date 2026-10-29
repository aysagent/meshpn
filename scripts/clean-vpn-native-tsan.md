# Native ThreadSanitizer acceptance

30 октября 2026 отдельный ARM64 Linux runner подтвердил работоспособность GCC
TSan: корректно синхронизированный пример прошёл, заведомая гонка дала отчёт и
exit66. ASLR, sysctl, binfmt и сеть Mac не менялись. Сборка ограничена одним CPU,
1500 MiB и одним compiler job; зависимости взяты из существующего проверенного
cache без доступа к сети.

Обнаружена и исправлена реальная гонка: SIGHUP мог выполняться в classifier
worker, записывая `volatile sig_atomic_t reload_requested`, пока main reactor
читал этот флаг. `sig_atomic_t` не обеспечивает межпоточную синхронизацию.
Тот же недостаток был у флага остановки. Commit `400e7d8` заменяет оба флага на
`std::atomic<sig_atomic_t>` со static_assert lock-free; handler выполняет только
atomic store. `exchange(0)` при обработке reload также устраняет окно между
отдельными чтением и сбросом флага. Никакие ключи/структуры peer из handler
не обрабатываются.

Новый `test-native-signal-concurrency.mjs` направляет восемь SIGHUP и затем
SIGTERM именно worker thread через Linux tgkill. Он исключает потоки с
заблокированными сигналами, включая внутренний helper TSan. На исходном engine
`1f57b89` тест воспроизводит data race и exit66; на исправленном engine проходит.
Для запуска теста нужны Linux, Node и C compiler для маленького tgkill helper.

В итоговом прогоне 14/14 проверок: восемь address/discovery/concurrency для H1/H2
и boring/combo; пять peer reload, включая standalone transparent; одна проверка
сигналов worker. Отдельно прошли instrumented quota/replay/revocation с 24
authentication workers и native DNS relay unit с удержанными TCP workers,
заменой peers, отменой и возвратом FD/threads к baseline. Также прошёл
[реальный TUN/DNS churn 12/12](../fixtures/clean-vpn-native-dns-reload-churn-20261030.json).

DNS unit раньше сравнивал общее число thread entries с абсолютными 23.
TSan создаёт собственный persistent helper только при первом std::thread:
измерено 3 entries до первого потока и 24 при saturation. Commit `974f645`
сначала инициализирует runtime пустым thread/join, затем измеряет baseline.
Лимит остаётся **baseline +20 application threads**, а после завершения
проверяется возврат к baseline. Нормальный и instrumented варианты прошли;
производственные лимиты DNS не менялись.

Сборка engine и packet fixture: `-O1 -g1 -fsanitize=thread
-fno-omit-frame-pointer -std=c++17`, fixture дополнительно
`-DCVPN_TEST_PACKET_FD=1`. Все project C++ headers включены в инструментированные
translation units. BoringSSL/nghttp2/Brotli, маленький C ALPS adapter и
traffic-generator integration-test остаются без instrumentation — это явная
граница проверки, а не подавление найденных ошибок.

Пример запуска готовой instrumented сборки внутри отдельного Linux namespace:

```sh
CVPN_BUILD=/work/build \
TSAN_OPTIONS=halt_on_error=1:exitcode=66:log_path=/tmp/tsan-final \
node --test --test-concurrency=1 \
  --test-name-pattern='live exit peers|standalone transparent|session binding|worker-directed' \
  scripts/test-native-peer-reload.mjs \
  scripts/test-native-address-assignment.mjs \
  scripts/test-native-signal-concurrency.mjs
```

После завершения нужно отдельно проверить `/tmp/tsan-final*`: дочерний fixture
может перенаправлять stderr. В итоговом прогоне таких файлов было ноль; known-race
контроль и before-fix отчёты сохранены отдельно. Ноль отчётов в ограниченном
прогоне не доказывает отсутствие всех возможных гонок. Точные source/binary/log
SHA и результаты — [JSON receipt](../fixtures/clean-vpn-native-tsan-20261030.json).
