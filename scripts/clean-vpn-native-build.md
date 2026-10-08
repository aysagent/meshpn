# Сборка native на малом VPS / Radxa

Обычная сборка уже использует **одну** compiler job. Одно ядро увеличивает время
сборки, но само по себе не является причиной `Terminated`.

```bash
bash scripts/build-clean-vpn-native.sh
```

Для уменьшения расхода памяти компилятором:

```bash
bash scripts/build-clean-vpn-native.sh --low-memory
```

На малом узле можно явно включить временный swap для сборки и затем удалить его:

```bash
sudo bash scripts/clean-vpn-native-swap.sh on
bash scripts/build-clean-vpn-native.sh --low-memory
sudo bash scripts/clean-vpn-native-swap.sh off
```

`on` создаёт отдельный owner-only файл на 2 GiB в
`/var/lib/clean-vpn-native-build-swap`, повторный вызов только проверяет/включает
тот же принадлежащий скрипту файл. `off` сначала успешно отключает swap и только
потом удаляет его. Чужие или изменённые path/marker не перезаписываются и не
удаляются. `/etc/fstab` не меняется: после reboot файл остаётся выключенным,
повторный `on` активирует его, а `off` удаляет.

Режим задаёт `CVPN_LOW_MEMORY_BUILD=ON`: для C/C++ добавляется `-g0` после
build-type flags. Это относится к engine, тестам, BoringSSL и nghttp2. Сохраняются
`RelWithDebInfo`, оптимизация `-O2`, прежние NDEBUG/assert settings, один job и
весь CTest. Нет перехода на `-O0/-O1`, отключения тестов или замены data plane.
Режим уменьшает debug-информацию, но **не гарантирует сборку в 1 GiB RAM**.
Пиковое потребление зависит от компилятора, исходного файла и остальных процессов.
Это не `strip`: таблицы символов и debug-секции из assembler objects могут оставаться.

Проверено 2026-10-08: отдельная low-memory сборка native engine и всех CTest targets
успешна, CTest 7/7. Тесты CLI/build/benchmark/trial — 70/70. Проверены реальные
compile flags engine/BoringSSL/nghttp2 и их возврат при отключении режима.
Эта лабораторная сборка не выполнялась с лимитом RAM данного VPS.

Повторный запуск без `--low-memory` явно возвращает `CVPN_LOW_MEMORY_BUILD=OFF`;
cache не оставляет `-g0` скрыто включённым. Смена режима потребует пересборки
затронутых объектов. Лог прежний: `native/clean_vpn/build/radxa-build.log`.
В начале лога указаны профиль, low-memory flag и число jobs.

Скрипт не создаёт swap, не меняет fstab, firewall или systemd, не останавливает
службы. Но глобальный OOM во время сборки может убить не только компилятор:
не следует повторять сборку при недостаточном запасе памяти на рабочем узле.

## Если сборка прервана

`Terminated` без дополнительных данных не доказывает OOM. До повторного запуска
(который перезапишет build log) сохранить конец лога и проверить:

```bash
free -h
swapon --show
tail -n 80 native/clean_vpn/build/radxa-build.log
journalctl -k -b --since '30 minutes ago' --no-pager \
  --grep='oom|OOM|Out of memory|Killed process|Memory cgroup'
```

На тестируемом VPS с 956 MiB RAM и без swap kernel сообщил
`Out of memory: Killed process ... (cc1plus)`; последний подтверждённый отказ
произошёл на production `engine.cc.o` при anonymous RSS около 432 MiB после
успешной сборки BoringSSL. Это подтверждённая нехватка памяти, не тестовый target
и не отсутствие OpenSSL
или других optional nghttp2 dependencies. CMake configure при этом завершился.

Для надёжного продолжения нужен дополнительный запас: согласованный swap после
проверки свободного диска/файловой системы, увеличение RAM или сборка на другом
совместимом Linux-узле с последующей проверкой архитектуры и динамических библиотек.
Swap здесь не создаётся автоматически; low-memory flag не заменяет эту проверку.
Для сравнительных benchmark следует сохранять compiler/build flags и binary hash.
