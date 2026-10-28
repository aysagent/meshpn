# Native binary update: отдельная транзакция

2026-10-28. Опциональное обновление **только engine** у новой именованной
boring-tls установки, созданной `clean-vpn-native-install.mjs` с внешними
network/guard units. Это не миграция legacy clean-vpn и не обновление DNS,
unit-файлов, Node runtime, библиотек ОС или конфигурации.

## Контракт

- Подключение updater выполняется при остановленном экземпляре. Проверяются
  исходный manifest, binary/config/key/profile bytes, режимы и внешние units.
  Неизвестные/изменённые установки не принимаются автоматически.
- Релизы сохраняются в приватном `binary-updates/releases/SHA256`, файлы `0555`.
  Активный `engine` заменяется атомарно через новый файл, без записи поверх
  работающего executable. Прежний артефакт остаётся доступным для восстановления.
- SHA-256 задаётся явно и проверяется **до исполнения**. Это контроль целостности,
  не подпись издателя: входной бинарник должен быть доверенным. Его capabilities
  и существующий config проверяются из сохранённой копии.
- Перед остановкой записывается fsync-журнал с before/after hashes, исходным
  running state и отпечатками config/keys/units. После готовности нового engine
  фиксируется commit. Остановленный экземпляр сохраняет stopped state.
- Ошибка запуска возвращает предыдущий executable и состояние службы. Чужие
  изменения защищённых файлов вызывают отказ с сохранением журнала, не overwrite.
- `--apply` работает в bounded transient systemd unit. Его независимый
  `ExecStopPost` выполняет recovery после обрыва worker/SSH. Runtime deadline
  ограничен; длительная недоступность exit может привести к failed rollback,
  журнал в таком случае остаётся для повторного восстановления.
- На следующем boot отдельная recovery-служба упорядочена **до** engine.
  Незавершённый update откатывается без раннего запуска VPN; затем обычные
  network/guard зависимости разрешают либо запрещают запуск. Файлы config,
  ключи и профили updater не восстанавливает из устаревшего общего snapshot.
- `ready` подтверждает native TLS/VPN handshake клиента или listener exit.
  Это не доказательство DNS/интернет-доступа: end-to-end пробы обязательны
  в приёмке. Работающий PID дополнительно сверяется по SHA-256 `/proc/PID/exe`.

## Команды

Примеры для заранее проверенной новой установки `pilot`; не выполнять над
существующим legacy VPN. Все команды — root на Linux/systemd.

```sh
# Экземпляр должен быть остановлен. Ничего не enable/start автоматически.
node scripts/clean-vpn-native-update.mjs --enroll pilot

# Проверка статуса; updater не раскрывает ключи.
node /opt/clean-vpn-native/pilot/update-control/clean-vpn-native-update.mjs --status pilot

# Хеш из проверенного результата сборки, путь — доверенный executable.
node /opt/clean-vpn-native/pilot/update-control/clean-vpn-native-update.mjs \
  --apply pilot /absolute/new-engine SHA256

# Повтор recovery при сохранённом журнале после отказа; не стирать его вручную.
node /opt/clean-vpn-native/pilot/update-control/clean-vpn-native-update.mjs --recover pilot
```

Установленный controller и module копируются в bundle, не зависят от git checkout.
Путь Node закрепляется при enrollment; удаление/замена этого Node — отдельная
операция. Автозагрузка engine управляется существующей установкой, updater её
не включает. Enrollment после частичного сбоя не продолжает/удаляет файлы вслепую.
Одновременные действия администратора/systemctl вне updater не поддерживаются.

Для возврата к сохранённому исправному релизу после уже завершённого update
можно передать его `releases/SHA256` в обычный `--apply` с тем же SHA256:
он снова пройдёт validation и полноценную транзакцию.

## Проверки и границы

`node --test scripts/test-native-binary-update.mjs` проверяет реальные файловые
записи и SIGKILL дочернего updater в шести durable boundaries. Service adapter
в этих unit-тестах моделируется; это не systemd-приёмка.

`npm run lab:native:mac -- --native-boot` расширен реальным обновлением ELF,
отказом candidate, передачей данных после обновления и незавершённой транзакцией
перед новой загрузкой kernel. Для различающихся fixture-релизов к тому же ELF
добавляется хвост-маркер: это проверка lifecycle, не новый production C++ build.
Положительный результат записывается отдельно после фактического прогона.

Cold-boot стенд использует persistent ext4 с восстановлением файлов в initramfs.
Он не равен отключению питания физической Radxa и не доказывает свойства её
носителя при power loss. Физический pilot не должен заменять legacy installation
либо reboot VPS без отдельной необходимости и проверенного пути восстановления.
