# Radxa: восстановление управления combo и прямого выхода

После переключения на `combo-daily` пользователь обнаружил отсутствие интернета,
неработающие операции админки и неверную надпись `boring-tls`.

Причина: прежний systemd drop-in разрешал broker запись только в
`/opt/clean-vpn-native/daily`. Новая конфигурация находилась в `combo-daily`,
который оставался read-only из-за `ProtectSystem=strict`. Сохранение настроек
создавало journal, запись config завершалась ошибкой, а восстановление тоже не
могло записать прежний config. Broker циклически перезапускался. Движок был
остановлен, network owner и закрывающие выход правила оставались активны.
Проверки только `systemctl is-active` до пользовательской операции были недостаточны.

## Исправление

- `admin/install.mjs --update` до остановки админки проверяет настоящую native
  installation, config/unit binding и собственную запись `ReadWritePaths`.
  Затем разрешает запись только в выбранный bundle и штатные state/run пути.
  Точный прежний owned drop-in удаляется; отредактированный вручную отклоняется.
  `ProtectSystem=strict` и capability policy сохраняются.
- Если восстановление настроек не удалось, broker остаётся доступным для чтения
  диагностики и остановки VPN; журнал не удаляется, новое применение блокируется.
- Start при уже работающем network owner явно ставит start engine в очередь.
  Повторный start здорового engine не перезапускает соединение.
- UI показывает транспорт из config, ход длительных операций и блокировку
  конкурирующих кнопок. Выбор kill switch не сбрасывается фоновым обновлением.
  Переключение между транспортами через UI пока не реализовано; неверный
  жёстко заданный disabled selector удалён.

## Приёмка

Mac: 39/39 broker/transaction/binding/unit/HTTP проверок и 14/14 связанных
certificate/diagnostics/captive/exit-install проверок. Реальный Chromium:
client DOM (combo label, сохранение выбора защиты, подтверждение direct,
progress, disabled controls, completed state) и существующий exit DOM прошли.

Изолированный Linux systemd container: 14/14 gates. Реальный read-only mount
воспроизводит отказ записи; restart broker сохраняет доступ к диагностике;
`--update` исправляет sandbox и завершает rollback без включения остановленного
VPN. Проверены профиль, stop/start/restart, отдельно остановленный engine при
активном owner, guard off/on и USB HTTPS. BindToDevice в контейнере очищен из-за
отсутствия udev; это не подмена физической USB-проверки.

На Radxa первоначальный scoped repair сохранил приватные резервные копии в
`/var/lib/clean-vpn-admin-repair-20261031`. Через настоящий broker API проверены
guard off → owner/engine stopped → DNS/HTTPS напрямую, затем guard on и combo
start → DNS/HTTPS через VPS. Mac использовал существующий USB route `en9`;
его системные сетевые настройки не менялись.

Отдельно обнаружено ограничение: HTTPS на голый IP без SNI в transparent-ветке
закрывается. Обычный HTTPS с SNI (`one.one.one.one`, `example.org`) проходит.
Это отдельная задача совместимости; исправление broker её не устраняет.

Полное обновление админки на Radxa и повторная физическая приёмка фиксируются
отдельным follow-up после установки этой ревизии.
