# Файловая часть установки DNS

`lib/dns-deployment-files.mjs` — исполняемая файловая транзакция будущего opt-in
установщика. **Не готовая команда установки на VPS/Radxa.** Публичного apply CLI
пока нет: live entrypoint должен сначала проверить согласованный профиль,
root-owned код, владельцев DNS, отсутствие активной интеграции и взять стабильный
deployment lock. Здесь нет SSH, systemctl, enable, DNS-проб или firewall setters.

## Объём

Общие пять файлов из существующих renderer:

- `clean-vpn-dns-adapter.service` и `clean-vpn-dns-guard.service` в `/etc/systemd/system`;
- `upstream.json`, `domains.json` и `guard-policy.json` в `/etc/clean-vpn/dns`.

Для новых VPS2 plans добавляется шестой фиксированный artifact:
`/etc/systemd/network/00-clean-vpn-dns.network`0644. Он содержит только Match
для `cvdns` + ровно8 lowercase hex символов и `[Link] Unmanaged=yes`, без
настроек uplink, DHCP, адресов или DNS. Для Radxa остаются пять файлов.
Прежние пятифайловые журналы VPS2 можно inspect/recover/remove; это **не**
автоматическое обновление до полной новой установки. Новая installed baseline
проверка требует exclusion-файл и отвергает его отсутствие/изменение.
Файловая транзакция не выполняет networkd Reload и не доказывает, что правило
уже загружено. Перед DNS setters требуется реальный unmanaged state своего link.

Units не содержат `[Install]`; symlink в `.wants` или dependency drop-in не
создаётся. Boot policy имеет `enabled:true`, но этот файл сам не запускает unit.
После публикации **нельзя вручную запускать эти units**: файловая транзакция не
доказывает готовность полного deployment. PSK и исходники не копируются; конфиги
существующего resolved/dnsmasq/resolv.conf не входят в allowlist. При совпадении
имени networkd artifact чужой файл не принимается даже с идентичными байтами.

Установщик обязан предоставить заранее проверенные каталоги и функцию
`assertInactive`, которая подтверждает отсутствие активации под своим общим
lock. Callback нужен для всех операций, повторяется до изменений и во время
проверок. Библиотека сама не доказывает ownership служб и не захватывает lock.
Нельзя передавать `() => true` из будущего live entrypoint: это только fixture.
Hash/валидный manifest не является разрешением на установку или запуск.

## Файлы и журнал

Только создание **отсутствующих** targets, без overwrite или усыновления
одноимённого файла даже с теми же байтами. Повторный install поверх deployment
запрещён; обновление установленной версии — отдельная будущая операция.

Стадии: `installing → installed → removing → removed`. `recover` продолжает
записанное направление, `remove` явно переводит незавершённую установку в откат.
`inspect` проверяет файлы/контекст, не меняя их. Журнал сохраняется после remove.

Перед первым target создаются и fsync-ятся staging files в private0700 journal
directory; затем записывается write-ahead manifest. Публикация — hardlink без
перезаписи, fsync target parent, удаление staging-ссылки и fsync journal directory.
До `installed` каждый итоговый файл обязан иметь ровно одну ссылку, что совместимо
с существующим boot policy reader. Промежуточные две ссылки допустимы только
для точной пары staging/target при recovery; третья ссылка — конфликт.

Контекст включает dev:ino корня, journal directory и **всех** parent directories.
Проверяются UID/mode, отсутствие symlink, dev:ino/mode/mtime/SHA256 файлов.
Все targets проверяются перед первой мутацией следующей операции; известный
конфликт не вызывает частичный откат других файлов. Перед удалением каждого
файла состояние проверяется снова. Уже удалённый target допустим только при
записанном `removing`, а не как пропавший `installed` файл.

Staging и target parents должны находиться на одном **mount**, а не просто
иметь одинаковый `st_dev`: проверяется `mnt_id` открытых каталогов, до staging
writes и при дальнейших проверках. Отдельный bind mount на том же устройстве
отвергается до публикации любого artifact. Существующие каталоги не удаляются даже после remove, чужие
файлы не затрагиваются. При обрыве **до** появления журнала orphan staging/temp
сохраняются для review: они никогда не становятся recovery authority.
Если сторонний root меняет файлы одновременно с setter, общий lock его не
останавливает: это не атомарная защита от враждебного root или другого менеджера,
не соблюдающего ownership. Такая машина не является поддержанным deployment.

Дополнение проверки:57/57 файловых tests, включая9 реальных SIGKILL под flock
и отдельный private mount namespace с same-device bind mount. Проверены
публикация/удаление шестого artifact, строгие contents/hash, отказ при чужом
файле/drift, сохранение старого пятифайлового rollback и отдельного Radxa plan.

Файловый remove разрешён только **до активации**. Он не заменяет DNS disable:
для активного клиента сначала нужны proof восстановленного DNS, guard release,
снятие boot dependencies/policy и остановка служб в проверенном порядке. Нельзя
удалять файлы активной интеграции одним этим модулем.

## Проверки

```bash
npm run test:dns-deployment-files
```

47/47 PASS: реальные temp-directory файлы, обе политики VPS2/Radxa, 14 install checkpoints с recovery и
rollback, 7 removal checkpoints, foreign inode/content/mode/link, потеря proof,
corrupt journal и замена parent/journal directories. Дополнительно внутри этих
47 тестов — **7 настоящих process SIGKILL**, 7 отказов конкурирующему `flock` и
освобождение lock после смерти владельца. Остальные checkpoints моделируют
исключения, не убийство процесса. Host DNS/units не меняются.
Полная Node-регрессия:1724/1724 PASS, без skips,
`/var/tmp/meshpn-acceptance-aIKWA7/report.json` (2026-09-27).

Это ещё не whole-guest power-loss тест установки и не VM/live installer PASS.
Следующий шаг — связать эту транзакцию с клиентскими controllers, проверкой
неактивного deployment, установкой кода/credentials и opt-in entrypoint; затем
проверить единый install/activate/disable/uninstall в VM. Только после этого —
согласованный пользовательский пилот каждого клиента. [DNS v1](dns-v1.md) открыт.
