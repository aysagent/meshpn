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

Явный `compileDnsDeploymentFiles({adapter, guard, controller: true})` расширяет
VPS2-набор до десяти файлов: добавляет start/disable units и оба manager drop-in
из [controller plan](dns-controller-service-plan.md). Это только полный набор;
частичные группы, отсутствие networkd exclusion, произвольный текст controller
units, смешанные firewall backends или несовпадение с guard policy запрещены.
Radxa с `controller:true` отклоняется до публикации. По умолчанию прежние пять/шесть
файлов не меняются; recovery старого журнала не добавляет controller artifacts.

Units не содержат `[Install]`; symlink в `.wants` не создаётся. Два dependency
drop-in публикуются только в явном десятифайловом наборе; daemon-reload отсутствует.
Boot policy имеет `enabled:true`, но этот файл сам не запускает unit.
После публикации **нельзя вручную запускать эти units**: файловая транзакция не
доказывает готовность полного deployment. В пяти/шести/десятифайловом варианте
PSK и исходники не копируются; конфиги
существующего resolved/dnsmasq/resolv.conf не входят в allowlist. При совпадении
имени networkd artifact чужой файл не принимается даже с идентичными байтами.

### Приватный клиентский набор

`compileDnsClientDeploymentFiles({adapter, guard, config, bundle, secret})` —
отдельный, явно чувствительный VPS2-набор из13 файлов: прежние10, затем бинарный
`hmac.key` (ровно32байта), `client.json` и **последним** `client-opt-in.json`, все0600.
При откате порядок обратный: opt-in удаляется первым. Неполный или переставленный
набор не принимается ни при install, ни как recovery journal.

Клиентский config проходит существующий VPS2 validator; порт, readiness name,
domain policy и полный adapter unit сверяются тем же template-assessment,
который используется для проверки загруженного adapter. Opt-in связан с guard ID,
точными байтами client config и переданного code manifest. Manifest проходит
структурную проверку, **но код по нему здесь не читается и не публикуется**.
Установщик обязан сначала проверить и опубликовать соответствующий bundle;
hash сам по себе не подтверждает существование или происхождение исходников.

Ключ не генерируется: передаётся существующий PSK, согласованный с exit.
Итог этого compiler нельзя печатать как обычный JSON-plan — он содержит секрет.
Журнал хранит только hash/identity, не байты ключа; внутренние временные buffers
затираются после операции. Caller отдельно уничтожает свой исходный ключ и
чувствительный plan. Это best-effort очистка buffers, не гарантия отсутствия
копий в памяти/дампах. Recovery читает приватный staging/target, а не требует
повторного ввода PSK. Чужой существующий ключ не принимается даже при совпадении
байтов. Прежние5/6/10-файловые журналы не добавляют эти три файла автоматически.

Это всё ещё файловая часть, не разрешённая установка на живом клиенте:
root-owned bundle, реальная inactive-проверка, общий lock, активация и полный
uninstall остаются обязанностями интегрированного entrypoint.

Установщик обязан предоставить заранее проверенные каталоги и функцию
`assertInactive`, которая подтверждает отсутствие активации под своим общим
lock. Callback нужен на входе/выходе всех операций и перед изменением публичного
target или detach staging hardlink. Приватное staging и промежуточные чтения
проверяют файловый контекст без повторного полного OS-check; результаты OS не
кэшируются между публичными setters. Библиотека сама не доказывает ownership
служб и не захватывает lock.
Нельзя передавать `() => true` из будущего live entrypoint: это только fixture.
Hash/валидный manifest не является разрешением на установку или запуск.

### Фиксированная граница снятия зависимостей

Для полного13-файлового набора добавлена файловая операция `detach`.
Она сначала журналирует `detaching`, затем в обратном порядке удаляет только
пять последних файлов: opt-in/config/key и два manager drop-in. Остальные
восемь файлов обязаны остаться с прежними inode/mode/hash; кодом этот модуль
по-прежнему не распоряжается. Успешная стадия — `detached`.

`recover` из `detaching` завершает только этот suffix и останавливается;
из `detached` ничего больше не удаляет. Полное удаление требует отдельного
`remove` и внешнего OS-proof. Legacy5/6/10-наборы, неполная установка,
возвращённый drop-in и исчезновение любого из восьми сохраняемых файлов
отклоняются. Потеря OS-proof между удалениями сохраняет журнал и останавливает
следующий setter. Это не daemon-reload, stop guard или разрешение обходить
строгий released collector; интегрированный coordinator ещё нужен.

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

Расширенный десятифайловый набор: **66/66 PASS**, включая **14 настоящих SIGKILL**
под flock. Дополнительно проверены публикация и удаление controller/drop-in,
отказ до staging при неполной/смешанной группе, сохранение всего набора при
чужом изменении drop-in и recovery старого шестифайлового журнала без upgrade.
Полная Node-регрессия **1912/1912 PASS**, без skips:
`/var/tmp/meshpn-acceptance-EDSJDr/report.json`. Первый общий прогон
`meshpn-acceptance-lcxpSf` имел9 ECH failures при1903 passed; детали причин тот
отчёт не сохранил. Отдельные9/9 ECH и повтор всей Node-suite прошли, причина
первого отказа не установлена; DNS/transport таймауты не увеличивались.

Следующий приватный13-файловый набор: **77/77 PASS**, включая **18 настоящих
SIGKILL** под flock (новые точки — публикация PSK/opt-in и удаление opt-in/PSK).
Проверены порядок публикации/отката, согласованность config/adapter/guard,
чужой существующий PSK, отсутствие байтов ключа в journal и неизменность старых
журналов. Полная Node-регрессия **1923/1923 PASS**, без skips:
`/var/tmp/meshpn-acceptance-spOM4k/report.json`. Это private temp-files, не
доказательство inactive-состояния служб настоящего клиента или installer VM.

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
